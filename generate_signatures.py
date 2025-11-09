#!/usr/bin/env python3
"""
Vulnerability Signature Generator
Extracts exploitability signatures from WordPress plugin vulnerabilities by analyzing
code diffs between vulnerable and patched versions.
"""

import json
import os
import sys
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import requests
from dataclasses import dataclass, asdict
from collections import defaultdict
import ast
import difflib
from datetime import datetime

# Force unbuffered output
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', buffering=1)

# Configuration
SVN_REPOS_DIR = "/home/ravindu/compweb/svn_wordpress_org"
VULNERABILITIES_FILE = "plugin_vulnerabilities.json"
SIGNATURES_OUTPUT_FILE = "vulnerability_signatures.json"
WORDFENCE_API_BASE = "https://www.wordfence.com/api/intelligence/v2/vulnerabilities"

@dataclass
class VulnerabilityInfo:
    """Structured vulnerability information"""
    cve: Optional[str]
    plugin_slug: str
    vuln_type: str
    title: str
    affected_versions: str
    patched_version: Optional[str]
    wordfence_uuid: str
    references: List[str]

@dataclass
class CodeSignature:
    """Abstract signature extracted from vulnerability diff"""
    cve: Optional[str]
    plugin_slug: str
    vuln_type: str
    signature_type: str  # 'ast_pattern', 'regex_pattern', 'structural_pattern'
    pattern: str
    context: Dict[str, any]
    severity_indicators: List[str]
    exploitability_score: float
    diff_before: str
    diff_after: str
    extracted_at: str

class SVNDiffExtractor:
    """Extracts code diffs from SVN repositories"""

    def __init__(self, svn_repos_dir: str):
        self.svn_repos_dir = Path(svn_repos_dir)

    def get_local_repo_path(self, plugin_slug: str) -> Optional[Path]:
        """Get path to local SVN repository"""
        repo_path = self.svn_repos_dir / plugin_slug
        return repo_path if repo_path.exists() else None

    def get_available_tags(self, plugin_slug: str) -> List[str]:
        """Get list of available version tags"""
        repo_path = self.get_local_repo_path(plugin_slug)
        if not repo_path:
            return []

        tags_dir = repo_path / "tags"
        if not tags_dir.exists():
            return []

        tags = [d.name for d in tags_dir.iterdir() if d.is_dir()]
        # Sort versions properly
        return sorted(tags, key=lambda v: self._version_key(v))

    def _version_key(self, version: str) -> Tuple:
        """Convert version string to sortable tuple"""
        # Extract numeric parts
        parts = re.findall(r'\d+', version)
        return tuple(int(p) for p in parts) if parts else (0,)

    def find_vulnerable_and_patched_versions(self, plugin_slug: str,
                                            affected_versions: str,
                                            patched_version: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        """
        Find the actual vulnerable and patched version tags available in SVN

        Args:
            plugin_slug: Plugin identifier
            affected_versions: Version range string like "<= 1.1.2" or "< 1.0.5"
            patched_version: Known patched version if available

        Returns:
            Tuple of (vulnerable_version, fixed_version)
        """
        available_tags = self.get_available_tags(plugin_slug)
        if not available_tags:
            return None, None

        # Parse affected version constraint
        vulnerable_version = self._find_last_vulnerable_version(affected_versions, available_tags)

        # Find patched version
        if patched_version:
            fixed_version = self._find_closest_tag(patched_version, available_tags)
        else:
            # Find next version after vulnerable version
            fixed_version = self._find_next_version(vulnerable_version, available_tags)

        return vulnerable_version, fixed_version

    def _find_last_vulnerable_version(self, constraint: str, available_tags: List[str]) -> Optional[str]:
        """Find the last vulnerable version matching the constraint"""
        # Parse constraint like "<= 1.1.2", "< 1.0.5", "= 1.2.3"
        match = re.search(r'([<>=]+)\s*([\d.]+)', constraint)
        if not match:
            return available_tags[-1] if available_tags else None

        operator, version = match.groups()
        target_key = self._version_key(version)

        candidates = []
        for tag in available_tags:
            tag_key = self._version_key(tag)
            if operator == '<=' and tag_key <= target_key:
                candidates.append(tag)
            elif operator == '<' and tag_key < target_key:
                candidates.append(tag)
            elif operator == '=' and tag_key == target_key:
                candidates.append(tag)

        return candidates[-1] if candidates else None

    def _find_closest_tag(self, version: str, available_tags: List[str]) -> Optional[str]:
        """Find the closest matching tag to a version"""
        target_key = self._version_key(version)

        # Try exact match first
        for tag in available_tags:
            if self._version_key(tag) == target_key:
                return tag

        # Find closest higher version
        for tag in available_tags:
            if self._version_key(tag) >= target_key:
                return tag

        return None

    def _find_next_version(self, current_version: Optional[str], available_tags: List[str]) -> Optional[str]:
        """Find the next version after current version"""
        if not current_version:
            return None

        current_key = self._version_key(current_version)
        for tag in available_tags:
            if self._version_key(tag) > current_key:
                return tag

        return None

    def get_diff_from_local(self, plugin_slug: str, vuln_version: str, fixed_version: str) -> Optional[str]:
        """Extract diff between two versions from local SVN repo"""
        repo_path = self.get_local_repo_path(plugin_slug)
        if not repo_path:
            return None

        vuln_path = repo_path / "tags" / vuln_version
        fixed_path = repo_path / "tags" / fixed_version

        if not (vuln_path.exists() and fixed_path.exists()):
            return None

        try:
            # Get diff of PHP files
            result = subprocess.run(
                ['diff', '-ruN', str(vuln_path), str(fixed_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            # diff returns 1 when differences found, 0 when identical
            return result.stdout if result.stdout else None
        except subprocess.TimeoutExpired:
            print(f"Timeout diffing {plugin_slug} {vuln_version} -> {fixed_version}")
            return None
        except Exception as e:
            print(f"Error diffing {plugin_slug}: {e}")
            return None

    def get_diff_from_remote(self, plugin_slug: str, vuln_version: str, fixed_version: str) -> Optional[str]:
        """Fetch and diff versions from remote SVN repository"""
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmpdir = Path(tmpdir)

                vuln_url = f"https://plugins.svn.wordpress.org/{plugin_slug}/tags/{vuln_version}/"
                fixed_url = f"https://plugins.svn.wordpress.org/{plugin_slug}/tags/{fixed_version}/"

                vuln_dir = tmpdir / "vulnerable"
                fixed_dir = tmpdir / "fixed"

                # Checkout vulnerable version
                result = subprocess.run(
                    ['svn', 'checkout', '--depth', 'infinity', vuln_url, str(vuln_dir)],
                    capture_output=True,
                    timeout=120
                )
                if result.returncode != 0:
                    print(f"Failed to checkout vulnerable version {vuln_url}")
                    return None

                # Checkout fixed version
                result = subprocess.run(
                    ['svn', 'checkout', '--depth', 'infinity', fixed_url, str(fixed_dir)],
                    capture_output=True,
                    timeout=120
                )
                if result.returncode != 0:
                    print(f"Failed to checkout fixed version {fixed_url}")
                    return None

                # Generate diff
                result = subprocess.run(
                    ['diff', '-ruN', str(vuln_dir), str(fixed_dir)],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                return result.stdout if result.stdout else None

        except subprocess.TimeoutExpired:
            print(f"Timeout fetching remote diff for {plugin_slug}")
            return None
        except Exception as e:
            print(f"Error fetching remote diff for {plugin_slug}: {e}")
            return None

class SignatureExtractor:
    """Extracts abstract vulnerability signatures from code diffs"""

    # Vulnerability pattern definitions
    AUTH_PATTERNS = [
        r'wp_verify_nonce',
        r'current_user_can',
        r'is_user_logged_in',
        r'check_admin_referer',
        r'wp_create_nonce',
    ]

    INPUT_SANITIZATION_PATTERNS = [
        r'sanitize_text_field',
        r'sanitize_email',
        r'esc_html',
        r'esc_attr',
        r'esc_url',
        r'wp_kses',
        r'sanitize_key',
    ]

    SQL_SECURITY_PATTERNS = [
        r'\$wpdb->prepare',
        r'esc_sql',
        r'absint',
        r'intval',
    ]

    FILE_SECURITY_PATTERNS = [
        r'validate_file',
        r'wp_check_filetype',
        r'basename',
        r'realpath',
    ]

    def __init__(self):
        self.signatures = []

    def extract_signature_from_diff(self, diff: str, vuln_info: VulnerabilityInfo) -> Optional[CodeSignature]:
        """Extract vulnerability signature from diff"""
        if not diff:
            return None

        # Parse diff to get before/after code
        diff_blocks = self._parse_diff_blocks(diff)
        if not diff_blocks:
            return None

        # Analyze each diff block for vulnerability patterns
        patterns = []
        severity_indicators = []

        for block in diff_blocks:
            # Check what security functions were added in the patch
            added_security = self._detect_added_security_functions(block)
            if added_security:
                patterns.extend(added_security)
                severity_indicators.extend(self._assess_severity(added_security, vuln_info.vuln_type))

        # Generate abstract pattern signature
        if patterns:
            signature_pattern = self._generate_abstract_pattern(patterns, vuln_info.vuln_type)
            exploitability_score = self._calculate_exploitability_score(
                severity_indicators, vuln_info.vuln_type
            )

            return CodeSignature(
                cve=vuln_info.cve,
                plugin_slug=vuln_info.plugin_slug,
                vuln_type=vuln_info.vuln_type,
                signature_type='security_function_pattern',
                pattern=signature_pattern,
                context={
                    'title': vuln_info.title,
                    'affected_versions': vuln_info.affected_versions,
                    'patched_version': vuln_info.patched_version,
                    'detected_patterns': patterns,
                    'file_changes': len(diff_blocks)
                },
                severity_indicators=severity_indicators,
                exploitability_score=exploitability_score,
                diff_before=self._extract_before_code(diff_blocks),
                diff_after=self._extract_after_code(diff_blocks),
                extracted_at=datetime.now().isoformat()
            )

        return None

    def _parse_diff_blocks(self, diff: str) -> List[Dict[str, any]]:
        """Parse diff into structured blocks"""
        blocks = []
        current_file = None
        current_before = []
        current_after = []

        for line in diff.split('\n'):
            # File header
            if line.startswith('--- ') or line.startswith('+++ '):
                if current_file and (current_before or current_after):
                    blocks.append({
                        'file': current_file,
                        'before': '\n'.join(current_before),
                        'after': '\n'.join(current_after)
                    })
                    current_before = []
                    current_after = []

                if line.startswith('--- '):
                    current_file = line[4:].split('\t')[0]

            # Removed lines (vulnerable code)
            elif line.startswith('-') and not line.startswith('---'):
                current_before.append(line[1:])

            # Added lines (patched code)
            elif line.startswith('+') and not line.startswith('+++'):
                current_after.append(line[1:])

        # Add final block
        if current_file and (current_before or current_after):
            blocks.append({
                'file': current_file,
                'before': '\n'.join(current_before),
                'after': '\n'.join(current_after)
            })

        return blocks

    def _detect_added_security_functions(self, block: Dict[str, any]) -> List[str]:
        """Detect security functions added in the patch"""
        after_code = block['after']
        before_code = block['before']

        added_security = []

        # Check authentication patterns
        for pattern in self.AUTH_PATTERNS:
            if re.search(pattern, after_code) and not re.search(pattern, before_code):
                added_security.append(f'AUTH:{pattern}')

        # Check input sanitization
        for pattern in self.INPUT_SANITIZATION_PATTERNS:
            if re.search(pattern, after_code) and not re.search(pattern, before_code):
                added_security.append(f'SANITIZE:{pattern}')

        # Check SQL security
        for pattern in self.SQL_SECURITY_PATTERNS:
            if re.search(pattern, after_code) and not re.search(pattern, before_code):
                added_security.append(f'SQL_SECURITY:{pattern}')

        # Check file security
        for pattern in self.FILE_SECURITY_PATTERNS:
            if re.search(pattern, after_code) and not re.search(pattern, before_code):
                added_security.append(f'FILE_SECURITY:{pattern}')

        return added_security

    def _generate_abstract_pattern(self, patterns: List[str], vuln_type: str) -> str:
        """Generate abstract signature pattern"""
        # Categorize patterns
        categories = defaultdict(list)
        for pattern in patterns:
            category, func = pattern.split(':', 1) if ':' in pattern else ('UNKNOWN', pattern)
            categories[category].append(func)

        # Build abstract pattern
        signature_parts = []
        for category, funcs in sorted(categories.items()):
            signature_parts.append(f"{category}[{','.join(sorted(set(funcs)))}]")

        return f"{vuln_type}::{'|'.join(signature_parts)}"

    def _assess_severity(self, patterns: List[str], vuln_type: str) -> List[str]:
        """Assess severity indicators based on detected patterns"""
        indicators = []

        # Critical: Missing authentication on sensitive operations
        if any('AUTH:' in p for p in patterns):
            if 'CSRF' in vuln_type or 'Missing Authorization' in vuln_type:
                indicators.append('CRITICAL:MISSING_AUTH')

        # High: Missing input sanitization
        if any('SANITIZE:' in p for p in patterns):
            if 'XSS' in vuln_type or 'Injection' in vuln_type:
                indicators.append('HIGH:MISSING_SANITIZATION')

        # High: SQL injection protection
        if any('SQL_SECURITY:' in p for p in patterns):
            indicators.append('HIGH:SQL_INJECTION_RISK')

        # Critical: File operation security
        if any('FILE_SECURITY:' in p for p in patterns):
            if 'Traversal' in vuln_type or 'File' in vuln_type:
                indicators.append('CRITICAL:UNSAFE_FILE_OPS')

        return indicators

    def _calculate_exploitability_score(self, severity_indicators: List[str], vuln_type: str) -> float:
        """Calculate exploitability score (0-10)"""
        score = 5.0  # Base score

        # Adjust based on severity indicators
        critical_count = sum(1 for i in severity_indicators if 'CRITICAL:' in i)
        high_count = sum(1 for i in severity_indicators if 'HIGH:' in i)

        score += critical_count * 2.0
        score += high_count * 1.0

        # Adjust based on vulnerability type
        high_impact_types = [
            'SQL Injection',
            'Remote Code Execution',
            'Authentication Bypass',
            'Privilege Escalation',
            'Arbitrary File',
        ]

        if any(vuln in vuln_type for vuln in high_impact_types):
            score += 1.5

        return min(10.0, score)

    def _extract_before_code(self, blocks: List[Dict[str, any]]) -> str:
        """Extract vulnerable code snippets"""
        snippets = []
        for block in blocks[:3]:  # Limit to first 3 files
            if block['before']:
                snippets.append(f"File: {block['file']}\n{block['before'][:500]}")
        return '\n\n'.join(snippets)

    def _extract_after_code(self, blocks: List[Dict[str, any]]) -> str:
        """Extract patched code snippets"""
        snippets = []
        for block in blocks[:3]:  # Limit to first 3 files
            if block['after']:
                snippets.append(f"File: {block['file']}\n{block['after'][:500]}")
        return '\n\n'.join(snippets)

class VulnerabilityFetcher:
    """Fetch detailed vulnerability information"""

    def __init__(self):
        self.cache = {}

    def fetch_vulnerability_details(self, wordfence_uuid: str) -> Optional[Dict]:
        """Fetch detailed vulnerability info from Wordfence API"""
        if wordfence_uuid in self.cache:
            return self.cache[wordfence_uuid]

        try:
            url = f"{WORDFENCE_API_BASE}/{wordfence_uuid}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                self.cache[wordfence_uuid] = data
                return data
            else:
                print(f"Failed to fetch {wordfence_uuid}: {response.status_code}")
                return None
        except Exception as e:
            print(f"Error fetching {wordfence_uuid}: {e}")
            return None

    def extract_version_info(self, vuln_data: Dict, title: str) -> Tuple[str, Optional[str]]:
        """Extract affected and patched version from vulnerability data"""
        affected_versions = "unknown"
        patched_version = None

        # Try to get from API data
        if vuln_data and 'affected_versions' in vuln_data:
            affected_versions = vuln_data.get('affected_versions', 'unknown')

        if vuln_data and 'patched_version' in vuln_data:
            patched_version = vuln_data.get('patched_version')

        # Fallback: parse from title
        if affected_versions == "unknown":
            # Pattern like "<= 1.1.2" or "< 1.0.5"
            match = re.search(r'([<>=]+)\s*([\d.]+)', title)
            if match:
                affected_versions = f"{match.group(1)} {match.group(2)}"

        return affected_versions, patched_version

def main():
    """Main signature generation pipeline"""
    print("=== WordPress Vulnerability Signature Generator ===\n")

    # Initialize components
    print("Initializing components...")
    svn_extractor = SVNDiffExtractor(SVN_REPOS_DIR)
    signature_extractor = SignatureExtractor()
    vuln_fetcher = VulnerabilityFetcher()

    # Load vulnerabilities
    print(f"Loading vulnerabilities from {VULNERABILITIES_FILE}...")
    with open(VULNERABILITIES_FILE, 'r') as f:
        vulnerabilities = json.load(f)

    # Filter out null entries
    vulnerabilities = {k: v for k, v in vulnerabilities.items() if v is not None}

    total_plugins = len(vulnerabilities)
    total_vulns = sum(len(vulns) for vulns in vulnerabilities.values())
    print(f"Loaded {total_vulns} vulnerabilities across {total_plugins} plugins\n")

    # Process each vulnerability
    signatures = []
    processed = 0
    success_count = 0

    for plugin_slug, plugin_vulns in vulnerabilities.items():
        print(f"\n[{processed}/{total_vulns}] Processing plugin: {plugin_slug}")

        for vuln in plugin_vulns:
            processed += 1
            cve = vuln.get('cve', 'N/A')
            vuln_type = vuln.get('type', 'Unknown')
            title = vuln.get('title', '')
            wordfence_uuid = vuln.get('wordfence_uuid')

            print(f"  [{processed}/{total_vulns}] {cve} - {vuln_type}")

            # Fetch detailed vulnerability info
            vuln_details = vuln_fetcher.fetch_vulnerability_details(wordfence_uuid) if wordfence_uuid else None

            # Extract version information
            affected_versions, patched_version = vuln_fetcher.extract_version_info(vuln_details, title)

            # Create vulnerability info object
            vuln_info = VulnerabilityInfo(
                cve=cve,
                plugin_slug=plugin_slug,
                vuln_type=vuln_type,
                title=title,
                affected_versions=affected_versions,
                patched_version=patched_version,
                wordfence_uuid=wordfence_uuid,
                references=vuln.get('references', [])
            )

            # Find vulnerable and patched versions in SVN
            vuln_version, fixed_version = svn_extractor.find_vulnerable_and_patched_versions(
                plugin_slug, affected_versions, patched_version
            )

            if not vuln_version or not fixed_version:
                print(f"    [!] Could not find versions in SVN (vuln={vuln_version}, fixed={fixed_version})")
                continue

            print(f"    [->] Comparing versions: {vuln_version} -> {fixed_version}")

            # Try to get diff from local repo first
            diff = svn_extractor.get_diff_from_local(plugin_slug, vuln_version, fixed_version)

            # Fallback to remote if local fails
            if not diff:
                print(f"    � Fetching from remote SVN...")
                diff = svn_extractor.get_diff_from_remote(plugin_slug, vuln_version, fixed_version)

            if not diff:
                print(f"     Failed to extract diff")
                continue

            # Extract signature from diff
            signature = signature_extractor.extract_signature_from_diff(diff, vuln_info)

            if signature:
                signatures.append(asdict(signature))
                success_count += 1
                print(f"     Signature extracted: {signature.pattern}")
                print(f"     Exploitability score: {signature.exploitability_score:.1f}/10")
            else:
                print(f"    � No signature pattern detected")

    # Save signatures
    print(f"\n\n=== Generation Complete ===")
    print(f"Total processed: {processed}")
    print(f"Signatures extracted: {success_count}")
    print(f"Success rate: {success_count/processed*100:.1f}%")

    print(f"\nSaving signatures to {SIGNATURES_OUTPUT_FILE}...")
    with open(SIGNATURES_OUTPUT_FILE, 'w') as f:
        json.dump({
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_vulnerabilities': processed,
                'signatures_extracted': success_count,
                'plugins_analyzed': total_plugins
            },
            'signatures': signatures
        }, f, indent=2)

    print(f" Signatures saved successfully!")

    # Generate statistics
    print("\n=== Signature Statistics ===")
    vuln_type_counts = defaultdict(int)
    for sig in signatures:
        vuln_type_counts[sig['vuln_type']] += 1

    print("\nVulnerability types covered:")
    for vuln_type, count in sorted(vuln_type_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {vuln_type}: {count}")

    avg_exploitability = sum(sig['exploitability_score'] for sig in signatures) / len(signatures) if signatures else 0
    print(f"\nAverage exploitability score: {avg_exploitability:.2f}/10")

    critical_sigs = [sig for sig in signatures if sig['exploitability_score'] >= 8.0]
    print(f"Critical signatures (score >= 8.0): {len(critical_sigs)}")

if __name__ == "__main__":
    main()
