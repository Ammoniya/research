#!/usr/bin/env python3
"""
Malicious JavaScript Detection Tool

Scans JavaScript files for common malicious patterns including:
- Obfuscated code
- Remote code execution
- Backdoors and web shells
- Data exfiltration
- XSS and injection attempts
- Crypto miners
- Command execution

Usage:
    python detect_malicious_js.py [--dir DIRECTORY] [--output OUTPUT_FILE]
"""

import re
import json
import math
import argparse
from pathlib import Path
from typing import Dict, List
from collections import defaultdict
from datetime import datetime


class MaliciousJSDetector:
    """
    Detects potentially malicious JavaScript code patterns.
    """
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.stats = {
            'files_scanned': 0,
            'malicious_files': 0,
            'total_findings': 0,
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0
        }
        
        # Define malicious patterns with severity levels
        self.patterns = self._init_patterns()
    
    def _init_patterns(self) -> Dict[str, List[Dict]]:
        """Initialize detection patterns categorized by type."""
        return {
            'obfuscation': [
                {
                    'pattern': r'eval\s*\(',
                    'description': 'Use of eval() function',
                    'severity': 'HIGH',
                    'cwe': 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code'
                },
                {
                    'pattern': r'Function\s*\(\s*[\'"]',
                    'description': 'Dynamic function creation from string',
                    'severity': 'HIGH',
                    'cwe': 'CWE-95'
                },
                {
                    'pattern': r'atob\s*\(',
                    'description': 'Base64 decoding (potential obfuscation)',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-506: Embedded Malicious Code'
                },
                {
                    'pattern': r'fromCharCode',
                    'description': 'Character code obfuscation',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-506'
                },
                {
                    'pattern': r'\\x[0-9a-fA-F]{2}',
                    'description': 'Hex-encoded strings (potential obfuscation)',
                    'severity': 'LOW',
                    'cwe': 'CWE-506'
                },
                {
                    'pattern': r'\\u[0-9a-fA-F]{4}',
                    'description': 'Unicode escape sequences (potential obfuscation)',
                    'severity': 'LOW',
                    'cwe': 'CWE-506'
                },
                {
                    'pattern': r'unescape\s*\(',
                    'description': 'Use of deprecated unescape() (often used in obfuscation)',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-506'
                }
            ],
            'remote_execution': [
                {
                    'pattern': r'new\s+ActiveXObject\s*\(\s*[\'"]WScript\.Shell',
                    'description': 'Windows Script Host execution',
                    'severity': 'HIGH',
                    'cwe': 'CWE-94: Improper Control of Generation of Code'
                },
                {
                    'pattern': r'\.exec\s*\(',
                    'description': 'Command execution',
                    'severity': 'HIGH',
                    'cwe': 'CWE-78: OS Command Injection'
                },
                {
                    'pattern': r'child_process',
                    'description': 'Node.js child process (potential command execution)',
                    'severity': 'HIGH',
                    'cwe': 'CWE-78'
                },
                {
                    'pattern': r'require\s*\(\s*[\'"]child_process',
                    'description': 'Loading child_process module',
                    'severity': 'HIGH',
                    'cwe': 'CWE-78'
                }
            ],
            'backdoor': [
                {
                    'pattern': r'(?:password|passwd|pwd)\s*[=:]\s*[\'"][^\'"]+[\'"]',
                    'description': 'Hardcoded password',
                    'severity': 'HIGH',
                    'cwe': 'CWE-259: Use of Hard-coded Password'
                },
                {
                    'pattern': r'backdoor',
                    'description': 'Reference to "backdoor"',
                    'severity': 'HIGH',
                    'cwe': 'CWE-506'
                },
                {
                    'pattern': r'shell\s*[=:]\s*[\'"][^\'"]*(?:bash|sh|cmd|powershell)',
                    'description': 'Shell reference (potential backdoor)',
                    'severity': 'HIGH',
                    'cwe': 'CWE-506'
                },
                {
                    'pattern': r'(?:cmd|command)\s*=\s*[\'"][^\'"]*/bin/',
                    'description': 'Direct system binary execution',
                    'severity': 'HIGH',
                    'cwe': 'CWE-78'
                }
            ],
            'data_exfiltration': [
                {
                    'pattern': r'XMLHttpRequest.*open\s*\(\s*[\'"](?:POST|GET)',
                    'description': 'HTTP request (check destination)',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-601: URL Redirection to Untrusted Site'
                },
                {
                    'pattern': r'fetch\s*\(',
                    'description': 'Fetch API call (check destination)',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-601'
                },
                {
                    'pattern': r'document\.cookie',
                    'description': 'Cookie access (potential theft)',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-79: Cross-site Scripting (XSS)'
                },
                {
                    'pattern': r'localStorage|sessionStorage',
                    'description': 'Local storage access',
                    'severity': 'LOW',
                    'cwe': 'CWE-922: Insecure Storage of Sensitive Information'
                },
                {
                    'pattern': r'location\.href\s*=',
                    'description': 'Page redirection',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-601'
                }
            ],
            'injection': [
                {
                    'pattern': r'innerHTML\s*=',
                    'description': 'innerHTML assignment (potential XSS)',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-79'
                },
                {
                    'pattern': r'document\.write\s*\(',
                    'description': 'document.write (potential XSS)',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-79'
                },
                {
                    'pattern': r'outerHTML\s*=',
                    'description': 'outerHTML assignment (potential XSS)',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-79'
                },
                {
                    'pattern': r'insertAdjacentHTML\s*\(',
                    'description': 'insertAdjacentHTML (potential XSS)',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-79'
                }
            ],
            'crypto_mining': [
                {
                    'pattern': r'coinhive|cryptonight|webminer',
                    'description': 'Crypto mining reference',
                    'severity': 'HIGH',
                    'cwe': 'CWE-506'
                },
                {
                    'pattern': r'stratum\+tcp',
                    'description': 'Mining pool connection',
                    'severity': 'HIGH',
                    'cwe': 'CWE-506'
                }
            ],
            'suspicious_apis': [
                {
                    'pattern': r'WebSocket\s*\(',
                    'description': 'WebSocket connection (verify endpoint)',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-400: Uncontrolled Resource Consumption'
                },
                {
                    'pattern': r'Worker\s*\(\s*[\'"]',
                    'description': 'Web Worker creation',
                    'severity': 'LOW',
                    'cwe': 'CWE-400'
                },
                {
                    'pattern': r'importScripts\s*\(',
                    'description': 'Dynamic script import in worker',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-494: Download of Code Without Integrity Check'
                },
                {
                    'pattern': r'\.call\s*\(\s*null',
                    'description': 'Function.call with null context',
                    'severity': 'LOW',
                    'cwe': 'CWE-20: Improper Input Validation'
                }
            ],
            'file_system': [
                {
                    'pattern': r'require\s*\(\s*[\'"]fs[\'"]',
                    'description': 'File system access (Node.js)',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-73: External Control of File Name or Path'
                },
                {
                    'pattern': r'\.writeFile|\.readFile',
                    'description': 'File read/write operations',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-73'
                },
                {
                    'pattern': r'\.unlink|\.rmdir',
                    'description': 'File/directory deletion',
                    'severity': 'HIGH',
                    'cwe': 'CWE-73'
                }
            ]
        }
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """
        Scan a single JavaScript file for malicious patterns.
        
        Returns:
            List of findings with details
        """
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            self.stats['files_scanned'] += 1
            
            # Check for extremely long lines (potential obfuscation)
            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                if len(line) > 1000:
                    findings.append({
                        'type': 'obfuscation',
                        'pattern': 'extremely_long_line',
                        'description': f'Extremely long line ({len(line)} chars) - potential obfuscation',
                        'severity': 'MEDIUM',
                        'line': line_num,
                        'snippet': line[:100] + '...' if len(line) > 100 else line,
                        'cwe': 'CWE-506'
                    })
            
            # Check each pattern category
            for category, patterns in self.patterns.items():
                for pattern_info in patterns:
                    matches = re.finditer(pattern_info['pattern'], content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        # Find line number
                        line_num = content[:match.start()].count('\n') + 1
                        
                        # Get surrounding context
                        start = max(0, match.start() - 50)
                        end = min(len(content), match.end() + 50)
                        snippet = content[start:end].strip()
                        
                        findings.append({
                            'type': category,
                            'pattern': pattern_info['pattern'],
                            'description': pattern_info['description'],
                            'severity': pattern_info['severity'],
                            'line': line_num,
                            'snippet': snippet[:200],  # Limit snippet length
                            'cwe': pattern_info['cwe']
                        })
                        
                        self.stats['total_findings'] += 1
                        if pattern_info['severity'] == 'HIGH':
                            self.stats['high_severity'] += 1
                        elif pattern_info['severity'] == 'MEDIUM':
                            self.stats['medium_severity'] += 1
                        else:
                            self.stats['low_severity'] += 1
            
            # Check for suspicious entropy (highly obfuscated code)
            if self._check_high_entropy(content):
                findings.append({
                    'type': 'obfuscation',
                    'pattern': 'high_entropy',
                    'description': 'Code has high entropy - likely obfuscated',
                    'severity': 'HIGH',
                    'line': 0,
                    'snippet': 'Overall file analysis',
                    'cwe': 'CWE-506'
                })
                self.stats['high_severity'] += 1
                self.stats['total_findings'] += 1
            
            if findings:
                self.stats['malicious_files'] += 1
            
        except Exception as e:
            if self.verbose:
                print(f"Error scanning {file_path}: {e}")
        
        return findings
    
    def _check_high_entropy(self, content: str) -> bool:
        """
        Check if content has suspiciously high entropy (obfuscation indicator).
        """
        if len(content) < 100:
            return False
        
        # Calculate character frequency
        freq = defaultdict(int)
        for char in content:
            freq[char] += 1
        
        # Calculate entropy
        entropy = 0
        content_len = len(content)
        for count in freq.values():
            p = count / content_len
            if p > 0:
                entropy -= p * math.log2(p)
        
        # High entropy threshold (normal JS ~4.5, obfuscated ~6+)
        return entropy > 5.5
    
    def scan_directory(self, directory: Path) -> Dict[str, List[Dict]]:
        """
        Recursively scan directory for JavaScript files.
        
        Returns:
            Dictionary mapping file paths to their findings
        """
        results = {}
        
        if not directory.exists():
            print(f"[!] Directory not found: {directory}")
            return results
        
        if self.verbose:
            print(f"[*] Scanning directory: {directory}")
        
        # Find all JS files recursively
        js_files = list(directory.rglob('*.js'))
        
        if not js_files:
            print(f"[!] No JavaScript files found in {directory}")
            return results
        
        if self.verbose:
            print(f"[*] Found {len(js_files)} JavaScript files")
        
        for js_file in js_files:
            if self.verbose:
                print(f"[*] Scanning: {js_file.relative_to(directory)}")
            
            findings = self.scan_file(js_file)
            if findings:
                results[str(js_file.relative_to(directory))] = findings
        
        return results
    
    def generate_report(self, results: Dict[str, List[Dict]], output_file: Path = None) -> str:
        """
        Generate a detailed report of findings.
        """
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("MALICIOUS JAVASCRIPT DETECTION REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")
        
        # Summary statistics
        report_lines.append("SUMMARY")
        report_lines.append("-" * 80)
        report_lines.append(f"Files Scanned:        {self.stats['files_scanned']}")
        report_lines.append(f"Malicious Files:      {self.stats['malicious_files']}")
        report_lines.append(f"Total Findings:       {self.stats['total_findings']}")
        report_lines.append(f"  HIGH Severity:      {self.stats['high_severity']}")
        report_lines.append(f"  MEDIUM Severity:    {self.stats['medium_severity']}")
        report_lines.append(f"  LOW Severity:       {self.stats['low_severity']}")
        report_lines.append("")
        
        if not results:
            report_lines.append("✓ No malicious patterns detected!")
            report_lines.append("")
        else:
            report_lines.append("DETAILED FINDINGS")
            report_lines.append("-" * 80)
            
            # Sort files by number of findings (most suspicious first)
            sorted_files = sorted(results.items(), key=lambda x: len(x[1]), reverse=True)
            
            for file_path, findings in sorted_files:
                report_lines.append("")
                report_lines.append(f"FILE: {file_path}")
                report_lines.append(f"Findings: {len(findings)}")
                report_lines.append("-" * 80)
                
                # Group by severity
                high = [f for f in findings if f['severity'] == 'HIGH']
                medium = [f for f in findings if f['severity'] == 'MEDIUM']
                low = [f for f in findings if f['severity'] == 'LOW']
                
                for severity, findings_list in [('HIGH', high), ('MEDIUM', medium), ('LOW', low)]:
                    if findings_list:
                        report_lines.append(f"\n{severity} SEVERITY:")
                        for finding in findings_list:
                            report_lines.append(f"  - Line {finding['line']}: {finding['description']}")
                            report_lines.append(f"    Type: {finding['type']}")
                            report_lines.append(f"    CWE: {finding['cwe']}")
                            report_lines.append(f"    Snippet: {finding['snippet'][:150]}")
                            report_lines.append("")
        
        report_lines.append("=" * 80)
        report_lines.append("END OF REPORT")
        report_lines.append("=" * 80)
        
        report_text = "\n".join(report_lines)
        
        # Save to file if specified
        if output_file:
            output_file.write_text(report_text)
            print(f"\n[+] Report saved to: {output_file}")
        
        return report_text


def main():
    parser = argparse.ArgumentParser(
        description='Detect malicious JavaScript patterns in files'
    )
    parser.add_argument(
        '--dir',
        type=str,
        default='diff_results',
        help='Directory to scan (default: diff_results)'
    )
    parser.add_argument(
        '--output',
        type=str,
        help='Output report file (optional)'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results in JSON format'
    )
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress verbose output'
    )
    
    args = parser.parse_args()
    
    # Initialize detector
    detector = MaliciousJSDetector(verbose=not args.quiet)
    
    # Scan directory
    scan_dir = Path(args.dir)
    results = detector.scan_directory(scan_dir)
    
    # Generate output
    if args.json:
        output_data = {
            'scan_time': datetime.now().isoformat(),
            'directory': str(scan_dir),
            'statistics': detector.stats,
            'findings': results
        }
        
        if args.output:
            output_file = Path(args.output)
            output_file.write_text(json.dumps(output_data, indent=2))
            print(f"\n[+] JSON report saved to: {output_file}")
        else:
            print(json.dumps(output_data, indent=2))
    else:
        output_file = Path(args.output) if args.output else None
        report = detector.generate_report(results, output_file)
        if not args.output:
            print("\n" + report)


if __name__ == '__main__':
    main()
