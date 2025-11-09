#!/usr/bin/env python3
"""
WordPress Vulnerability Signature Generator v2.0

Enhanced modular version with better pattern detection, validation, and resume capability.
"""

import json
import os
import signal
import sys
from typing import Dict, List
from pathlib import Path
from collections import defaultdict

# Add package to path
sys.path.insert(0, str(Path(__file__).parent))

from wordpress_vulnerability_analyzer import (
    Config,
    VulnerabilityInfo,
    SignatureGenerator,
)

# Force unbuffered output
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', buffering=1)

# Global shutdown flag
shutdown_requested = False


def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully."""
    global shutdown_requested
    print("\n\n[!] Shutdown requested. Finishing current vulnerability and saving progress...")
    shutdown_requested = True


def load_vulnerabilities(filepath: str) -> Dict:
    """Load vulnerabilities from JSON file."""
    with open(filepath, 'r') as f:
        vulns = json.load(f)
    # Filter out null entries
    return {k: v for k, v in vulns.items() if v is not None}


def main():
    """Main signature generation pipeline."""
    global shutdown_requested

    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("=== WordPress Vulnerability Signature Generator v2.0 ===\n")

    # Initialize configuration
    print("[*] Initializing configuration...")
    config = Config()

    try:
        config.validate()
    except ValueError as e:
        print(f"[!] Configuration error: {e}")
        sys.exit(1)

    config.ensure_directories()

    # Initialize components
    print("[*] Initializing components...")
    generator = SignatureGenerator(config)
    progress_mgr = generator.progress_manager
    storage = generator.signature_storage

    # Load progress
    print(f"[*] Loading progress from {config.progress_file}...")
    processed_ids = progress_mgr.load()

    if processed_ids:
        print(f"[*] Found {len(processed_ids)} already processed vulnerabilities")
        print(f"[*] Resuming from where we left off...")
    else:
        print(f"[*] Starting fresh (no previous progress found)")

    # Load vulnerabilities
    print(f"\n[*] Loading vulnerabilities from {config.vulnerabilities_file}...")
    vulnerabilities = load_vulnerabilities(config.vulnerabilities_file)

    total_plugins = len(vulnerabilities)
    total_vulns = sum(len(vulns) for vulns in vulnerabilities.values())
    remaining = total_vulns - len(processed_ids)

    print(f"[*] Loaded {total_vulns} vulnerabilities across {total_plugins} plugins")
    print(f"[*] Remaining to process: {remaining}\n")

    # Processing statistics
    stats = {
        'processed': 0,
        'success': 0,
        'failed': 0,
        'skipped': len(processed_ids),
        'high_quality': 0,
        'medium_quality': 0,
        'low_quality': 0,
    }

    # Process vulnerabilities
    for plugin_slug, plugin_vulns in vulnerabilities.items():
        if shutdown_requested:
            break

        print(f"\n[{stats['processed']}/{total_vulns}] Processing plugin: {plugin_slug}")

        for vuln in plugin_vulns:
            if shutdown_requested:
                break

            cve = vuln.get('cve', 'N/A')
            vuln_type = vuln.get('type', 'Unknown')
            title = vuln.get('title', '')
            wordfence_uuid = vuln.get('wordfence_uuid')

            # Create vulnerability info
            vuln_info = VulnerabilityInfo(
                cve=cve,
                plugin_slug=plugin_slug,
                vuln_type=vuln_type,
                title=title,
                affected_versions="unknown",  # Will be populated later
                patched_version=None,
                wordfence_uuid=wordfence_uuid,
                references=vuln.get('references', [])
            )

            vuln_id = vuln_info.get_unique_id()

            # Skip if already processed
            if progress_mgr.is_processed(vuln_id):
                stats['skipped'] += 1
                stats['processed'] += 1
                print(f"  [{stats['processed']}/{total_vulns}] {cve} - {vuln_type} [SKIPPED]")
                continue

            print(f"  [{stats['processed']}/{total_vulns}] {cve} - {vuln_type}")

            # Get version information (simplified for now)
            # In production, you'd fetch from Wordfence API
            vuln_info.affected_versions = title.split()[-1] if title else "unknown"

            # Find versions in SVN
            print(f"    [*] Looking for versions in SVN...")
            vuln_version, fixed_version = generator.svn_extractor.find_vulnerable_and_patched_versions(
                plugin_slug,
                vuln_info.affected_versions,
                vuln_info.patched_version
            )

            if not vuln_version or not fixed_version:
                print(f"    [!] Could not find suitable versions in SVN")
                progress_mgr.mark_processed(vuln_id)
                stats['processed'] += 1
                stats['failed'] += 1

                if stats['processed'] % config.progress_save_frequency == 0:
                    progress_mgr.save(progress_mgr.processed_ids, stats)
                continue

            print(f"    [->] Comparing versions: {vuln_version} -> {fixed_version}")

            # Get diff
            print(f"    [*] Extracting diff from local repository...")
            diff = generator.svn_extractor.get_diff_from_local(
                plugin_slug, vuln_version, fixed_version
            )

            if not diff:
                print(f"    [X] Failed to extract diff")
                progress_mgr.mark_processed(vuln_id)
                stats['processed'] += 1
                stats['failed'] += 1

                if stats['processed'] % config.progress_save_frequency == 0:
                    progress_mgr.save(progress_mgr.processed_ids, stats)
                continue

            # Generate signature
            signature = generator.generate_signature(vuln_info, diff)

            if signature:
                # Save signature immediately
                filepath = storage.save_signature(signature)

                quality = signature.context.get('quality_score', 0)
                if quality >= 0.8:
                    stats['high_quality'] += 1
                    quality_label = "HIGH"
                elif quality >= 0.5:
                    stats['medium_quality'] += 1
                    quality_label = "MEDIUM"
                else:
                    stats['low_quality'] += 1
                    quality_label = "LOW"

                print(f"    [+] Signature saved: {filepath}")
                print(f"    [+] Pattern: {signature.pattern}")
                print(f"    [+] Exploitability: {signature.exploitability_score:.1f}/10")
                print(f"    [+] Quality: {quality:.2f} ({quality_label})")
                print(f"    [+] Validation: {'✓ PASSED' if signature.validated else '✗ FAILED'}")

                stats['success'] += 1
            else:
                print(f"    [-] No signature pattern detected")
                stats['failed'] += 1

            # Mark as processed
            progress_mgr.mark_processed(vuln_id)
            stats['processed'] += 1

            # Save progress periodically
            if stats['processed'] % config.progress_save_frequency == 0:
                progress_mgr.save(progress_mgr.processed_ids, stats)
                print(f"\n    [*] Progress saved ({stats['processed']}/{total_vulns}, "
                      f"{stats['success']} signatures)")

    # Save final progress
    print(f"\n[*] Saving final progress...")
    progress_mgr.save(progress_mgr.processed_ids, stats)

    # Generate consolidated file
    print(f"\n[*] Generating consolidated signatures file...")
    generator.save_consolidated_signatures(config.signatures_consolidated_file)

    # Generate statistics
    gen_stats = generator.generate_statistics()

    # Print summary
    print(f"\n=== Generation Complete ===")
    print(f"Total processed: {stats['processed']}")
    print(f"Skipped (already done): {stats['skipped']}")
    print(f"Signatures extracted: {stats['success']}")
    print(f"Failed: {stats['failed']}")

    if stats['processed'] > 0:
        success_rate = (stats['success'] / stats['processed']) * 100
        print(f"Success rate: {success_rate:.1f}%")

    print(f"\n=== Quality Distribution ===")
    print(f"High quality (≥0.8): {stats['high_quality']}")
    print(f"Medium quality (≥0.5): {stats['medium_quality']}")
    print(f"Low quality (<0.5): {stats['low_quality']}")

    print(f"\n=== Signature Database Statistics ===")
    print(f"Total signatures: {gen_stats['total_signatures']}")
    print(f"Average exploitability: {gen_stats['avg_exploitability_score']:.2f}/10")
    print(f"Average quality: {gen_stats['avg_quality_score']:.2f}")
    print(f"Critical signatures (≥8.0): {gen_stats['critical_signatures']}")
    print(f"High confidence signatures: {gen_stats['high_confidence_signatures']}")

    print(f"\n=== Top Vulnerability Types ===")
    top_types = sorted(
        gen_stats['vuln_type_distribution'].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]

    for vuln_type, count in top_types:
        print(f"  {vuln_type}: {count}")

    print(f"\n[+] Signatures saved to: {config.signatures_output_dir}/")
    print(f"[+] Consolidated file: {config.signatures_consolidated_file}")
    print(f"[+] Progress file: {config.progress_file}")


if __name__ == "__main__":
    import os
    main()
