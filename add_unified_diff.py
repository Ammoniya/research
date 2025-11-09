#!/usr/bin/env python3
"""
Add Unified Diff to Existing Signature

This script takes an existing vulnerability signature JSON and adds
the full unified diff by fetching it from the SVN repository.
"""

import json
import sys
from pathlib import Path
from wordpress_vulnerability_analyzer.svn_extractor import SVNDiffExtractor
from wordpress_vulnerability_analyzer.config import Config


def add_unified_diff_to_signature(signature_data: dict, config: Config) -> dict:
    """
    Add unified diff to an existing signature.

    Args:
        signature_data: Existing signature data
        config: Configuration object

    Returns:
        Updated signature data with unified_diff field
    """
    plugin_slug = signature_data.get('plugin_slug')
    affected_versions = signature_data.get('context', {}).get('affected_versions')
    patched_version = signature_data.get('context', {}).get('patched_version')

    if not plugin_slug or not affected_versions:
        print(f"[!] Missing required fields: plugin_slug or affected_versions")
        return signature_data

    print(f"[*] Processing {plugin_slug}...")
    print(f"    Affected versions: {affected_versions}")
    print(f"    Patched version: {patched_version}")

    # Initialize SVN extractor
    extractor = SVNDiffExtractor(config.svn_repos_dir, config.diff_timeout)

    # Find versions
    vuln_version, fixed_version = extractor.find_vulnerable_and_patched_versions(
        plugin_slug, affected_versions, patched_version
    )

    if not vuln_version or not fixed_version:
        print(f"[!] Could not determine versions for {plugin_slug}")
        print(f"    Vulnerable version: {vuln_version}")
        print(f"    Fixed version: {fixed_version}")
        return signature_data

    print(f"[*] Fetching diff: {vuln_version} -> {fixed_version}")

    # Get diff
    diff_content = extractor.get_diff_from_local(plugin_slug, vuln_version, fixed_version)

    if not diff_content:
        print(f"[!] Could not fetch diff for {plugin_slug}")
        return signature_data

    # Add unified diff to signature
    signature_data['unified_diff'] = diff_content
    print(f"[✓] Added unified diff ({len(diff_content)} bytes)")

    return signature_data


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python add_unified_diff.py <signature_json_file> [--stdin]")
        print("   OR: echo '<json>' | python add_unified_diff.py --stdin")
        sys.exit(1)

    # Load configuration
    config = Config()

    # Read signature data
    if sys.argv[1] == '--stdin':
        signature_data = json.load(sys.stdin)
    else:
        json_file = sys.argv[1]
        with open(json_file, 'r') as f:
            signature_data = json.load(f)

    # Add unified diff
    updated_signature = add_unified_diff_to_signature(signature_data, config)

    # Output updated JSON
    print("\n" + "="*80)
    print(json.dumps(updated_signature, indent=2))


if __name__ == '__main__':
    main()
