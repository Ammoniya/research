#!/usr/bin/env python3
"""
Generate improved AST-based signatures using proper diff parsing.

This script implements the correct approach:
1. Parse unified diff → extract file paths and line ranges
2. Reconstruct full before/after files (valid PHP)
3. Parse with tree-sitter into ASTs
4. Map line ranges to find minimal changed nodes
5. Extract minimal differing subtree
6. Normalize to create reusable patterns

Usage:
    python generate_improved_signatures.py --input cve_data.json
    python generate_improved_signatures.py --input-file single_cve.json
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict

sys.path.insert(0, str(Path(__file__).parent))

from wordpress_vulnerability_analyzer.improved_signature_generator import ImprovedSignatureGenerator


def process_cve_json(cve_data: Dict, generator: ImprovedSignatureGenerator) -> List[Dict]:
    """
    Process a single CVE JSON object.

    Expected format:
    {
        "cve": "CVE-2022-36405",
        "plugin_slug": "amcharts-charts-and-maps",
        "vuln_type": "Cross-site Scripting",
        "title": "...",
        "unified_diff": "diff -ruN ...",  # Optional
        "vulnerable_code": "...",
        "patched_code": "...",
        ...
    }

    Args:
        cve_data: CVE data dictionary
        generator: Signature generator instance

    Returns:
        List of signature dictionaries
    """
    cve = cve_data.get('cve', 'Unknown')
    plugin_slug = cve_data.get('plugin_slug', 'unknown-plugin')
    vuln_type = cve_data.get('vuln_type', 'Unknown')
    title = cve_data.get('title', '')

    signatures = []

    # Prefer unified_diff if available
    if 'unified_diff' in cve_data and cve_data['unified_diff']:
        print(f"\nProcessing {cve} using unified diff...")

        sigs = generator.generate_from_unified_diff(
            unified_diff=cve_data['unified_diff'],
            cve=cve,
            plugin_slug=plugin_slug,
            vuln_type=vuln_type,
            title=title
        )

        signatures.extend(sigs)

    # Fallback to code snippets
    elif 'vulnerable_code' in cve_data and 'patched_code' in cve_data:
        print(f"\nProcessing {cve} using code snippets...")

        sig = generator.generate_from_code_snippets(
            vuln_code=cve_data['vulnerable_code'],
            patch_code=cve_data['patched_code'],
            cve=cve,
            plugin_slug=plugin_slug,
            vuln_type=vuln_type,
            title=title,
            file_path=cve_data.get('file_path', '')
        )

        if sig:
            signatures.append(sig)

    else:
        print(f"\n✗ {cve}: No diff or code snippets available")

    return signatures


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Generate improved AST signatures from CVE data',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--input',
        type=Path,
        help='Input JSON file with CVE data'
    )

    parser.add_argument(
        '--output',
        type=Path,
        help='Output directory for signatures (default: data/output/improved_signatures)'
    )

    parser.add_argument(
        '--output-file',
        type=Path,
        help='Output to a single JSON file instead of directory'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Print detailed progress'
    )

    args = parser.parse_args()

    # Set defaults
    if not args.output and not args.output_file:
        args.output = Path('data/output/improved_signatures')

    # Create generator
    generator = ImprovedSignatureGenerator(verbose=args.verbose)

    # Process input
    all_signatures = []

    if args.input:
        print(f"Loading CVE data from {args.input}...")

        with open(args.input, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Handle different input formats
        if isinstance(data, dict):
            # Single CVE or dict of plugin -> CVEs
            if 'cve' in data:
                # Single CVE
                signatures = process_cve_json(data, generator)
                all_signatures.extend(signatures)
            else:
                # Dict of plugin -> CVEs
                for plugin_slug, cves in data.items():
                    if isinstance(cves, list):
                        for cve_data in cves:
                            signatures = process_cve_json(cve_data, generator)
                            all_signatures.extend(signatures)
                    elif isinstance(cves, dict):
                        signatures = process_cve_json(cves, generator)
                        all_signatures.extend(signatures)

        elif isinstance(data, list):
            # List of CVEs
            for cve_data in data:
                signatures = process_cve_json(cve_data, generator)
                all_signatures.extend(signatures)

    else:
        print("Error: --input is required")
        sys.exit(1)

    # Save output
    print(f"\n{'='*70}")
    print(f"Generated {len(all_signatures)} signature(s)")
    print(f"{'='*70}")

    if args.output_file:
        # Save to single file
        print(f"\nSaving to {args.output_file}...")

        args.output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(args.output_file, 'w', encoding='utf-8') as f:
            json.dump(all_signatures, f, indent=2, ensure_ascii=False)

        print(f"✓ Saved {len(all_signatures)} signature(s) to {args.output_file}")

    elif args.output:
        # Save to directory (one file per signature)
        print(f"\nSaving to {args.output}/...")

        args.output.mkdir(parents=True, exist_ok=True)

        for i, sig in enumerate(all_signatures, 1):
            cve = sig.get('cve', f'sig_{i}')
            plugin = sig.get('plugin_slug', 'unknown')

            # Create plugin subdirectory
            plugin_dir = args.output / plugin
            plugin_dir.mkdir(exist_ok=True)

            # Save signature
            filename = f"{cve}_improved.json"
            filepath = plugin_dir / filename

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(sig, f, indent=2, ensure_ascii=False)

            print(f"  {i}. {filepath}")

        print(f"\n✓ Saved {len(all_signatures)} signature(s) to {args.output}")

    # Print summary
    if all_signatures:
        print(f"\nSignature Summary:")
        print(f"{'='*70}")

        pattern_types = {}
        for sig in all_signatures:
            ptype = sig.get('pattern_type', 'unknown')
            pattern_types[ptype] = pattern_types.get(ptype, 0) + 1

        for ptype, count in sorted(pattern_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  {ptype}: {count}")

        # Show security functions added
        all_sec_funcs = set()
        for sig in all_signatures:
            all_sec_funcs.update(sig.get('security_functions_added', []))

        if all_sec_funcs:
            print(f"\nSecurity Functions Added:")
            for func in sorted(all_sec_funcs):
                print(f"  - {func}")

        print(f"{'='*70}\n")


if __name__ == '__main__':
    main()
