#!/usr/bin/env python3
"""
Generate AST-based signatures from CVE data.

This script processes CVE JSON objects to generate AST signatures:
1. Loads CVE data from existing signature files or JSON
2. Extracts unified diffs from signatures
3. Parses pre/post patch code into ASTs
4. Diffs the ASTs to find minimal differences
5. Stores AST signatures in the database

Usage:
    python generate_ast_signatures.py [OPTIONS]

Options:
    --input-dir PATH        Path to existing signatures directory
    --input-json PATH       Path to CVE JSON file
    --output-dir PATH       Output directory for AST signatures (default: data/output/ast_signatures)
    --limit N               Process only first N signatures
    --verbose               Print detailed progress information
    --only-security         Only keep security-relevant diffs
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from data_paths import OUTPUT_AST_SIGNATURES_DIR, OUTPUT_SIGNATURES_DIR
from wordpress_vulnerability_analyzer.models import CodeSignature
from wordpress_vulnerability_analyzer.ast_signature_generator import ASTSignatureGenerator


class ASTSignaturePipeline:
    """Main pipeline for generating AST signatures from CVE data."""

    def __init__(self, verbose: bool = False):
        """
        Initialize the pipeline.

        Args:
            verbose: Whether to print detailed progress
        """
        self.verbose = verbose
        self.generator = ASTSignatureGenerator(verbose=verbose)
        self.stats = {
            'total': 0,
            'processed': 0,
            'success': 0,
            'failed': 0,
            'skipped': 0
        }

    def process_signature_directory(
        self,
        input_dir: Path,
        output_dir: Path,
        limit: Optional[int] = None
    ):
        """
        Process all signature files in a directory.

        Args:
            input_dir: Directory containing existing signature JSON files
            output_dir: Output directory for AST signatures
            limit: Maximum number of signatures to process
        """
        if not input_dir.exists():
            print(f"Error: Input directory does not exist: {input_dir}")
            return

        print(f"\n{'='*70}")
        print(f"AST Signature Generation Pipeline")
        print(f"{'='*70}")
        print(f"Input:  {input_dir}")
        print(f"Output: {output_dir}")
        print(f"{'='*70}\n")

        # Find all signature JSON files
        signature_files = list(input_dir.rglob("*.json"))
        self.stats['total'] = len(signature_files)

        if limit:
            signature_files = signature_files[:limit]
            print(f"Limiting to first {limit} signatures\n")

        if not signature_files:
            print("No signature files found!")
            return

        print(f"Found {len(signature_files)} signature file(s)\n")

        # Process each signature
        for i, sig_file in enumerate(signature_files, 1):
            print(f"\n[{i}/{len(signature_files)}] Processing: {sig_file.name}")

            try:
                # Load existing signature
                code_sig = self._load_code_signature(sig_file)

                if not code_sig:
                    print(f"  ✗ Failed to load signature")
                    self.stats['failed'] += 1
                    continue

                # Generate AST signature
                ast_sig = self.generator.generate_from_code_signature(code_sig)

                if not ast_sig:
                    print(f"  ✗ Failed to generate AST signature")
                    self.stats['failed'] += 1
                    continue

                # Save AST signature
                output_path = self.generator.save_signature(ast_sig, output_dir)
                print(f"  ✓ Saved: {output_path.relative_to(output_dir.parent)}")

                self.stats['success'] += 1
                self.stats['processed'] += 1

            except Exception as e:
                print(f"  ✗ Error: {e}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()
                self.stats['failed'] += 1

        # Print final statistics
        self._print_statistics()

    def process_cve_json(
        self,
        json_file: Path,
        output_dir: Path,
        limit: Optional[int] = None
    ):
        """
        Process CVEs from a JSON file directly.

        Expected JSON format:
        {
          "plugin_slug": [
            {
              "cve": "CVE-2021-12345",
              "type": "Cross-Site Scripting",
              "title": "...",
              "unified_diff": "...",
              "vulnerable_version": "1.0.0",
              "patched_version": "1.0.1",
              ...
            }
          ]
        }

        Args:
            json_file: Path to CVE JSON file
            output_dir: Output directory for AST signatures
            limit: Maximum number of CVEs to process
        """
        if not json_file.exists():
            print(f"Error: JSON file does not exist: {json_file}")
            return

        print(f"\n{'='*70}")
        print(f"AST Signature Generation from CVE JSON")
        print(f"{'='*70}")
        print(f"Input:  {json_file}")
        print(f"Output: {output_dir}")
        print(f"{'='*70}\n")

        # Load JSON data
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Flatten into list of (plugin_slug, vuln) tuples
        vulnerabilities = []
        for plugin_slug, vulns in data.items():
            if not vulns:
                continue
            for vuln in vulns:
                vulnerabilities.append((plugin_slug, vuln))

        self.stats['total'] = len(vulnerabilities)

        if limit:
            vulnerabilities = vulnerabilities[:limit]
            print(f"Limiting to first {limit} vulnerabilities\n")

        print(f"Found {len(vulnerabilities)} vulnerability/vulnerabilities\n")

        # Process each vulnerability
        for i, (plugin_slug, vuln) in enumerate(vulnerabilities, 1):
            cve = vuln.get('cve', 'N/A')
            print(f"\n[{i}/{len(vulnerabilities)}] Processing: {plugin_slug} - {cve}")

            try:
                # Check if we have unified_diff
                if 'unified_diff' not in vuln:
                    print(f"  - Skipping: no unified_diff field")
                    self.stats['skipped'] += 1
                    continue

                # Generate AST signatures from unified diff
                ast_sigs = self.generator.generate_from_unified_diff(
                    cve=vuln.get('cve'),
                    plugin_slug=plugin_slug,
                    vuln_type=vuln.get('type', 'Unknown'),
                    title=vuln.get('title', ''),
                    unified_diff=vuln['unified_diff'],
                    vulnerable_version=vuln.get('vulnerable_version', ''),
                    patched_version=vuln.get('patched_version', ''),
                    wordfence_uuid=vuln.get('wordfence_uuid'),
                    references=vuln.get('references', [])
                )

                if not ast_sigs:
                    print(f"  ✗ Failed to generate AST signatures")
                    self.stats['failed'] += 1
                    continue

                # Save all generated signatures
                for ast_sig in ast_sigs:
                    output_path = self.generator.save_signature(ast_sig, output_dir)
                    print(f"  ✓ Saved: {output_path.relative_to(output_dir.parent)}")

                self.stats['success'] += 1
                self.stats['processed'] += 1

            except Exception as e:
                print(f"  ✗ Error: {e}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()
                self.stats['failed'] += 1

        # Print final statistics
        self._print_statistics()

    def _load_code_signature(self, filepath: Path) -> Optional[CodeSignature]:
        """
        Load a CodeSignature from a JSON file.

        Args:
            filepath: Path to the signature JSON file

        Returns:
            CodeSignature object or None if loading fails
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            return CodeSignature(
                cve=data.get('cve'),
                plugin_slug=data['plugin_slug'],
                vuln_type=data['vuln_type'],
                title=data['title'],
                wordfence_uuid=data.get('wordfence_uuid'),
                vulnerable_version=data.get('vulnerable_version', ''),
                patched_version=data.get('patched_version', ''),
                affected_versions=data.get('affected_versions', ''),
                patch_location=data.get('patch_location', ''),
                pre_patch_code=data.get('pre_patch_code', ''),
                post_patch_code=data.get('post_patch_code', ''),
                unified_diff=data.get('unified_diff', ''),
                files_changed=data.get('files_changed', 0),
                lines_added=data.get('lines_added', 0),
                lines_removed=data.get('lines_removed', 0),
                extracted_at=data.get('extracted_at', ''),
                references=data.get('references', [])
            )

        except Exception as e:
            if self.verbose:
                print(f"Error loading {filepath}: {e}")
            return None

    def _print_statistics(self):
        """Print final processing statistics."""
        print(f"\n{'='*70}")
        print(f"Processing Complete")
        print(f"{'='*70}")
        print(f"Total:     {self.stats['total']}")
        print(f"Processed: {self.stats['processed']}")
        print(f"Success:   {self.stats['success']} ✓")
        print(f"Failed:    {self.stats['failed']} ✗")
        print(f"Skipped:   {self.stats['skipped']} -")

        if self.stats['processed'] > 0:
            success_rate = (self.stats['success'] / self.stats['processed']) * 100
            print(f"Success Rate: {success_rate:.1f}%")

        print(f"{'='*70}\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Generate AST-based signatures from CVE data',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--input-dir',
        type=Path,
        help='Path to existing signatures directory'
    )

    parser.add_argument(
        '--input-json',
        type=Path,
        help='Path to CVE JSON file'
    )

    parser.add_argument(
        '--output-dir',
        type=Path,
        default=OUTPUT_AST_SIGNATURES_DIR,
        help=f'Output directory for AST signatures (default: {OUTPUT_AST_SIGNATURES_DIR})'
    )

    parser.add_argument(
        '--limit',
        type=int,
        help='Process only first N items'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Print detailed progress information'
    )

    args = parser.parse_args()

    # Validate arguments
    if not args.input_dir and not args.input_json:
        # Default to processing existing signatures
        args.input_dir = OUTPUT_SIGNATURES_DIR

    if args.input_dir and args.input_json:
        print("Error: Cannot specify both --input-dir and --input-json")
        sys.exit(1)

    # Create pipeline
    pipeline = ASTSignaturePipeline(verbose=args.verbose)

    # Run processing
    if args.input_dir:
        pipeline.process_signature_directory(
            input_dir=args.input_dir,
            output_dir=args.output_dir,
            limit=args.limit
        )
    elif args.input_json:
        pipeline.process_cve_json(
            json_file=args.input_json,
            output_dir=args.output_dir,
            limit=args.limit
        )


if __name__ == '__main__':
    main()
