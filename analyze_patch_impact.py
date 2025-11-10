#!/usr/bin/env python3
"""
Analyze the impact of one CVE patch on another.

This script compares CVE patches using call graph analysis, data flow analysis,
and control flow graph comparison to determine how they relate to each other.

Usage:
    # Compare two specific CVEs
    python analyze_patch_impact.py --cve1 <path_to_cve1> --cve2 <path_to_cve2>

    # Compare all CVEs within each plugin (only adjacent chronological pairs)
    python analyze_patch_impact.py --signatures-dir <dir> --compare-all

    # Compare all pairs within each plugin
    python analyze_patch_impact.py --signatures-dir <dir> --compare-all --all-pairs

Supports both JSON (.json) and Markdown (.md) signature formats.
When both formats exist, JSON is preferred by default (use --prefer-format to change).

Examples:
    # Pairwise comparison
    python analyze_patch_impact.py --cve1 signatures/plugin/CVE-2023-1234.md \\
                                   --cve2 signatures/plugin/CVE-2023-5678.md \\
                                   --output results/impact_analysis.md

    # Batch analysis (adjacent CVEs only - default)
    python analyze_patch_impact.py --signatures-dir data/output/signatures \\
                                   --compare-all \\
                                   --output-dir data/output/impact_analysis

    # Batch analysis (all pairs)
    python analyze_patch_impact.py --signatures-dir data/output/signatures \\
                                   --compare-all --all-pairs
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

from patch_impact_analyzer import PatchImpactAnalyzer


def load_cve_signature(file_path: Path) -> Optional[Dict]:
    """
    Load CVE signature data from a JSON or Markdown file.

    Args:
        file_path: Path to the JSON or Markdown file

    Returns:
        Dict with CVE signature data or None if error
    """
    try:
        if file_path.suffix == '.json':
            with open(file_path, 'r') as f:
                data = json.load(f)
            return data
        elif file_path.suffix == '.md':
            # Parse markdown format
            return parse_markdown_signature(file_path)
        else:
            print(f"Warning: Unsupported file format: {file_path.suffix}")
            return None
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        return None
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in file: {file_path}")
        return None
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return None


def parse_markdown_signature(file_path: Path) -> Optional[Dict]:
    """
    Parse a markdown signature file to extract CVE data.

    Args:
        file_path: Path to the markdown file

    Returns:
        Dict with CVE signature data
    """
    import re

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Extract CVE/title from header
        cve_match = re.search(r'^#\s+(.+?)$', content, re.MULTILINE)
        cve = cve_match.group(1) if cve_match else file_path.stem

        # Extract plugin slug
        plugin_match = re.search(r'\*\*Plugin\*\*:\s*(.+?)$', content, re.MULTILINE)
        plugin_slug = plugin_match.group(1).strip() if plugin_match else 'unknown'

        # Extract vulnerability type
        type_match = re.search(r'\*\*Type\*\*:\s*(.+?)$', content, re.MULTILINE)
        vuln_type = type_match.group(1).strip() if type_match else 'Unknown'

        # Extract title
        title_match = re.search(r'\*\*Title\*\*:\s*(.+?)$', content, re.MULTILINE)
        title = title_match.group(1).strip() if title_match else ''

        # Extract patch location
        patch_match = re.search(r'\*\*Patch\*\*:\s*(.+?)$', content, re.MULTILINE)
        patch_location = patch_match.group(1).strip() if patch_match else ''

        # Extract pre-patch code
        pre_patch_match = re.search(
            r'## Pre-Patch Code.*?```(?:php)?\n(.*?)\n```',
            content,
            re.DOTALL
        )
        pre_patch_code = pre_patch_match.group(1) if pre_patch_match else ''

        # Extract post-patch code
        post_patch_match = re.search(
            r'## Post-Patch Code.*?```(?:php)?\n(.*?)\n```',
            content,
            re.DOTALL
        )
        post_patch_code = post_patch_match.group(1) if post_patch_match else ''

        # Extract unified diff
        diff_match = re.search(
            r'## Unified Diff.*?```(?:diff)?\n(.*?)\n```',
            content,
            re.DOTALL
        )
        unified_diff = diff_match.group(1) if diff_match else ''

        return {
            'cve': cve,
            'plugin_slug': plugin_slug,
            'vuln_type': vuln_type,
            'title': title,
            'patch_location': patch_location,
            'pre_patch_code': pre_patch_code,
            'post_patch_code': post_patch_code,
            'unified_diff': unified_diff
        }
    except Exception as e:
        print(f"Error parsing markdown {file_path}: {e}")
        return None


def load_signatures_from_directory(directory: Path, prefer_format: str = 'json', verbose: bool = False) -> List[Dict]:
    """
    Load all CVE signatures from a directory (searches recursively).

    Deduplicates signatures by preferring one format when both JSON and Markdown exist.

    Args:
        directory: Directory containing signature JSON or Markdown files
        prefer_format: 'json' or 'markdown' - format to prefer when both exist
        verbose: Whether to print verbose output

    Returns:
        List of signature dicts
    """
    signatures = []

    if not directory.exists():
        print(f"❌ Error: Directory not found: {directory}")
        return signatures

    if verbose:
        print(f"\n{'='*60}")
        print(f"Loading signatures from: {directory}")
        print(f"{'='*60}")
        print(f"Searching for signature files...")

    # Search recursively for both JSON and Markdown files
    json_files = list(directory.rglob("*.json"))
    md_files = list(directory.rglob("*.md"))

    print(f"✓ Found {len(json_files)} JSON and {len(md_files)} Markdown signature files")

    # Build a map of signature stem -> files to deduplicate
    from collections import defaultdict
    sig_map = defaultdict(lambda: {'json': None, 'md': None})

    for json_file in json_files:
        sig_map[json_file.stem]['json'] = json_file

    for md_file in md_files:
        sig_map[md_file.stem]['md'] = md_file

    if verbose:
        print(f"\nDeduplicating signatures (preferring {prefer_format} format)...")
        duplicates = sum(1 for files in sig_map.values() if files['json'] and files['md'])
        print(f"  Found {len(sig_map)} unique signatures")
        print(f"  Resolved {duplicates} duplicates (JSON+MD pairs)")

    # Load one file per signature, preferring the specified format
    loaded_count = 0
    failed_count = 0

    if verbose:
        print(f"\nLoading signature files...")

    for sig_name, files in sig_map.items():
        # Choose which file to load based on preference
        if prefer_format == 'json' and files['json']:
            sig_file = files['json']
        elif prefer_format == 'markdown' and files['md']:
            sig_file = files['md']
        elif files['json']:
            sig_file = files['json']
        elif files['md']:
            sig_file = files['md']
        else:
            continue

        sig = load_cve_signature(sig_file)
        if sig:
            # Add file path for reference
            sig['_source_file'] = str(sig_file)
            signatures.append(sig)
            loaded_count += 1
            if verbose and loaded_count % 10 == 0:
                print(f"  Loaded {loaded_count}/{len(sig_map)} signatures...", end='\r')
        else:
            failed_count += 1
            print(f"⚠️  Warning: Failed to load {sig_file}")

    print(f"✓ Loaded {loaded_count} unique signatures (preferring {prefer_format} format)")
    if failed_count > 0:
        print(f"⚠️  {failed_count} signatures failed to load")

    if verbose:
        print(f"{'='*60}\n")

    return signatures


def create_example_cve_data(cve_id: str, code: str) -> Dict:
    """
    Create example CVE data for testing.

    Args:
        cve_id: CVE identifier
        code: PHP code

    Returns:
        Dict with CVE data structure
    """
    return {
        'cve': cve_id,
        'plugin_slug': 'example-plugin',
        'vuln_type': 'Example Vulnerability',
        'title': f'Example vulnerability {cve_id}',
        'patch_location': 'example.php',
        'pre_patch_code': '',
        'post_patch_code': code,
        'unified_diff': ''
    }


def run_pairwise_analysis(cve1_path: Path, cve2_path: Path,
                         output_path: Optional[Path] = None,
                         verbose: bool = False) -> int:
    """
    Run impact analysis between two CVEs.

    Args:
        cve1_path: Path to first CVE signature
        cve2_path: Path to second CVE signature
        output_path: Optional path to save the report
        verbose: Whether to print verbose output

    Returns:
        Exit code (0 for success)
    """
    print(f"\n{'='*60}")
    print(f"Patch Impact Analysis")
    print(f"{'='*60}\n")

    # Load CVE data
    print(f"Loading CVE 1: {cve1_path}")
    cve1_data = load_cve_signature(cve1_path)
    if not cve1_data:
        return 1

    print(f"Loading CVE 2: {cve2_path}")
    cve2_data = load_cve_signature(cve2_path)
    if not cve2_data:
        return 1

    # Initialize analyzer
    analyzer = PatchImpactAnalyzer()

    # Perform analysis
    print(f"\nAnalyzing impact relationship...\n")
    impact = analyzer.analyze_patch_impact(cve1_data, cve2_data, verbose=verbose)

    # Print summary
    print(f"\n{'='*60}")
    print(f"Analysis Results")
    print(f"{'='*60}\n")
    print(f"CVE 1: {impact.cve1}")
    print(f"CVE 2: {impact.cve2}")
    print(f"\nImpact Score: {impact.impact_score:.2f}/100")
    print(f"Impact Level: {impact.impact_level}")
    print(f"\nShared Functions: {len(impact.shared_functions)}")
    print(f"Shared Variables: {len(impact.shared_variables)}")
    print(f"Call Graph Overlap: {impact.call_graph_overlap:.1f}%")
    print(f"Relationships Found: {len(impact.relationships)}")

    if impact.relationships:
        print(f"\nKey Relationships:")
        for i, rel in enumerate(impact.relationships[:5], 1):
            print(f"  {i}. {rel.relationship_type}: {rel.description} (confidence: {rel.confidence:.2f})")

    # Generate and save report
    if output_path:
        print(f"\nGenerating detailed report...")
        report = analyzer.generate_report(impact, output_path)
        print(f"Report saved to: {output_path}")
    else:
        # Print report to stdout
        print(f"\n{'='*60}")
        print(f"Detailed Report")
        print(f"{'='*60}\n")
        report = analyzer.generate_report(impact)
        print(report)

    return 0


def run_batch_analysis(signatures_dir: Path, output_dir: Path,
                      verbose: bool = False,
                      adjacent_only: bool = True,
                      date_field: str = None,
                      prefer_format: str = 'json') -> int:
    """
    Run impact analysis on signatures in a directory.

    Args:
        signatures_dir: Directory containing signature files
        output_dir: Directory to save results
        verbose: Whether to print verbose output
        adjacent_only: Only compare chronologically adjacent CVEs within each plugin
        date_field: Field name for date/timestamp sorting (None = use CVE ID)
        prefer_format: 'json' or 'markdown' when both formats exist

    Returns:
        Exit code (0 for success)
    """
    if verbose:
        print(f"\n{'#'*60}")
        print(f"# BATCH PATCH IMPACT ANALYSIS")
        print(f"{'#'*60}")
        print(f"Configuration:")
        print(f"  Signatures directory: {signatures_dir}")
        print(f"  Output directory: {output_dir}")
        print(f"  Comparison mode: {'adjacent only' if adjacent_only else 'all pairs'}")
        print(f"  Date field: {date_field if date_field else 'CVE ID'}")
        print(f"  Prefer format: {prefer_format}")
        print(f"{'#'*60}\n")
    else:
        print(f"\n{'='*60}")
        print(f"Batch Patch Impact Analysis")
        print(f"{'='*60}\n")

    # Load all signatures (deduplicating JSON/Markdown)
    signatures = load_signatures_from_directory(signatures_dir, prefer_format=prefer_format, verbose=verbose)

    if len(signatures) < 2:
        print(f"❌ Error: Need at least 2 signatures for comparison. Found {len(signatures)}")
        return 1

    if verbose:
        print(f"✓ Ready to analyze {len(signatures)} CVE signatures\n")

    # Initialize analyzer
    if verbose:
        print(f"Initializing patch impact analyzer...")
    analyzer = PatchImpactAnalyzer()

    # Run comparisons
    if verbose:
        print(f"Starting comparison process...\n")

    results = analyzer.compare_multiple_patches(
        signatures,
        output_dir=output_dir,
        verbose=verbose,
        adjacent_only=adjacent_only,
        date_field=date_field
    )

    # Print summary
    if verbose:
        print(f"\n{'#'*60}")
        print(f"# BATCH ANALYSIS COMPLETE")
        print(f"{'#'*60}\n")
    else:
        print(f"\n{'='*60}")
        print(f"Batch Analysis Summary")
        print(f"{'='*60}\n")

    print(f"📊 Analysis Statistics:")
    print(f"  Total CVEs analyzed: {results['total_cves']}")
    print(f"  Total plugins: {results['total_plugins']}")
    print(f"  Total comparisons: {results['summary']['total_comparisons']}")
    print(f"  Comparison mode: {results['comparison_mode']}")

    print(f"\n📈 Impact Scores:")
    print(f"  Average: {results['summary']['average_impact_score']:.2f}/100")
    print(f"  Maximum: {results['summary']['max_impact_score']:.2f}/100")
    print(f"  Minimum: {results['summary']['min_impact_score']:.2f}/100")

    print(f"\n⚠️  High Impact Findings:")
    print(f"  High impact pairs (≥60): {results['summary']['high_impact_count']}")

    if results['high_impact_pairs']:
        print(f"\n🔍 Top High Impact Pairs:")
        for i, pair in enumerate(results['high_impact_pairs'][:10], 1):
            print(f"  {i:2d}. [{pair['plugin']}] {pair['pair']}: {pair['score']:.2f} ({pair['level']})")
        if len(results['high_impact_pairs']) > 10:
            print(f"  ... and {len(results['high_impact_pairs']) - 10} more high impact pairs")
    else:
        print(f"  No high impact pairs detected")

    print(f"\n💾 Output:")
    print(f"  Results saved to: {output_dir}")
    print(f"  Main report: {output_dir}/patch_impact_analysis.json")

    if verbose:
        print(f"\n{'#'*60}")
        print(f"# ANALYSIS COMPLETE")
        print(f"{'#'*60}\n")
    else:
        print(f"\n{'='*60}\n")

    return 0


def run_example_analysis(verbose: bool = False) -> int:
    """
    Run an example analysis with sample PHP code.

    Args:
        verbose: Whether to print verbose output

    Returns:
        Exit code (0 for success)
    """
    print(f"\n{'='*60}")
    print(f"Example Patch Impact Analysis")
    print(f"{'='*60}\n")

    # Create example CVE data with sample vulnerable code
    cve1_code = '''<?php
function process_user_input() {
    $user_id = $_GET['user_id'];
    $query = "SELECT * FROM users WHERE id = $user_id";
    $result = $wpdb->query($query);
    return $result;
}

function display_user_data($data) {
    echo $data;
}
'''

    cve2_code = '''<?php
function process_user_input() {
    $user_id = sanitize_text_field($_GET['user_id']);
    $user_id = intval($user_id);
    $query = $wpdb->prepare("SELECT * FROM users WHERE id = %d", $user_id);
    $result = $wpdb->query($query);
    return $result;
}

function display_user_data($data) {
    echo esc_html($data);
}

function validate_user_permissions() {
    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized');
    }
}
'''

    cve1_data = create_example_cve_data('CVE-2023-EXAMPLE-1', cve1_code)
    cve2_data = create_example_cve_data('CVE-2023-EXAMPLE-2', cve2_code)

    # Initialize analyzer
    analyzer = PatchImpactAnalyzer()

    # Perform analysis
    print(f"Analyzing example patches...\n")
    impact = analyzer.analyze_patch_impact(cve1_data, cve2_data, verbose=verbose)

    # Print results
    print(f"\n{'='*60}")
    print(f"Example Analysis Results")
    print(f"{'='*60}\n")
    print(f"Impact Score: {impact.impact_score:.2f}/100")
    print(f"Impact Level: {impact.impact_level}")
    print(f"\nShared Functions: {len(impact.shared_functions)}")
    if impact.shared_functions:
        for func in impact.shared_functions[:5]:
            print(f"  - {func}")

    print(f"\nShared Variables: {len(impact.shared_variables)}")
    if impact.shared_variables:
        for var in impact.shared_variables[:5]:
            print(f"  - {var}")

    print(f"\nRelationships Found: {len(impact.relationships)}")
    for i, rel in enumerate(impact.relationships, 1):
        print(f"\n{i}. {rel.relationship_type.replace('_', ' ').title()}")
        print(f"   Description: {rel.description}")
        print(f"   Confidence: {rel.confidence:.2f}")
        if rel.evidence:
            print(f"   Evidence:")
            for evidence in rel.evidence[:3]:
                print(f"     - {evidence}")

    return 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze the impact relationship between CVE patches",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument(
        '--cve1',
        type=Path,
        help='Path to first CVE signature file (JSON or Markdown)'
    )

    parser.add_argument(
        '--cve2',
        type=Path,
        help='Path to second CVE signature file (JSON or Markdown)'
    )

    parser.add_argument(
        '--signatures-dir',
        type=Path,
        help='Directory containing signature files for batch analysis (searches recursively for .json and .md files)'
    )

    parser.add_argument(
        '--compare-all',
        action='store_true',
        help='Compare all signatures in the signatures directory'
    )

    parser.add_argument(
        '--output',
        type=Path,
        help='Output file path for the analysis report (default: print to stdout)'
    )

    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('data/output/impact_analysis'),
        help='Output directory for batch analysis results (default: data/output/impact_analysis)'
    )

    parser.add_argument(
        '--example',
        action='store_true',
        help='Run example analysis with sample code'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '--all-pairs',
        action='store_true',
        help='Compare all pairs of CVEs within each plugin (default: only adjacent chronological pairs)'
    )

    parser.add_argument(
        '--date-field',
        type=str,
        default=None,
        help='Field name containing release date/timestamp for chronological sorting (default: use CVE ID)'
    )

    parser.add_argument(
        '--prefer-format',
        type=str,
        choices=['json', 'markdown'],
        default='json',
        help='Preferred format when both JSON and Markdown exist for a signature (default: json)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.example:
        return run_example_analysis(verbose=args.verbose)

    if args.compare_all:
        if not args.signatures_dir:
            print("Error: --signatures-dir required for batch analysis")
            return 1
        return run_batch_analysis(
            args.signatures_dir,
            args.output_dir,
            verbose=args.verbose,
            adjacent_only=not args.all_pairs,  # --all-pairs inverts the default
            date_field=args.date_field,
            prefer_format=args.prefer_format
        )

    if args.cve1 and args.cve2:
        return run_pairwise_analysis(args.cve1, args.cve2, args.output, verbose=args.verbose)

    # No valid operation specified
    parser.print_help()
    print("\nError: Please specify either:")
    print("  1. --cve1 and --cve2 for pairwise comparison")
    print("  2. --signatures-dir and --compare-all for batch analysis")
    print("  3. --example to run an example analysis")
    return 1


if __name__ == '__main__':
    sys.exit(main())
