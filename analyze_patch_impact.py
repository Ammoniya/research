#!/usr/bin/env python3
"""
Analyze the impact of one CVE patch on another.

This script compares two CVE patches using call graph analysis, data flow analysis,
and control flow graph comparison to determine how they relate to each other.

Usage:
    python analyze_patch_impact.py --cve1 <path_to_cve1_signature.json> --cve2 <path_to_cve2_signature.json>
    python analyze_patch_impact.py --signatures-dir <dir> --compare-all

Example:
    python analyze_patch_impact.py --cve1 data/output/signatures/CVE-2023-1234.json \\
                                   --cve2 data/output/signatures/CVE-2023-5678.json \\
                                   --output results/impact_analysis.md
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

from patch_impact_analyzer import PatchImpactAnalyzer


def load_cve_signature(file_path: Path) -> Optional[Dict]:
    """
    Load CVE signature data from a JSON file.

    Args:
        file_path: Path to the JSON file

    Returns:
        Dict with CVE signature data or None if error
    """
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        return None
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in file: {file_path}")
        return None


def load_signatures_from_directory(directory: Path) -> List[Dict]:
    """
    Load all CVE signatures from a directory.

    Args:
        directory: Directory containing signature JSON files

    Returns:
        List of signature dicts
    """
    signatures = []

    if not directory.exists():
        print(f"Error: Directory not found: {directory}")
        return signatures

    json_files = list(directory.glob("*.json"))
    print(f"Found {len(json_files)} signature files in {directory}")

    for json_file in json_files:
        sig = load_cve_signature(json_file)
        if sig:
            signatures.append(sig)

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
                      verbose: bool = False) -> int:
    """
    Run impact analysis on all pairs of signatures in a directory.

    Args:
        signatures_dir: Directory containing signature files
        output_dir: Directory to save results
        verbose: Whether to print verbose output

    Returns:
        Exit code (0 for success)
    """
    print(f"\n{'='*60}")
    print(f"Batch Patch Impact Analysis")
    print(f"{'='*60}\n")

    # Load all signatures
    signatures = load_signatures_from_directory(signatures_dir)

    if len(signatures) < 2:
        print(f"Error: Need at least 2 signatures for comparison. Found {len(signatures)}")
        return 1

    print(f"Loaded {len(signatures)} signatures")
    print(f"Will perform {len(signatures) * (len(signatures) - 1) // 2} comparisons\n")

    # Initialize analyzer
    analyzer = PatchImpactAnalyzer()

    # Run comparisons
    results = analyzer.compare_multiple_patches(
        signatures,
        output_dir=output_dir,
        verbose=verbose
    )

    # Print summary
    print(f"\n{'='*60}")
    print(f"Batch Analysis Summary")
    print(f"{'='*60}\n")
    print(f"Total CVEs analyzed: {results['total_cves']}")
    print(f"Total comparisons: {results['summary']['total_comparisons']}")
    print(f"Average impact score: {results['summary']['average_impact_score']:.2f}")
    print(f"Max impact score: {results['summary']['max_impact_score']:.2f}")
    print(f"High impact pairs: {results['summary']['high_impact_count']}")

    if results['high_impact_pairs']:
        print(f"\nHigh Impact Pairs (score >= 60):")
        for pair in results['high_impact_pairs'][:10]:
            print(f"  {pair['pair']}: {pair['score']:.2f} ({pair['level']})")

    print(f"\nResults saved to: {output_dir}")

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
        help='Path to first CVE signature JSON file'
    )

    parser.add_argument(
        '--cve2',
        type=Path,
        help='Path to second CVE signature JSON file'
    )

    parser.add_argument(
        '--signatures-dir',
        type=Path,
        help='Directory containing signature files for batch analysis'
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

    args = parser.parse_args()

    # Validate arguments
    if args.example:
        return run_example_analysis(verbose=args.verbose)

    if args.compare_all:
        if not args.signatures_dir:
            print("Error: --signatures-dir required for batch analysis")
            return 1
        return run_batch_analysis(args.signatures_dir, args.output_dir, verbose=args.verbose)

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
