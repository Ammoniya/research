#!/usr/bin/env python3
"""
Phase 3: Fuzzing-Based False Positive Pruning & Zero-Day Validation

This script takes Phase 2 zero-day candidates and validates them through
automated fuzzing, pruning false positives and generating proof-of-concept
exploits for validated vulnerabilities.

Usage:
    python validate_zero_days.py [options]

Examples:
    # Validate all candidates
    python validate_zero_days.py

    # Validate with custom timeout
    python validate_zero_days.py --timeout 7200

    # Validate specific plugin
    python validate_zero_days.py --plugin vulnerable-plugin

    # Limit scope
    python validate_zero_days.py --max-candidates 50

    # Use AFL++ fuzzer
    python validate_zero_days.py --fuzzer afl++

    # Parallel fuzzing
    python validate_zero_days.py --parallel 8
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Import centralized data paths
from data_paths import MINING_ZERO_DAYS_DIR, OUTPUT_FUZZ_DIR

from vulnerability_miner.models import ZeroDayFinding
from vulnerability_miner.zero_day_detector import ZeroDayDetector

from fuzzing_validator import (
    FuzzingConfig,
    HarnessGenerator,
    FuzzingOrchestrator,
    FalsePositivePruner,
    PoCGenerator,
    FuzzingCampaign,
    FuzzingStats,
)


class ZeroDayValidator:
    """Main orchestrator for Phase 3 validation."""

    def __init__(self, config: FuzzingConfig):
        """
        Initialize validator.

        Args:
            config: Fuzzing configuration
        """
        self.config = config
        self.harness_generator = HarnessGenerator(
            wordpress_path=config.wordpress_path,
            plugins_path=config.plugins_path
        )
        self.orchestrator = FuzzingOrchestrator(config)
        self.pruner = FalsePositivePruner(output_dir=config.fuzz_results_dir)
        self.poc_generator = PoCGenerator(output_dir=config.exploits_dir)

        self.stats = FuzzingStats()

    def load_zero_day_candidates(
        self,
        input_dir: Optional[str] = None,
        plugin_filter: Optional[str] = None,
        vuln_type_filter: Optional[str] = None,
        signature_filter: Optional[str] = None,
        max_candidates: Optional[int] = None,
    ) -> List[ZeroDayFinding]:
        """
        Load zero-day candidates from Phase 2.

        Args:
            input_dir: Input directory (Phase 2 zero_days output)
            plugin_filter: Filter by plugin slug
            vuln_type_filter: Filter by vulnerability type
            signature_filter: Filter by signature ID
            max_candidates: Maximum candidates to load

        Returns:
            List[ZeroDayFinding]: Zero-day candidates
        """
        input_dir = input_dir or self.config.zero_days_input_dir

        if not os.path.exists(input_dir):
            print(f"Error: Input directory not found: {input_dir}")
            print("Please run Phase 2 first: python mine_vulnerability_clones.py")
            return []

        # Use ZeroDayDetector to load findings
        detector = ZeroDayDetector(output_dir=input_dir)

        # Load all findings
        all_findings = []
        findings_file = os.path.join(input_dir, "zero_day_findings.json")

        if os.path.exists(findings_file):
            with open(findings_file, 'r') as f:
                data = json.load(f)
                for finding_data in data.get('findings', []):
                    # Reconstruct ZeroDayFinding
                    finding = self._dict_to_zero_day_finding(finding_data)
                    if finding:
                        all_findings.append(finding)

        # Apply filters
        filtered = all_findings

        if plugin_filter:
            filtered = [f for f in filtered if f.plugin_slug == plugin_filter]

        if vuln_type_filter:
            filtered = [f for f in filtered if vuln_type_filter.lower() in f.vulnerability_type.lower()]

        if signature_filter:
            filtered = [f for f in filtered if f.signature_id == signature_filter]

        # Apply max limit
        if max_candidates:
            filtered = filtered[:max_candidates]

        print(f"\nLoaded {len(filtered)} zero-day candidates")
        print(f"  Total available: {len(all_findings)}")
        if plugin_filter:
            print(f"  Plugin filter: {plugin_filter}")
        if vuln_type_filter:
            print(f"  Type filter: {vuln_type_filter}")

        return filtered

    def _dict_to_zero_day_finding(self, data: dict) -> Optional[ZeroDayFinding]:
        """Convert dict to ZeroDayFinding."""
        try:
            return ZeroDayFinding(
                plugin_slug=data['plugin_slug'],
                current_version=data['current_version'],
                signature_id=data['signature_id'],
                original_cve=data.get('original_cve'),
                vulnerability_type=data['vulnerability_type'],
                pattern=data['pattern'],
                confidence=data['confidence'],
                matched_files=data.get('matched_files', []),
                matched_code_snippets=data.get('matched_code_snippets', []),
                exploitability_score=data.get('exploitability_score', 0.0),
                is_exact_clone=data.get('is_exact_clone', False),
            )
        except Exception as e:
            print(f"Warning: Failed to parse finding: {e}")
            return None

    def generate_fuzzing_campaigns(
        self,
        candidates: List[ZeroDayFinding]
    ) -> List[FuzzingCampaign]:
        """
        Generate fuzzing campaigns for candidates.

        Args:
            candidates: Zero-day candidates

        Returns:
            List[FuzzingCampaign]: Fuzzing campaigns
        """
        print("\n=== Generating Fuzzing Campaigns ===\n")

        campaigns = []

        for candidate in candidates:
            # Filter by confidence
            if candidate.confidence < self.config.min_confidence_for_fuzzing:
                print(f"Skipping {candidate.plugin_slug} (confidence too low: {candidate.confidence})")
                continue

            # Generate harness
            print(f"Generating harness for {candidate.plugin_slug}...")

            harness_code = self.harness_generator.generate_harness(
                vulnerability_type=candidate.vulnerability_type,
                plugin_slug=candidate.plugin_slug,
                matched_files=candidate.matched_files,
                matched_code=candidate.matched_code_snippets,
                signature_id=candidate.signature_id,
            )

            # Save harness
            vuln_type_normalized = candidate.vulnerability_type.lower().replace(' ', '_')
            harness_path = os.path.join(
                self.config.fuzz_targets_dir,
                vuln_type_normalized,
                f"{candidate.plugin_slug}_harness.php"
            )

            self.harness_generator.save_harness(harness_code, harness_path)

            # Create campaign
            campaign = FuzzingCampaign(
                campaign_id=f"fuzz-{candidate.signature_id}-{candidate.plugin_slug}",
                plugin_slug=candidate.plugin_slug,
                signature_id=candidate.signature_id,
                vulnerability_type=candidate.vulnerability_type,
                fuzzer=self.config.fuzzer,
                target_file=candidate.matched_files[0] if candidate.matched_files else "index.php",
                fuzz_duration_seconds=self.config.timeout_per_target,
                initial_seeds=self.config.get_seeds_for_vuln_type(candidate.vulnerability_type),
                harness_path=harness_path,
            )

            campaigns.append(campaign)

        print(f"\nGenerated {len(campaigns)} fuzzing campaigns")

        return campaigns

    def run_validation(
        self,
        candidates: List[ZeroDayFinding],
        campaigns: List[FuzzingCampaign]
    ):
        """
        Run complete validation pipeline.

        Args:
            candidates: Zero-day candidates
            campaigns: Fuzzing campaigns
        """
        self.stats.total_candidates = len(candidates)
        self.stats.start_time = datetime.now()

        print("\n=== Running Fuzzing Campaigns ===\n")

        # Run campaigns
        completed_campaigns = self.orchestrator.run_parallel_campaigns(
            campaigns,
            max_parallel=self.config.max_parallel_campaigns
        )

        self.stats.campaigns_run = len(completed_campaigns)
        self.stats.campaigns_completed = sum(
            1 for c in completed_campaigns if c.status.value == 'completed'
        )
        self.stats.campaigns_with_crashes = sum(
            1 for c in completed_campaigns if c.crashes_found > 0
        )

        print("\n=== Filtering False Positives ===\n")

        # Filter results
        validated, false_positives = self.pruner.filter_results(
            zero_day_candidates=candidates,
            fuzzing_campaigns=completed_campaigns
        )

        self.stats.validated_vulnerabilities = len(validated)
        self.stats.false_positives = len(false_positives)

        print("\n=== Generating Proof-of-Concept Exploits ===\n")

        # Generate PoCs
        for vuln in validated:
            print(f"Generating PoC for {vuln.plugin_slug}...")
            try:
                poc_path = self.poc_generator.generate_poc(vuln)
                print(f"  Saved to: {poc_path}")
            except Exception as e:
                print(f"  Error: {e}")

        # Calculate final stats
        self._calculate_final_stats(validated, completed_campaigns)

        # Save validation report
        self._save_validation_report()

        # Print summary
        self._print_summary()

    def _calculate_final_stats(self, validated, campaigns):
        """Calculate final statistics."""
        self.stats.end_time = datetime.now()
        self.stats.calculate_metrics()

        # Aggregate campaign stats
        for campaign in campaigns:
            self.stats.total_executions += campaign.total_executions
            self.stats.total_crashes_found += campaign.crashes_found
            self.stats.unique_crashes_found += campaign.unique_crashes
            self.stats.total_fuzzing_time_seconds += campaign.elapsed_seconds

        # Severity breakdown
        for vuln in validated:
            cvss = vuln.cvss_score
            if cvss >= 9.0:
                self.stats.critical_count += 1
            elif cvss >= 7.0:
                self.stats.high_count += 1
            elif cvss >= 4.0:
                self.stats.medium_count += 1
            else:
                self.stats.low_count += 1

            # Type breakdown
            vuln_type = vuln.vulnerability_type
            self.stats.vulnerability_type_counts[vuln_type] = \
                self.stats.vulnerability_type_counts.get(vuln_type, 0) + 1

    def _save_validation_report(self):
        """Save validation report."""
        report_path = os.path.join(self.config.fuzz_results_dir, "validation_report.json")

        with open(report_path, 'w') as f:
            json.dump(self.stats.to_dict(), f, indent=2)

        print(f"\nValidation report saved to: {report_path}")

    def _print_summary(self):
        """Print validation summary."""
        print("\n" + "="*70)
        print("PHASE 3 FUZZING VALIDATION SUMMARY")
        print("="*70)
        print(f"\nCandidates Tested: {self.stats.total_candidates}")
        print(f"Campaigns Run: {self.stats.campaigns_run}")
        print(f"Campaigns Completed: {self.stats.campaigns_completed}")
        print(f"\nValidation Results:")
        print(f"  ✓ Validated Vulnerabilities: {self.stats.validated_vulnerabilities}")
        print(f"  ✗ False Positives: {self.stats.false_positives}")
        print(f"  False Positive Rate: {self.stats.false_positive_rate:.1f}%")
        print(f"  Validation Accuracy: {self.stats.validation_accuracy:.1f}%")
        print(f"\nCrashes Found:")
        print(f"  Total Crashes: {self.stats.total_crashes_found}")
        print(f"  Unique Crashes: {self.stats.unique_crashes_found}")
        print(f"\nSeverity Breakdown:")
        print(f"  Critical: {self.stats.critical_count}")
        print(f"  High: {self.stats.high_count}")
        print(f"  Medium: {self.stats.medium_count}")
        print(f"  Low: {self.stats.low_count}")
        print(f"\nVulnerability Types:")
        for vuln_type, count in self.stats.vulnerability_type_counts.items():
            print(f"  {vuln_type}: {count}")
        print(f"\nPerformance:")
        print(f"  Total Executions: {self.stats.total_executions:,}")
        print(f"  Total Fuzzing Time: {self.stats.total_fuzzing_time_seconds/3600:.1f} hours")
        print("="*70)
        print("\nResults saved to:")
        print(f"  Validated: {self.config.validated_dir}")
        print(f"  False Positives: {self.config.false_positives_dir}")
        print(f"  PoC Exploits: {self.config.exploits_dir}")
        print("="*70)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Phase 3: Fuzzing-Based Zero-Day Validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument(
        '--input-dir',
        default=str(MINING_ZERO_DAYS_DIR),
        help='Input directory with Phase 2 zero-day findings'
    )

    parser.add_argument(
        '--output-dir',
        default=str(OUTPUT_FUZZ_DIR),
        help='Output directory for fuzzing results'
    )

    parser.add_argument(
        '--fuzzer',
        choices=['custom-php-fuzzer', 'afl++'],
        default='custom-php-fuzzer',
        help='Fuzzer to use'
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=3600,
        help='Timeout per target in seconds (default: 3600 = 1 hour)'
    )

    parser.add_argument(
        '--parallel',
        type=int,
        default=4,
        help='Number of parallel fuzzing campaigns'
    )

    parser.add_argument(
        '--max-candidates',
        type=int,
        help='Maximum candidates to validate'
    )

    parser.add_argument(
        '--plugin',
        help='Filter by specific plugin slug'
    )

    parser.add_argument(
        '--vuln-type',
        help='Filter by vulnerability type (e.g., CSRF, SQLi)'
    )

    parser.add_argument(
        '--signature',
        help='Filter by specific signature/CVE ID'
    )

    parser.add_argument(
        '--wordpress-path',
        default='/var/www/html',
        help='Path to WordPress installation'
    )

    args = parser.parse_args()

    # Create configuration
    config = FuzzingConfig(
        wordpress_path=args.wordpress_path,
        fuzz_results_dir=args.output_dir,
        zero_days_input_dir=args.input_dir,
        fuzzer=args.fuzzer,
        timeout_per_target=args.timeout,
        max_parallel_campaigns=args.parallel,
    )

    # Ensure directories exist
    config.ensure_directories()

    # Create validator
    validator = ZeroDayValidator(config)

    # Load candidates
    candidates = validator.load_zero_day_candidates(
        plugin_filter=args.plugin,
        vuln_type_filter=args.vuln_type,
        signature_filter=args.signature,
        max_candidates=args.max_candidates,
    )

    if not candidates:
        print("\nNo candidates found to validate.")
        print("Please run Phase 2 first: python mine_vulnerability_clones.py")
        return 1

    # Generate campaigns
    campaigns = validator.generate_fuzzing_campaigns(candidates)

    if not campaigns:
        print("\nNo campaigns generated (candidates may have low confidence)")
        return 1

    # Run validation
    validator.run_validation(candidates, campaigns)

    print("\n✓ Phase 3 validation complete!")

    return 0


if __name__ == "__main__":
    sys.exit(main())
