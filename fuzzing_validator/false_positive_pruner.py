"""Filters false positives from zero-day candidates."""

import json
import os
from typing import List, Tuple

from vulnerability_miner.models import ZeroDayFinding
from .models import FuzzingCampaign, ValidatedVulnerability


class FalsePositivePruner:
    """Filters out false positive vulnerability candidates."""

    def __init__(self, output_dir: str = "fuzz_results"):
        """
        Initialize false positive pruner.

        Args:
            output_dir: Output directory for results
        """
        self.output_dir = output_dir
        self.validated_dir = os.path.join(output_dir, "validated")
        self.false_positives_dir = os.path.join(output_dir, "false_positives")

        os.makedirs(self.validated_dir, exist_ok=True)
        os.makedirs(self.false_positives_dir, exist_ok=True)

    def filter_results(
        self,
        zero_day_candidates: List[ZeroDayFinding],
        fuzzing_campaigns: List[FuzzingCampaign]
    ) -> Tuple[List[ValidatedVulnerability], List[ZeroDayFinding]]:
        """
        Filter results based on fuzzing outcomes.

        Args:
            zero_day_candidates: Original zero-day candidates
            fuzzing_campaigns: Completed fuzzing campaigns

        Returns:
            Tuple[List[ValidatedVulnerability], List[ZeroDayFinding]]:
                (validated vulnerabilities, false positives)
        """
        # Build campaign lookup
        campaign_map = {c.campaign_id: c for c in fuzzing_campaigns}

        validated = []
        false_positives = []

        for candidate in zero_day_candidates:
            # Find corresponding campaign
            campaign_id = self._get_campaign_id(candidate)
            campaign = campaign_map.get(campaign_id)

            if not campaign:
                # No campaign run for this candidate
                false_positives.append(candidate)
                continue

            if campaign.crashes_found > 0:
                # Crashes found - validated vulnerability
                validated_vuln = self._create_validated_vulnerability(
                    candidate,
                    campaign
                )
                validated.append(validated_vuln)

                # Save validated vulnerability
                self._save_validated(validated_vuln)

            else:
                # No crashes - false positive
                false_positives.append(candidate)

                # Save false positive
                self._save_false_positive(candidate, campaign)

        print(f"\nValidation Results:")
        print(f"  Validated: {len(validated)}")
        print(f"  False Positives: {len(false_positives)}")
        print(f"  False Positive Rate: {len(false_positives) / len(zero_day_candidates) * 100:.1f}%")

        return validated, false_positives

    def _get_campaign_id(self, candidate: ZeroDayFinding) -> str:
        """Generate campaign ID for candidate."""
        return f"fuzz-{candidate.signature_id}-{candidate.plugin_slug}"

    def _create_validated_vulnerability(
        self,
        candidate: ZeroDayFinding,
        campaign: FuzzingCampaign
    ) -> ValidatedVulnerability:
        """Create validated vulnerability from candidate and campaign."""
        from datetime import datetime

        # Load crashes for this campaign
        crashes = self._load_crashes(campaign)

        # Get best crash for PoC
        best_crash = self._get_best_crash(crashes)

        validated = ValidatedVulnerability(
            plugin_slug=candidate.plugin_slug,
            current_version=candidate.current_version,
            signature_id=candidate.signature_id,
            original_cve=candidate.original_cve,
            vulnerability_type=candidate.vulnerability_type,
            validated=True,
            validation_method="fuzzing",
            validation_date=datetime.now(),
            crash_reports=crashes,
            unique_crashes=campaign.unique_crashes,
            matched_files=candidate.matched_files,
            matched_code_snippets=candidate.matched_code_snippets,
            false_positive=False,
        )

        if best_crash:
            validated.poc_payload = best_crash.crashing_input
            validated.poc_description = best_crash.exploitation_notes
            validated.cvss_score = best_crash.cvss_score
            validated.cvss_vector = best_crash.cvss_vector
            validated.exploitation_complexity = best_crash.attack_complexity

        return validated

    def _load_crashes(self, campaign: FuzzingCampaign) -> List:
        """Load crashes for campaign."""
        from .models import CrashReport

        crashes = []
        crashes_dir = os.path.join(self.output_dir, "crashes")

        if not os.path.exists(crashes_dir):
            return crashes

        for crash_id in os.listdir(crashes_dir):
            crash_file = os.path.join(crashes_dir, crash_id, "crash.json")
            if os.path.exists(crash_file):
                with open(crash_file, 'r') as f:
                    crash_data = json.load(f)
                    if crash_data.get('campaign_id') == campaign.campaign_id:
                        # Reconstruct crash (simplified)
                        crashes.append(crash_data)

        return crashes[:10]  # Limit to 10 crashes

    def _get_best_crash(self, crashes: List) -> any:
        """Get crash with highest exploitability score."""
        if not crashes:
            return None

        # Find crash with highest exploitability
        best = max(crashes, key=lambda c: c.get('exploitability_score', 0))
        return type('obj', (object,), best)()

    def _save_validated(self, validated: ValidatedVulnerability):
        """Save validated vulnerability."""
        filename = f"{validated.plugin_slug}_{validated.signature_id}.json"
        filepath = os.path.join(self.validated_dir, filename)

        with open(filepath, 'w') as f:
            json.dump(validated.to_dict(), f, indent=2)

    def _save_false_positive(self, candidate: ZeroDayFinding, campaign: FuzzingCampaign):
        """Save false positive."""
        filename = f"{candidate.plugin_slug}_{candidate.signature_id}.json"
        filepath = os.path.join(self.false_positives_dir, filename)

        data = {
            **candidate.to_dict(),
            'fuzzing_campaign_id': campaign.campaign_id,
            'fuzzing_executions': campaign.total_executions,
            'fuzzing_duration_seconds': campaign.elapsed_seconds,
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
