"""Orchestrates fuzzing campaigns for vulnerability validation."""

import os
import subprocess
import tempfile
import time
from datetime import datetime
from typing import List, Optional
from pathlib import Path

from .models import FuzzingCampaign, CrashReport, CampaignStatus
from .config import FuzzingConfig
from .crash_analyzer import CrashAnalyzer


class FuzzingOrchestrator:
    """Manages fuzzing campaigns."""

    def __init__(self, config: FuzzingConfig):
        """
        Initialize fuzzing orchestrator.

        Args:
            config: Fuzzing configuration
        """
        self.config = config
        self.crash_analyzer = CrashAnalyzer()

    def run_campaign(self, campaign: FuzzingCampaign) -> FuzzingCampaign:
        """
        Run a single fuzzing campaign.

        Args:
            campaign: Fuzzing campaign to run

        Returns:
            FuzzingCampaign: Updated campaign with results
        """
        print(f"Starting fuzzing campaign: {campaign.campaign_id}")

        campaign.status = CampaignStatus.RUNNING
        campaign.start_time = datetime.now()

        try:
            # Get seeds for vulnerability type
            seeds = self.config.get_seeds_for_vuln_type(campaign.vulnerability_type)

            # Create output directory
            campaign.output_dir = os.path.join(
                self.config.campaigns_dir,
                campaign.campaign_id
            )
            os.makedirs(campaign.output_dir, exist_ok=True)

            # Run fuzzing
            if self.config.fuzzer == "custom-php-fuzzer":
                crashes = self._run_php_fuzzer(campaign, seeds)
            elif self.config.fuzzer == "afl++":
                crashes = self._run_afl_fuzzer(campaign, seeds)
            else:
                crashes = self._run_php_fuzzer(campaign, seeds)

            # Update campaign stats
            campaign.crashes_found = len(crashes)
            campaign.unique_crashes = len(self.crash_analyzer.deduplicate_crashes(crashes))
            campaign.status = CampaignStatus.COMPLETED

            # Save crashes
            for crash in crashes:
                self._save_crash(crash)

        except Exception as e:
            print(f"Error in campaign {campaign.campaign_id}: {e}")
            campaign.status = CampaignStatus.ERROR

        campaign.end_time = datetime.now()
        campaign.calculate_elapsed()

        print(f"Campaign completed: {campaign.campaign_id}")
        print(f"  Executions: {campaign.total_executions}")
        print(f"  Crashes: {campaign.crashes_found}")
        print(f"  Unique: {campaign.unique_crashes}")

        return campaign

    def _run_php_fuzzer(
        self,
        campaign: FuzzingCampaign,
        seeds: List[str]
    ) -> List[CrashReport]:
        """
        Run custom PHP fuzzer.

        Args:
            campaign: Fuzzing campaign
            seeds: Initial seed inputs

        Returns:
            List[CrashReport]: Crashes found
        """
        crashes = []
        executions = 0
        crashes_since_last = 0

        max_iterations = self.config.min_executions
        timeout = campaign.fuzz_duration_seconds

        start_time = time.time()

        # Fuzz with seeds
        for seed in seeds:
            if time.time() - start_time > timeout:
                break

            # Test seed
            crash = self._execute_harness(campaign, seed)
            if crash:
                crashes.append(crash)
                crashes_since_last = 0
            else:
                crashes_since_last += 1

            executions += 1

            # Early stop if no crashes found
            if crashes_since_last > self.config.early_stop_no_crashes:
                break

        # Mutation-based fuzzing
        mutation_count = 0
        while time.time() - start_time < timeout and mutation_count < max_iterations:
            # Pick random seed
            import random
            seed = random.choice(seeds)

            # Mutate
            mutated = self._mutate_input(seed)

            # Test
            crash = self._execute_harness(campaign, mutated)
            if crash:
                crashes.append(crash)
                crashes_since_last = 0
                # Add to seed pool if interesting
                seeds.append(mutated)
            else:
                crashes_since_last += 1

            executions += 1
            mutation_count += 1

            # Early stop
            if crashes_since_last > self.config.early_stop_no_crashes:
                break

        campaign.total_executions = executions

        return crashes

    def _execute_harness(
        self,
        campaign: FuzzingCampaign,
        input_data: str
    ) -> Optional[CrashReport]:
        """
        Execute fuzzing harness with input.

        Args:
            campaign: Fuzzing campaign
            input_data: Input data to test

        Returns:
            Optional[CrashReport]: Crash report if crash detected
        """
        if not campaign.harness_path or not os.path.exists(campaign.harness_path):
            return None

        # Write input to temp file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(input_data)
            input_file = f.name

        try:
            # Execute harness
            result = subprocess.run(
                ['php', campaign.harness_path, input_file],
                capture_output=True,
                text=True,
                timeout=self.config.php_max_execution_time
            )

            # Check for crash (non-zero exit code)
            if result.returncode != 0:
                # Analyze crash
                output = result.stdout + result.stderr
                crash = self.crash_analyzer.analyze_crash_output(
                    output=output,
                    crashing_input=input_data,
                    campaign=campaign
                )
                return crash

        except subprocess.TimeoutExpired:
            # Timeout might indicate infinite loop (DoS)
            pass
        except Exception as e:
            print(f"Error executing harness: {e}")
        finally:
            # Cleanup
            try:
                os.unlink(input_file)
            except:
                pass

        return None

    def _mutate_input(self, input_data: str) -> str:
        """
        Mutate input using various strategies.

        Args:
            input_data: Input to mutate

        Returns:
            str: Mutated input
        """
        import random

        strategies = self.config.mutation_strategies

        strategy = random.choice(strategies)

        if strategy == 'bitflip' and input_data:
            # Flip random bit
            data = bytearray(input_data.encode())
            if data:
                idx = random.randint(0, len(data) - 1)
                data[idx] ^= (1 << random.randint(0, 7))
                return data.decode('utf-8', errors='ignore')

        elif strategy == 'byteflip' and input_data:
            # Flip random byte
            data = bytearray(input_data.encode())
            if data:
                idx = random.randint(0, len(data) - 1)
                data[idx] = random.randint(0, 255)
                return data.decode('utf-8', errors='ignore')

        elif strategy == 'arithmetic':
            # Add/subtract random value
            if input_data.isdigit():
                val = int(input_data)
                val += random.randint(-100, 100)
                return str(val)

        elif strategy == 'interesting_values':
            # Insert interesting values
            interesting = [
                '0', '-1', '65535', '2147483647', '-2147483648',
                'null', 'undefined', 'NaN', 'true', 'false',
            ]
            return random.choice(interesting)

        elif strategy == 'dictionary':
            # Use common attack patterns
            patterns = [
                "' OR '1'='1", '../../../', '<script>', '${', '{{',
                '%00', '\x00', '..;/', '....////',
            ]
            return input_data + random.choice(patterns)

        elif strategy == 'havoc':
            # Random havoc mutations
            data = input_data
            for _ in range(random.randint(1, 5)):
                op = random.choice(['insert', 'delete', 'replace'])
                if op == 'insert' and len(data) < 1000:
                    pos = random.randint(0, len(data))
                    char = chr(random.randint(32, 126))
                    data = data[:pos] + char + data[pos:]
                elif op == 'delete' and data:
                    pos = random.randint(0, len(data) - 1)
                    data = data[:pos] + data[pos+1:]
                elif op == 'replace' and data:
                    pos = random.randint(0, len(data) - 1)
                    char = chr(random.randint(32, 126))
                    data = data[:pos] + char + data[pos+1:]
            return data

        elif strategy == 'splice' and len(input_data) > 1:
            # Splice parts of input
            mid = len(input_data) // 2
            return input_data[mid:] + input_data[:mid]

        # Default: return with minor modification
        return input_data + "'"

    def _run_afl_fuzzer(
        self,
        campaign: FuzzingCampaign,
        seeds: List[str]
    ) -> List[CrashReport]:
        """
        Run AFL++ fuzzer (placeholder for now).

        Args:
            campaign: Fuzzing campaign
            seeds: Initial seeds

        Returns:
            List[CrashReport]: Crashes found
        """
        # AFL++ integration would require:
        # 1. Compiled PHP with AFL instrumentation
        # 2. Seed corpus directory
        # 3. Running afl-fuzz
        # 4. Parsing crash outputs

        # For now, fall back to PHP fuzzer
        return self._run_php_fuzzer(campaign, seeds)

    def _save_crash(self, crash: CrashReport):
        """Save crash report to disk."""
        import json

        crash_dir = os.path.join(self.config.crashes_dir, crash.crash_id)
        os.makedirs(crash_dir, exist_ok=True)

        # Save crash metadata
        with open(os.path.join(crash_dir, 'crash.json'), 'w') as f:
            json.dump(crash.to_dict(), f, indent=2)

        # Save crashing input
        with open(os.path.join(crash_dir, 'input.txt'), 'w') as f:
            f.write(crash.crashing_input)

    def run_parallel_campaigns(
        self,
        campaigns: List[FuzzingCampaign],
        max_parallel: Optional[int] = None
    ) -> List[FuzzingCampaign]:
        """
        Run multiple campaigns in parallel.

        Args:
            campaigns: List of campaigns to run
            max_parallel: Maximum parallel campaigns

        Returns:
            List[FuzzingCampaign]: Completed campaigns
        """
        max_parallel = max_parallel or self.config.max_parallel_campaigns

        # For simplicity, run sequentially for now
        # In production, use multiprocessing.Pool
        results = []
        for campaign in campaigns:
            result = self.run_campaign(campaign)
            results.append(result)

        return results
