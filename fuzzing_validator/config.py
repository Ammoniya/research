"""Configuration for fuzzing validation system."""

import os
from dataclasses import dataclass, field
from typing import List, Dict
from pathlib import Path

# Import centralized data paths
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from data_paths import (
    OUTPUT_FUZZ_DIR,
    FUZZ_CRASHES_DIR,
    FUZZ_VALIDATED_DIR,
    FUZZ_FALSE_POSITIVES_DIR,
    FUZZ_EXPLOITS_DIR,
    MINING_ZERO_DAYS_DIR,
    ensure_data_directories
)


@dataclass
class FuzzingConfig:
    """Configuration for fuzzing validation."""

    # Directories
    wordpress_path: str = "/var/www/html"
    plugins_path: str = "/var/www/html/wp-content/plugins"
    fuzz_targets_dir: str = "fuzz_targets"
    fuzz_results_dir: str = str(OUTPUT_FUZZ_DIR)
    zero_days_input_dir: str = str(MINING_ZERO_DAYS_DIR)

    # Output directories
    campaigns_dir: str = str(OUTPUT_FUZZ_DIR / "campaigns")
    crashes_dir: str = str(FUZZ_CRASHES_DIR)
    validated_dir: str = str(FUZZ_VALIDATED_DIR)
    false_positives_dir: str = str(FUZZ_FALSE_POSITIVES_DIR)
    exploits_dir: str = str(FUZZ_EXPLOITS_DIR)

    # Fuzzing parameters
    fuzzer: str = "custom-php-fuzzer"  # custom-php-fuzzer, afl++, libfuzzer
    timeout_per_target: int = 3600  # 1 hour per target
    max_parallel_campaigns: int = 4
    max_memory_mb: int = 4096

    # Coverage goals
    min_coverage_threshold: float = 0.7  # Stop if coverage > 70%
    min_executions: int = 10000  # Minimum executions
    early_stop_no_crashes: int = 10000  # Stop early if no crashes after N execs

    # Crash detection
    dedup_crashes: bool = True
    save_all_crashes: bool = False  # Only save unique crashes

    # Mutation strategies
    mutation_strategies: List[str] = field(default_factory=lambda: [
        'bitflip', 'byteflip', 'arithmetic',
        'interesting_values', 'dictionary',
        'havoc', 'splice'
    ])

    # Dictionaries
    dictionaries_dir: str = "dictionaries"

    # Seed corpus
    seed_corpus: Dict[str, List[str]] = field(default_factory=lambda: {
        'sqli': [
            "1' OR '1'='1",
            "1; DROP TABLE users--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "1' AND 1=1--",
            "admin'--",
            "' OR '1'='1' /*",
        ],
        'xss': [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            "'\"><script>alert(1)</script>",
        ],
        'path_traversal': [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "....//....//etc/passwd",
            "../wp-config.php",
            "../../../../../../etc/passwd",
        ],
        'csrf': [
            "action=delete_user&user_id=1",
            "action=change_password&new_pass=hacked",
            "action=update_settings&admin_email=attacker@evil.com",
        ],
        'auth_bypass': [
            "user_id=1",
            "role=administrator",
            "wp_user_id=1",
        ],
        'file_upload': [
            "shell.php",
            "backdoor.php5",
            "evil.phtml",
        ],
    })

    # Validation thresholds
    min_confidence_for_fuzzing: float = 0.7
    min_exploitability_score: float = 5.0  # Minimum score to consider exploitable

    # Resource limits
    php_memory_limit: str = "256M"
    php_max_execution_time: int = 30

    def ensure_directories(self):
        """Create necessary directories."""
        # Use centralized directory creation
        ensure_data_directories()

        # Create additional directories specific to fuzzing
        os.makedirs(self.fuzz_targets_dir, exist_ok=True)
        os.makedirs(self.campaigns_dir, exist_ok=True)
        os.makedirs(self.dictionaries_dir, exist_ok=True)

        # Create subdirectories for fuzz targets by vulnerability type
        vuln_types = ['sqli', 'xss', 'csrf', 'path_traversal', 'auth_bypass', 'file_upload']
        for vuln_type in vuln_types:
            os.makedirs(os.path.join(self.fuzz_targets_dir, vuln_type), exist_ok=True)

    def get_seeds_for_vuln_type(self, vuln_type: str) -> List[str]:
        """Get seed corpus for vulnerability type."""
        # Normalize vulnerability type
        vuln_type_lower = vuln_type.lower().replace(' ', '_').replace('-', '_')

        # Map common variations
        type_mapping = {
            'sql_injection': 'sqli',
            'cross_site_scripting': 'xss',
            'xss_stored': 'xss',
            'xss_reflected': 'xss',
            'path_traversal': 'path_traversal',
            'directory_traversal': 'path_traversal',
            'lfi': 'path_traversal',
            'rfi': 'path_traversal',
            'csrf': 'csrf',
            'authentication_bypass': 'auth_bypass',
            'authorization_bypass': 'auth_bypass',
            'file_upload': 'file_upload',
            'arbitrary_file_upload': 'file_upload',
        }

        normalized_type = type_mapping.get(vuln_type_lower, vuln_type_lower)
        return self.seed_corpus.get(normalized_type, ["test"])

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'wordpress_path': self.wordpress_path,
            'plugins_path': self.plugins_path,
            'fuzz_targets_dir': self.fuzz_targets_dir,
            'fuzz_results_dir': self.fuzz_results_dir,
            'fuzzer': self.fuzzer,
            'timeout_per_target': self.timeout_per_target,
            'max_parallel_campaigns': self.max_parallel_campaigns,
            'max_memory_mb': self.max_memory_mb,
            'min_coverage_threshold': self.min_coverage_threshold,
            'min_executions': self.min_executions,
            'early_stop_no_crashes': self.early_stop_no_crashes,
            'dedup_crashes': self.dedup_crashes,
            'mutation_strategies': self.mutation_strategies,
            'min_confidence_for_fuzzing': self.min_confidence_for_fuzzing,
            'min_exploitability_score': self.min_exploitability_score,
        }
