"""
Centralized data path configuration for the research project.

This module provides consistent access to all input and output data paths,
keeping the codebase clean and separating code from execution results.
"""

from pathlib import Path
from typing import Optional

# Root directories
PROJECT_ROOT = Path(__file__).parent.resolve()
DATA_ROOT = PROJECT_ROOT / "data"
INPUT_DIR = DATA_ROOT / "input"
OUTPUT_DIR = DATA_ROOT / "output"

# Input data paths
INPUT_PLUGIN_LIST = INPUT_DIR / "top_10k_plugin_slugs.txt"
INPUT_PLUGIN_VULNERABILITIES = INPUT_DIR / "plugin_vulnerabilities.json"
INPUT_WORDFENCE_DB = INPUT_DIR / "wordfence_db.json"

# Output directories (actively used)
OUTPUT_SIGNATURES_DIR = OUTPUT_DIR / "signatures"
OUTPUT_AST_SIGNATURES_DIR = OUTPUT_DIR / "ast_signatures"
OUTPUT_VULNERABILITY_MATCHES_DIR = OUTPUT_DIR / "vulnerability_matches"

# Output directories (not currently used - kept for future features)
# OUTPUT_MINING_DIR = OUTPUT_DIR / "mining_results"
# OUTPUT_FUZZ_DIR = OUTPUT_DIR / "fuzz_results"
# OUTPUT_REPORTS_DIR = OUTPUT_DIR / "reports"

# Mining results subdirectories (not currently used)
# MINING_TIMELINES_DIR = OUTPUT_MINING_DIR / "timelines"
# MINING_ZERO_DAYS_DIR = OUTPUT_MINING_DIR / "zero_days"
# MINING_METRICS_DIR = OUTPUT_MINING_DIR / "metrics"
# MINING_CACHE_DIR = OUTPUT_MINING_DIR / "cache"
# MINING_PROGRESS_FILE = OUTPUT_MINING_DIR / "mining_progress.json"

# Fuzzing results subdirectories (not currently used)
# FUZZ_CRASHES_DIR = OUTPUT_FUZZ_DIR / "crashes"
# FUZZ_VALIDATED_DIR = OUTPUT_FUZZ_DIR / "validated"
# FUZZ_FALSE_POSITIVES_DIR = OUTPUT_FUZZ_DIR / "false_positives"
# FUZZ_EXPLOITS_DIR = OUTPUT_FUZZ_DIR / "exploits"
# FUZZ_VALIDATION_REPORT = OUTPUT_FUZZ_DIR / "validation_report.json"


def ensure_data_directories():
    """
    Create all necessary data directories if they don't exist.
    Call this at the start of any script that performs I/O operations.

    Only creates directories that are actively used in the current workflow.
    """
    directories = [
        INPUT_DIR,
        OUTPUT_DIR,
        OUTPUT_SIGNATURES_DIR,
        OUTPUT_AST_SIGNATURES_DIR,
        OUTPUT_VULNERABILITY_MATCHES_DIR,
    ]

    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)


def get_signature_file_path(plugin_slug: str, identifier: str) -> Path:
    """
    Get the path for a signature file.

    Args:
        plugin_slug: The plugin slug
        identifier: CVE ID or vulnerability hash

    Returns:
        Path object for the signature file
    """
    plugin_dir = OUTPUT_SIGNATURES_DIR / plugin_slug
    plugin_dir.mkdir(parents=True, exist_ok=True)

    if identifier.startswith("CVE-"):
        return plugin_dir / f"{identifier}.json"
    else:
        return plugin_dir / f"vuln_{identifier}.json"


def get_ast_signature_file_path(plugin_slug: str, identifier: str) -> Path:
    """
    Get the path for an AST signature file.

    Args:
        plugin_slug: The plugin slug
        identifier: CVE ID or vulnerability hash

    Returns:
        Path object for the AST signature file
    """
    plugin_dir = OUTPUT_AST_SIGNATURES_DIR / plugin_slug
    plugin_dir.mkdir(parents=True, exist_ok=True)

    if identifier.startswith("CVE-"):
        return plugin_dir / f"{identifier}_ast.json"
    else:
        return plugin_dir / f"vuln_{identifier}_ast.json"


# Commented out unused functions for future features
#
# def get_zero_day_file_path(plugin_slug: str, signature_id: str) -> Path:
#     """Get the path for a zero-day finding file."""
#     return MINING_ZERO_DAYS_DIR / f"{plugin_slug}_{signature_id}.json"
#
# def get_timeline_file_path(plugin_slug: str, signature_id: str) -> Path:
#     """Get the path for a timeline file."""
#     return MINING_TIMELINES_DIR / f"{plugin_slug}_{signature_id}.json"
#
# def get_clone_timeline_path(signature_id: str) -> Path:
#     """Get the path for a vulnerability clone timeline."""
#     return MINING_TIMELINES_DIR / f"clone_{signature_id}.json"
#
# def get_metrics_file_path(signature_id: Optional[str] = None) -> Path:
#     """Get the path for metrics files."""
#     if signature_id:
#         return MINING_METRICS_DIR / f"metrics_{signature_id}.json"
#     else:
#         return MINING_METRICS_DIR / "ecosystem_metrics.json"
#
# def get_cache_file_path(plugin_slug: str, cache_type: str = "revisions") -> Path:
#     """Get the path for cache files."""
#     if cache_type == "release_revisions":
#         return MINING_CACHE_DIR / f"{plugin_slug}_release_revisions.json"
#     else:
#         return MINING_CACHE_DIR / f"{plugin_slug}_revisions.json"
#
# def get_crash_dir_path(campaign_id: str) -> Path:
#     """Get the directory path for crash data."""
#     crash_dir = FUZZ_CRASHES_DIR / campaign_id
#     crash_dir.mkdir(parents=True, exist_ok=True)
#     return crash_dir
#
# def get_validated_file_path(plugin_slug: str, signature_id: str) -> Path:
#     """Get the path for validated vulnerability file."""
#     return FUZZ_VALIDATED_DIR / f"{plugin_slug}_{signature_id}.json"
#
# def get_false_positive_file_path(plugin_slug: str, signature_id: str) -> Path:
#     """Get the path for false positive file."""
#     return FUZZ_FALSE_POSITIVES_DIR / f"{plugin_slug}_{signature_id}.json"
#
# def get_exploit_file_path(plugin_slug: str, signature_id: str) -> Path:
#     """Get the path for exploit/PoC file."""
#     return FUZZ_EXPLOITS_DIR / f"{plugin_slug}_{signature_id}_poc.py"
#
# def get_report_file_path(plugin_slug: str, cve: str) -> Path:
#     """Get the path for vulnerability report file."""
#     return OUTPUT_REPORTS_DIR / f"{plugin_slug}_{cve}_report.md"
#
# def get_research_report_path() -> Path:
#     """Get the path for the research report."""
#     return MINING_METRICS_DIR / "research_report.txt"


# Ensure data directories exist when module is imported
ensure_data_directories()
