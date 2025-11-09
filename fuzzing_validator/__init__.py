"""
Fuzzing-based vulnerability validation system.

Phase 3: Fuzzing-Based False Positive Pruning & Zero-Day Validation
"""

from .models import (
    FuzzingCampaign,
    CrashReport,
    ValidatedVulnerability,
    FuzzingStats,
    CrashType,
    CampaignStatus,
    SeverityLevel
)

from .config import FuzzingConfig
from .harness_generator import HarnessGenerator
from .fuzzing_orchestrator import FuzzingOrchestrator
from .crash_analyzer import CrashAnalyzer
from .false_positive_pruner import FalsePositivePruner
from .poc_generator import PoCGenerator
from .exploitability_scorer import ExploitabilityScorer

__all__ = [
    'FuzzingCampaign',
    'CrashReport',
    'ValidatedVulnerability',
    'FuzzingStats',
    'CrashType',
    'CampaignStatus',
    'SeverityLevel',
    'FuzzingConfig',
    'HarnessGenerator',
    'FuzzingOrchestrator',
    'CrashAnalyzer',
    'FalsePositivePruner',
    'PoCGenerator',
    'ExploitabilityScorer',
]

__version__ = '1.0.0'
