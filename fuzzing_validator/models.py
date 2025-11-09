"""Data models for fuzzing validation system."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from datetime import datetime
from enum import Enum


class CampaignStatus(Enum):
    """Status of fuzzing campaign."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    CRASHED = "crashed"
    TIMEOUT = "timeout"
    ERROR = "error"


class CrashType(Enum):
    """Type of crash detected."""
    SQL_ERROR = "sql_error"
    PHP_FATAL = "php_fatal"
    PHP_WARNING = "php_warning"
    SEGFAULT = "segfault"
    ASAN_ERROR = "asan_error"
    UBSAN_ERROR = "ubsan_error"
    PATH_TRAVERSAL = "path_traversal"
    XSS_DETECTED = "xss_detected"
    CSRF_DETECTED = "csrf_detected"
    AUTH_BYPASS = "auth_bypass"
    FILE_UPLOAD = "file_upload"
    COMMAND_INJECTION = "command_injection"
    DESERIALIZATION = "deserialization"
    UNKNOWN = "unknown"


class SeverityLevel(Enum):
    """Severity of vulnerability."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class FuzzingCampaign:
    """Represents a fuzzing campaign for a specific zero-day candidate."""

    campaign_id: str
    plugin_slug: str
    signature_id: str
    vulnerability_type: str

    # Fuzzing configuration
    fuzzer: str  # "custom-php-fuzzer", "afl++", "libfuzzer"
    target_file: str
    target_function: Optional[str] = None
    fuzz_duration_seconds: int = 3600  # 1 hour default

    # Seeds
    initial_seeds: List[str] = field(default_factory=list)

    # Results
    status: CampaignStatus = CampaignStatus.PENDING
    total_executions: int = 0
    crashes_found: int = 0
    unique_crashes: int = 0
    coverage_percentage: float = 0.0

    # Metadata
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    elapsed_seconds: float = 0.0

    # Output paths
    harness_path: Optional[str] = None
    output_dir: Optional[str] = None

    def calculate_elapsed(self):
        """Calculate elapsed time."""
        if self.start_time and self.end_time:
            delta = self.end_time - self.start_time
            self.elapsed_seconds = delta.total_seconds()

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'campaign_id': self.campaign_id,
            'plugin_slug': self.plugin_slug,
            'signature_id': self.signature_id,
            'vulnerability_type': self.vulnerability_type,
            'fuzzer': self.fuzzer,
            'target_file': self.target_file,
            'target_function': self.target_function,
            'fuzz_duration_seconds': self.fuzz_duration_seconds,
            'initial_seeds': self.initial_seeds,
            'status': self.status.value,
            'total_executions': self.total_executions,
            'crashes_found': self.crashes_found,
            'unique_crashes': self.unique_crashes,
            'coverage_percentage': self.coverage_percentage,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'elapsed_seconds': self.elapsed_seconds,
            'harness_path': self.harness_path,
            'output_dir': self.output_dir,
        }


@dataclass
class CrashReport:
    """Represents a crash found during fuzzing."""

    crash_id: str
    campaign_id: str

    # Crash details
    crashing_input: str
    crash_type: CrashType
    stack_trace: Optional[str] = None
    error_message: Optional[str] = None

    # Exploitability
    exploitability_score: float = 0.0  # 0-10, CVSS-like
    is_exploitable: bool = False
    exploitation_notes: Optional[str] = None

    # CVSS scoring
    cvss_score: float = 0.0
    cvss_vector: Optional[str] = None

    # Attack characteristics
    attack_vector: str = "network"  # network, adjacent, local
    attack_complexity: str = "low"  # low, medium, high
    privileges_required: str = "none"  # none, low, high
    user_interaction: str = "none"  # none, required
    impact_level: str = "high"  # low, medium, high, critical

    # Classification
    is_unique: bool = True
    duplicate_of: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.MEDIUM

    # Metadata
    discovered_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'crash_id': self.crash_id,
            'campaign_id': self.campaign_id,
            'crashing_input': self.crashing_input,
            'crash_type': self.crash_type.value,
            'stack_trace': self.stack_trace,
            'error_message': self.error_message,
            'exploitability_score': self.exploitability_score,
            'is_exploitable': self.is_exploitable,
            'exploitation_notes': self.exploitation_notes,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'attack_vector': self.attack_vector,
            'attack_complexity': self.attack_complexity,
            'privileges_required': self.privileges_required,
            'user_interaction': self.user_interaction,
            'impact_level': self.impact_level,
            'is_unique': self.is_unique,
            'duplicate_of': self.duplicate_of,
            'severity': self.severity.value,
            'discovered_at': self.discovered_at.isoformat(),
        }


@dataclass
class ValidatedVulnerability:
    """Represents a validated zero-day with PoC."""

    plugin_slug: str
    current_version: str
    signature_id: str
    original_cve: Optional[str]
    vulnerability_type: str

    # Validation status
    validated: bool = False
    validation_method: str = "fuzzing"
    validation_date: Optional[datetime] = None

    # Proof of concept
    poc_payload: Optional[str] = None
    poc_description: Optional[str] = None
    poc_script_path: Optional[str] = None

    # Crash evidence
    crash_reports: List[CrashReport] = field(default_factory=list)
    unique_crashes: int = 0

    # Exploitability
    cvss_score: float = 0.0
    cvss_vector: Optional[str] = None
    exploitation_complexity: str = "medium"  # low, medium, high

    # Metadata
    false_positive: bool = False
    reported: bool = False
    disclosure_status: str = "pending"  # pending, disclosed, patched

    # Additional context
    matched_files: List[str] = field(default_factory=list)
    matched_code_snippets: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'plugin_slug': self.plugin_slug,
            'current_version': self.current_version,
            'signature_id': self.signature_id,
            'original_cve': self.original_cve,
            'vulnerability_type': self.vulnerability_type,
            'validated': self.validated,
            'validation_method': self.validation_method,
            'validation_date': self.validation_date.isoformat() if self.validation_date else None,
            'poc_payload': self.poc_payload,
            'poc_description': self.poc_description,
            'poc_script_path': self.poc_script_path,
            'unique_crashes': self.unique_crashes,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'exploitation_complexity': self.exploitation_complexity,
            'false_positive': self.false_positive,
            'reported': self.reported,
            'disclosure_status': self.disclosure_status,
            'matched_files': self.matched_files,
            'matched_code_snippets': self.matched_code_snippets,
            'crash_reports': [c.to_dict() for c in self.crash_reports],
        }


@dataclass
class FuzzingStats:
    """Statistics for fuzzing validation operations."""

    total_candidates: int = 0
    campaigns_run: int = 0
    campaigns_completed: int = 0
    campaigns_with_crashes: int = 0

    total_crashes_found: int = 0
    unique_crashes_found: int = 0

    validated_vulnerabilities: int = 0
    false_positives: int = 0

    # Performance
    total_executions: int = 0
    total_fuzzing_time_seconds: float = 0.0

    # Accuracy metrics
    false_positive_rate: float = 0.0
    validation_accuracy: float = 0.0

    # Severity breakdown
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    # Type breakdown
    vulnerability_type_counts: Dict[str, int] = field(default_factory=dict)

    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    def calculate_metrics(self):
        """Calculate derived metrics."""
        if self.total_candidates > 0:
            self.false_positive_rate = (self.false_positives / self.total_candidates) * 100
            self.validation_accuracy = (self.validated_vulnerabilities / self.total_candidates) * 100

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'total_candidates': self.total_candidates,
            'campaigns_run': self.campaigns_run,
            'campaigns_completed': self.campaigns_completed,
            'campaigns_with_crashes': self.campaigns_with_crashes,
            'total_crashes_found': self.total_crashes_found,
            'unique_crashes_found': self.unique_crashes_found,
            'validated_vulnerabilities': self.validated_vulnerabilities,
            'false_positives': self.false_positives,
            'total_executions': self.total_executions,
            'total_fuzzing_time_seconds': self.total_fuzzing_time_seconds,
            'total_fuzzing_time_hours': round(self.total_fuzzing_time_seconds / 3600, 2),
            'false_positive_rate': round(self.false_positive_rate, 2),
            'validation_accuracy': round(self.validation_accuracy, 2),
            'severity_breakdown': {
                'critical': self.critical_count,
                'high': self.high_count,
                'medium': self.medium_count,
                'low': self.low_count,
            },
            'vulnerability_type_breakdown': self.vulnerability_type_counts,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
        }
