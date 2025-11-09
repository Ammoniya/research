"""Analyzes crashes from fuzzing campaigns."""

import hashlib
import re
from typing import List, Optional
from .models import CrashReport, CrashType, FuzzingCampaign
from .exploitability_scorer import ExploitabilityScorer


class CrashAnalyzer:
    """Analyzes crashes to determine uniqueness and exploitability."""

    def __init__(self):
        """Initialize crash analyzer."""
        self.scorer = ExploitabilityScorer()
        self.seen_crash_hashes = set()

    def analyze_crash_output(
        self,
        output: str,
        crashing_input: str,
        campaign: FuzzingCampaign
    ) -> Optional[CrashReport]:
        """
        Analyze crash output to create crash report.

        Args:
            output: Output from fuzzing harness
            crashing_input: Input that caused crash
            campaign: Fuzzing campaign

        Returns:
            Optional[CrashReport]: Crash report if crash detected
        """
        # Detect crash type from output
        crash_type = self._detect_crash_type(output)

        if crash_type == CrashType.UNKNOWN:
            # No recognizable crash
            return None

        # Extract error message
        error_message = self._extract_error_message(output)

        # Generate crash ID
        crash_id = self._generate_crash_id(crashing_input, error_message)

        # Check if unique
        is_unique = crash_id not in self.seen_crash_hashes
        if is_unique:
            self.seen_crash_hashes.add(crash_id)

        # Create crash report
        crash = CrashReport(
            crash_id=crash_id,
            campaign_id=campaign.campaign_id,
            crashing_input=crashing_input,
            crash_type=crash_type,
            error_message=error_message,
            stack_trace=self._extract_stack_trace(output),
            is_unique=is_unique,
        )

        # Score the crash
        crash = self.scorer.score_crash(crash)

        # Add exploitation notes
        crash.exploitation_notes = self._generate_exploitation_notes(crash)

        return crash

    def _detect_crash_type(self, output: str) -> CrashType:
        """Detect crash type from output."""
        patterns = {
            CrashType.SQL_ERROR: [
                r'SQL_ERROR_DETECTED',
                r'SQL syntax',
                r'mysql_fetch',
                r'mysqli_fetch',
                r'Duplicate entry',
            ],
            CrashType.XSS_DETECTED: [
                r'XSS_DETECTED',
            ],
            CrashType.CSRF_DETECTED: [
                r'CSRF_DETECTED',
            ],
            CrashType.PATH_TRAVERSAL: [
                r'PATH_TRAVERSAL_DETECTED',
            ],
            CrashType.AUTH_BYPASS: [
                r'AUTH_BYPASS_DETECTED',
            ],
            CrashType.FILE_UPLOAD: [
                r'FILE_UPLOAD_DETECTED',
            ],
            CrashType.PHP_FATAL: [
                r'FATAL:',
                r'Fatal error',
                r'Call to undefined',
            ],
            CrashType.PHP_WARNING: [
                r'Warning:',
                r'Notice:',
            ],
            CrashType.SEGFAULT: [
                r'Segmentation fault',
                r'SIGSEGV',
            ],
            CrashType.ASAN_ERROR: [
                r'AddressSanitizer',
                r'heap-use-after-free',
                r'heap-buffer-overflow',
            ],
        }

        for crash_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, output, re.IGNORECASE):
                    return crash_type

        # Check for generic crash
        if 'CRASH:' in output:
            return CrashType.PHP_FATAL

        return CrashType.UNKNOWN

    def _extract_error_message(self, output: str) -> Optional[str]:
        """Extract error message from output."""
        # Try to find error message
        patterns = [
            r'(?:CRASH|ERROR|FATAL|WARNING):\s*(.+)',
            r'(?:Error|Fatal error):\s*(.+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, output, re.MULTILINE)
            if match:
                return match.group(1).strip()

        # Return first non-empty line
        for line in output.split('\n'):
            line = line.strip()
            if line:
                return line[:200]  # Limit length

        return None

    def _extract_stack_trace(self, output: str) -> Optional[str]:
        """Extract stack trace from output."""
        # Look for stack trace markers
        if 'Stack trace:' in output:
            idx = output.index('Stack trace:')
            return output[idx:idx+500]  # Limit length

        # For PHP errors, capture subsequent lines
        lines = output.split('\n')
        stack_lines = []
        in_stack = False

        for line in lines:
            if 'in ' in line and '.php' in line:
                in_stack = True
                stack_lines.append(line)
            elif in_stack and line.strip().startswith('#'):
                stack_lines.append(line)
            elif in_stack:
                break

        if stack_lines:
            return '\n'.join(stack_lines[:10])  # First 10 lines

        return None

    def _generate_crash_id(self, crashing_input: str, error_message: Optional[str]) -> str:
        """Generate unique crash ID."""
        # Hash based on input and error
        content = f"{crashing_input}:{error_message or ''}"
        return hashlib.md5(content.encode()).hexdigest()[:16]

    def _generate_exploitation_notes(self, crash: CrashReport) -> str:
        """Generate exploitation notes for crash."""
        notes = []

        if crash.crash_type == CrashType.SQL_ERROR:
            notes.append("SQL injection vulnerability detected.")
            notes.append("Attacker can extract data from database.")
            if 'UNION' in crash.crashing_input:
                notes.append("UNION-based injection possible.")
            notes.append("May lead to authentication bypass or data exfiltration.")

        elif crash.crash_type == CrashType.XSS_DETECTED:
            notes.append("Cross-Site Scripting (XSS) vulnerability detected.")
            notes.append("Attacker can inject malicious JavaScript.")
            notes.append("May lead to session hijacking or account takeover.")

        elif crash.crash_type == CrashType.CSRF_DETECTED:
            notes.append("Cross-Site Request Forgery (CSRF) vulnerability detected.")
            notes.append("Privileged action performed without nonce verification.")
            notes.append("Attacker can trick authenticated users into performing actions.")

        elif crash.crash_type == CrashType.PATH_TRAVERSAL:
            notes.append("Path traversal vulnerability detected.")
            notes.append("Attacker can read arbitrary files on the server.")
            if 'wp-config.php' in crash.error_message or '':
                notes.append("Database credentials accessible via path traversal.")
                notes.append("CRITICAL: Can lead to full database compromise.")

        elif crash.crash_type == CrashType.AUTH_BYPASS:
            notes.append("Authentication bypass vulnerability detected.")
            notes.append("Attacker can gain unauthorized access.")
            notes.append("May lead to privilege escalation.")

        elif crash.crash_type == CrashType.FILE_UPLOAD:
            notes.append("Arbitrary file upload vulnerability detected.")
            notes.append("Attacker can upload malicious PHP files.")
            notes.append("CRITICAL: Direct path to Remote Code Execution (RCE).")

        return " ".join(notes)

    def deduplicate_crashes(self, crashes: List[CrashReport]) -> List[CrashReport]:
        """
        Deduplicate crashes based on crash hash.

        Args:
            crashes: List of crashes

        Returns:
            List[CrashReport]: Unique crashes
        """
        unique_crashes = {}

        for crash in crashes:
            if crash.is_unique:
                unique_crashes[crash.crash_id] = crash
            else:
                # Mark as duplicate
                if crash.crash_id in unique_crashes:
                    crash.duplicate_of = crash.crash_id

        return list(unique_crashes.values())
