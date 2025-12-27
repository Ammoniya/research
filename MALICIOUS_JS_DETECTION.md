# Malicious JavaScript Detection Tool

## Overview

This tool scans JavaScript files for common malicious patterns and security vulnerabilities. It's designed to analyze directories containing JavaScript code and identify potential security threats.

## Features

The tool detects the following categories of malicious patterns:

### 1. **Obfuscation** (HIGH/MEDIUM/LOW Severity)
- `eval()` function usage - CWE-95
- Dynamic function creation from strings
- Base64 encoding/decoding (`atob`)
- Character code obfuscation (`fromCharCode`)
- Hex-encoded strings
- Unicode escape sequences
- Deprecated `unescape()` function
- High entropy content (likely obfuscated)
- Extremely long lines (>1000 characters)

### 2. **Remote Execution** (HIGH Severity)
- Windows Script Host execution (`WScript.Shell`)
- Command execution (`.exec()`)
- Node.js child process usage
- System command injection

### 3. **Backdoors** (HIGH Severity)
- Hardcoded passwords - CWE-259
- Shell references
- Direct system binary execution
- Backdoor keywords

### 4. **Data Exfiltration** (MEDIUM Severity)
- XMLHttpRequest usage
- Fetch API calls
- Cookie theft (`document.cookie`)
- Local/session storage access
- Page redirection

### 5. **Injection Attacks** (MEDIUM Severity)
- innerHTML assignments - CWE-79 (XSS)
- `document.write()` usage
- outerHTML assignments
- `insertAdjacentHTML()` usage

### 6. **Crypto Mining** (HIGH Severity)
- CoinHive references
- CryptoNight references
- Mining pool connections
- Stratum protocol usage

### 7. **Suspicious APIs** (MEDIUM/LOW Severity)
- WebSocket connections
- Web Worker creation
- Dynamic script imports (`importScripts`)
- Unusual function context manipulation

### 8. **File System Access** (MEDIUM/HIGH Severity)
- Node.js `fs` module usage
- File read/write operations
- File/directory deletion

## Installation

No installation required. The tool is a standalone Python script with no external dependencies (uses only Python standard library).

**Requirements:**
- Python 3.6 or higher

## Usage

### Basic Usage

Scan the `diff_results` directory (default):
```bash
python3 detect_malicious_js.py
```

### Specify a Different Directory

```bash
python3 detect_malicious_js.py --dir /path/to/javascript/files
```

### Save Report to File

```bash
python3 detect_malicious_js.py --dir diff_results --output report.txt
```

### JSON Output

Generate JSON output for programmatic processing:
```bash
python3 detect_malicious_js.py --dir diff_results --json --output results.json
```

### Quiet Mode

Suppress verbose output:
```bash
python3 detect_malicious_js.py --dir diff_results --quiet
```

## Command Line Options

```
--dir DIRECTORY       Directory to scan (default: diff_results)
--output FILE         Output report file (optional)
--json               Output results in JSON format
--quiet              Suppress verbose output
```

## Example Output

### Text Report Format

```
================================================================================
MALICIOUS JAVASCRIPT DETECTION REPORT
================================================================================
Generated: 2025-12-27 08:24:45

SUMMARY
--------------------------------------------------------------------------------
Files Scanned:        3
Malicious Files:      2
Total Findings:       16
  HIGH Severity:      8
  MEDIUM Severity:    7
  LOW Severity:       1

DETAILED FINDINGS
--------------------------------------------------------------------------------

FILE: subdir1/malicious.js
Findings: 10
--------------------------------------------------------------------------------

HIGH SEVERITY:
  - Line 4: Use of eval() function
    Type: obfuscation
    CWE: CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
    Snippet: eval(atob("bWFsaWNpb3VzX2NvZGU="));
    
...
```

### JSON Output Format

```json
{
  "scan_time": "2025-12-27T08:24:45.123456",
  "directory": "diff_results",
  "statistics": {
    "files_scanned": 3,
    "malicious_files": 2,
    "total_findings": 16,
    "high_severity": 8,
    "medium_severity": 7,
    "low_severity": 1
  },
  "findings": {
    "subdir1/malicious.js": [
      {
        "type": "obfuscation",
        "pattern": "eval\\s*\\(",
        "description": "Use of eval() function",
        "severity": "HIGH",
        "line": 4,
        "snippet": "eval(atob(\"bWFsaWNpb3VzX2NvZGU=\"));",
        "cwe": "CWE-95"
      }
    ]
  }
}
```

## Understanding Severity Levels

- **HIGH**: Critical security vulnerabilities that pose immediate risk (remote code execution, backdoors, crypto miners)
- **MEDIUM**: Potential security issues that require review (data exfiltration, XSS vulnerabilities, suspicious API usage)
- **LOW**: Suspicious patterns that may be legitimate but warrant investigation (Web Workers, storage access)

## Common Weakness Enumeration (CWE) References

The tool maps detected patterns to CWE identifiers:

- **CWE-78**: OS Command Injection
- **CWE-79**: Cross-site Scripting (XSS)
- **CWE-94**: Improper Control of Generation of Code
- **CWE-95**: Improper Neutralization of Directives in Dynamically Evaluated Code
- **CWE-259**: Use of Hard-coded Password
- **CWE-506**: Embedded Malicious Code
- **CWE-601**: URL Redirection to Untrusted Site
- And more...

## False Positives

The tool may report false positives in the following cases:

1. **Legitimate use of `eval()`**: Some libraries use eval for legitimate purposes
2. **Base64 encoding**: Used for data encoding, not always malicious
3. **Fetch/XHR**: Normal API calls may be flagged
4. **innerHTML**: Sometimes used safely with sanitized content

**Recommendation**: Always manually review findings to determine if they represent genuine threats.

## Testing

Test the tool with sample malicious patterns:

```bash
# Create test directory
mkdir -p test_dir
echo 'eval(atob("test"));' > test_dir/test.js

# Run scan
python3 detect_malicious_js.py --dir test_dir
```

## Integration

The tool can be integrated into CI/CD pipelines:

```bash
# Exit with error if malicious code is found
python3 detect_malicious_js.py --dir src/ --json --output scan.json
if [ $(jq '.statistics.malicious_files' scan.json) -gt 0 ]; then
    echo "Malicious code detected!"
    exit 1
fi
```

## Limitations

1. **Static Analysis Only**: The tool performs static pattern matching and doesn't execute code
2. **No Context Awareness**: Cannot determine if detected patterns are used safely
3. **Obfuscation**: Highly obfuscated code may evade some detection patterns
4. **False Positives**: Legitimate code may trigger warnings

## Contributing

To add new detection patterns, edit the `_init_patterns()` method in the `MaliciousJSDetector` class.

## License

This tool is part of the WordPress vulnerability research project.

## Contact

For issues or questions, please open an issue in the repository.
