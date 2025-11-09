# Working with Generated Signatures - Practical Guide

## Understanding Your Signature Data

When you generate signatures, here's what each field means:

### Example Signature

```json
{
  "cve": "CVE-2023-1234",
  "plugin_slug": "example-plugin",
  "vuln_type": "Cross-Site Request Forgery (CSRF)",
  "signature_type": "security_function_pattern",
  "pattern": "Cross-Site Request Forgery (CSRF)::AUTH[wp_verify_nonce]",
  "context": {
    "title": "CSRF in admin panel",
    "affected_versions": "<= 1.2.3",
    "patched_version": "1.2.4",
    "detected_patterns": [
      "AUTH:wp_verify_nonce",
      "SANITIZE:sanitize_text_field"
    ],
    "file_changes": 2
  },
  "severity_indicators": ["CRITICAL:MISSING_AUTH"],
  "exploitability_score": 7.0,
  "diff_before": "...",
  "diff_after": "..."
}
```

---

## Field-by-Field Breakdown

### 1. `detected_patterns` - What Was Added

**What it shows**: Security functions added in the patch

**Example**:
```json
"detected_patterns": [
    "AUTH:wp_verify_nonce",
    "SANITIZE:sanitize_text_field",
    "OUTPUT_ESC:esc_html"
]
```

**Interpretation**:
- `AUTH:wp_verify_nonce` → Nonce verification was added
- `SANITIZE:sanitize_text_field` → Input sanitization was added
- `OUTPUT_ESC:esc_html` → Output escaping was added

**⚠️ Important**:
- Multiple patterns may appear even if CVE only mentions one vulnerability
- Some patterns might be incidental fixes
- Some might be false positives from unrelated code

---

### 2. `pattern` - The Signature

**Format**: `{VulnType}::{Category}[functions]`

**Examples**:
```
"Cross-Site Request Forgery (CSRF)::AUTH[wp_verify_nonce]"
"SQL Injection::SQL_SECURITY[$wpdb->prepare,absint]"
"XSS::SANITIZE[sanitize_text_field]|OUTPUT_ESC[esc_html]"
```

**How to read it**:
- Before `::` = Vulnerability type
- After `::` = Security categories and functions added

---

### 3. `severity_indicators` - Why It's Critical

**What it shows**: Severity assessment based on pattern + vuln_type match

**Examples**:
```json
"severity_indicators": ["CRITICAL:MISSING_AUTH"]
→ Missing authentication on CSRF/authorization vulnerability

"severity_indicators": ["HIGH:SQL_INJECTION_RISK"]
→ SQL injection protection was added

"severity_indicators": ["HIGH:MISSING_SANITIZATION", "CRITICAL:MISSING_AUTH"]
→ Multiple critical issues fixed
```

**⚠️ Note**: Only includes indicators that **match the vuln_type**!

**Example of mismatch**:
```json
{
  "vuln_type": "Cross-Site Request Forgery (CSRF)",
  "detected_patterns": ["AUTH:wp_verify_nonce", "OUTPUT_ESC:esc_html"],
  "severity_indicators": ["CRITICAL:MISSING_AUTH"]
  // OUTPUT_ESC not in severity_indicators because vuln_type doesn't mention XSS
}
```

---

### 4. `exploitability_score` - Risk Level

**Scale**: 0.0 to 10.0

**Calculation**:
```
Base score: 5.0
+ Critical indicators: +2.0 each
+ High indicators: +1.0 each
+ High-impact vuln type: +1.5
```

**Risk Levels**:
- `8.0 - 10.0` = Critical (high priority)
- `6.0 - 7.9` = High (medium-high priority)
- `4.0 - 5.9` = Medium (review recommended)
- `0.0 - 3.9` = Low (informational)

---

## Querying Signatures

### Find all CSRF vulnerabilities

```bash
jq '.signatures[] | select(.vuln_type | contains("CSRF"))' vulnerability_signatures.json
```

### Find signatures with specific pattern

```bash
jq '.signatures[] | select(.context.detected_patterns[] | contains("AUTH:wp_verify_nonce"))' \
    vulnerability_signatures.json
```

### Find high-risk signatures (score >= 8.0)

```bash
jq '.signatures[] | select(.exploitability_score >= 8.0)' vulnerability_signatures.json
```

### Count signatures by vulnerability type

```bash
jq -r '.signatures[].vuln_type' vulnerability_signatures.json | \
    sort | uniq -c | sort -rn
```

### Find multi-pattern signatures

```bash
jq '.signatures[] | select(.context.detected_patterns | length > 1)' \
    vulnerability_signatures.json
```

---

## Interpreting Multi-Pattern Signatures

### Scenario 1: Primary + Incidental Fixes

```json
{
  "cve": "CVE-2023-1234",
  "vuln_type": "Cross-Site Request Forgery (CSRF)",
  "detected_patterns": [
    "AUTH:wp_verify_nonce",        ← Primary (matches CSRF)
    "OUTPUT_ESC:esc_html",         ← Incidental (XSS also fixed)
    "SANITIZE:sanitize_text_field" ← Incidental (input validation)
  ],
  "severity_indicators": [
    "CRITICAL:MISSING_AUTH"  ← Only CSRF-related
  ]
}
```

**How to interpret**:
1. **Primary issue**: CSRF (missing nonce verification)
2. **Also fixed**: XSS (output escaping + sanitization)
3. **Recommendation**: Developer fixed multiple issues in one patch

**Use case**:
- If scanning for CSRF, look for `AUTH:wp_verify_nonce`
- The XSS patterns are bonus information
- Good example of comprehensive security fix

---

### Scenario 2: Complex Pattern

```json
{
  "cve": "CVE-2023-5678",
  "vuln_type": "SQL Injection",
  "pattern": "SQL Injection::SQL_SECURITY[$wpdb->prepare,absint]|AUTH[current_user_can]",
  "detected_patterns": [
    "SQL_SECURITY:$wpdb->prepare",
    "SQL_SECURITY:absint",
    "AUTH:current_user_can"
  ],
  "severity_indicators": [
    "HIGH:SQL_INJECTION_RISK"
  ]
}
```

**How to interpret**:
1. **Primary issue**: SQL Injection
2. **Fix approach**:
   - Added prepared statements (`$wpdb->prepare`)
   - Added type casting (`absint`)
   - Added authorization check (`current_user_can`)
3. **Pattern shows**: Defense in depth (multiple layers)

**Use case**:
- Look for SQL queries without prepared statements
- Check for missing type validation
- Verify capability checks on database operations

---

## Building a Scanner from Signatures

### Step 1: Extract Common Patterns

```bash
# Find most common patterns for each vulnerability type
jq -r '.signatures[] |
    select(.vuln_type == "Cross-Site Request Forgery (CSRF)") |
    .context.detected_patterns[]' vulnerability_signatures.json | \
    sort | uniq -c | sort -rn
```

**Example output**:
```
    150 AUTH:wp_verify_nonce
     45 AUTH:check_admin_referer
     20 AUTH:current_user_can
```

**Conclusion**: CSRF vulnerabilities are usually fixed by adding `wp_verify_nonce`

---

### Step 2: Create Scanning Rules

Based on signatures, create scanning rules:

```php
// Scanner pseudo-code
function scan_for_csrf($code) {
    // Based on signature: CSRF usually needs nonce verification
    $functions_handling_post = find_functions_using($_POST);

    foreach ($functions_handling_post as $func) {
        // Check if function has nonce verification
        if (!contains($func, 'wp_verify_nonce') &&
            !contains($func, 'check_admin_referer')) {

            flag_vulnerability("Possible CSRF", $func);
        }
    }
}
```

---

### Step 3: Prioritize by Exploitability Score

```bash
# Get top 10 most exploitable patterns
jq -r '.signatures | sort_by(.exploitability_score) | reverse |
    .[0:10] | .[] |
    "\(.exploitability_score) - \(.vuln_type) - \(.pattern)"' \
    vulnerability_signatures.json
```

Use this to prioritize what to scan for first.

---

## Filtering Reliable Signatures

### High-Confidence Signatures

Look for signatures with:

1. **Single detected pattern** (less likely to be mixed)
```bash
jq '.signatures[] | select(.context.detected_patterns | length == 1)' \
    vulnerability_signatures.json
```

2. **Pattern matches vuln_type** (primary fix, not incidental)
```bash
# CSRF with AUTH pattern
jq '.signatures[] |
    select(.vuln_type | contains("CSRF")) |
    select(.context.detected_patterns[] | contains("AUTH"))' \
    vulnerability_signatures.json
```

3. **High exploitability score** (critical issues)
```bash
jq '.signatures[] | select(.exploitability_score >= 8.0)' \
    vulnerability_signatures.json
```

---

## Example: Building CSRF Detection Rules

### 1. Analyze CSRF Signatures

```bash
jq '.signatures[] | select(.vuln_type | contains("CSRF"))' \
    vulnerability_signatures.json > csrf_signatures.json
```

### 2. Extract Common Patterns

```bash
jq -r '.[].context.detected_patterns[]' csrf_signatures.json | \
    sort | uniq -c | sort -rn
```

**Result**:
```
    200 AUTH:wp_verify_nonce
     50 AUTH:check_admin_referer
     30 AUTH:current_user_can
     10 SANITIZE:sanitize_text_field
```

### 3. Build Detection Rule

**Rule**: Functions that process POST data without nonce verification are vulnerable to CSRF

```python
def detect_csrf_vulnerability(php_code):
    """
    Based on 200+ CSRF signatures showing wp_verify_nonce fixes
    """
    functions = parse_php_functions(php_code)

    for func in functions:
        # Check if function uses POST/GET data
        if uses_superglobal(func, ['$_POST', '$_GET', '$_REQUEST']):

            # Check if nonce verification exists
            has_nonce = (
                'wp_verify_nonce' in func.body or
                'check_admin_referer' in func.body or
                'check_ajax_referer' in func.body
            )

            if not has_nonce:
                return {
                    'vulnerability': 'CSRF',
                    'confidence': 0.8,  # High confidence based on 200 examples
                    'fix': 'Add wp_verify_nonce() check',
                    'example_cves': get_example_cves_with_pattern('AUTH:wp_verify_nonce')
                }
```

---

## Dealing with Ambiguous Signatures

### When You See This:

```json
{
  "vuln_type": "Cross-Site Request Forgery (CSRF)",
  "detected_patterns": [
    "AUTH:wp_verify_nonce",
    "SANITIZE:sanitize_text_field",
    "OUTPUT_ESC:esc_html",
    "SQL_SECURITY:absint"
  ]
}
```

### Ask:

1. **Is this one vulnerability or multiple?**
   - Check `diff_before` and `diff_after` fields
   - Review if patterns are in same function or different

2. **Which pattern is primary?**
   - Match against `vuln_type`
   - CSRF → AUTH patterns are primary
   - Others are likely incidental

3. **Should I trust all patterns?**
   - Check `file_changes` count
   - High count (>5) → more chance of unrelated code
   - Low count (1-2) → more reliable

---

## Best Practices

### ✓ DO:

1. **Cross-reference with CVE details**
   ```bash
   jq '.signatures[] | select(.cve == "CVE-2023-1234")' \
       vulnerability_signatures.json
   ```

2. **Look at diff_before and diff_after** for confirmation
   ```bash
   jq '.signatures[0].diff_after' vulnerability_signatures.json
   ```

3. **Focus on patterns matching vuln_type**
   ```
   CSRF → AUTH patterns
   XSS → SANITIZE/OUTPUT_ESC patterns
   SQL Injection → SQL_SECURITY patterns
   ```

4. **Use exploitability_score for prioritization**

### ✗ DON'T:

1. **Don't assume all detected_patterns are primary**
   - Some are incidental fixes

2. **Don't ignore context**
   - Check file_changes count
   - Review actual diffs when in doubt

3. **Don't treat low scores as unimportant**
   - Score reflects missing patterns, not actual impact

---

## Summary Cheat Sheet

| Field | What It Tells You | Trust Level |
|-------|------------------|-------------|
| `vuln_type` | Official vulnerability classification | High ✓ |
| `detected_patterns` | All security functions added | Medium ⚠️ |
| `pattern` | Signature for detection | Medium ⚠️ |
| `severity_indicators` | Matched severity (vuln_type + patterns) | High ✓ |
| `exploitability_score` | Risk level | Medium ⚠️ |
| `diff_before/after` | Actual code changes | High ✓ |

**Rule of thumb**:
- Single pattern + high score = High confidence ✓
- Multiple patterns + low file_changes = Medium confidence ⚠️
- Multiple patterns + high file_changes = Review manually ⚠️

---

## Production Usage Recommendations

### For Security Scanners

1. **Filter by Quality Score**: Use signatures with quality_score >= 0.8 for high confidence
2. **Focus on Primary Patterns**: Use patterns that match the vulnerability type
3. **Validate Detections**: Cross-reference with CVE details and patch diffs
4. **Update Regularly**: Regenerate signatures as new vulnerabilities are discovered

### For Vulnerability Research

1. **Analyze Pattern Distributions**: Understand common fix patterns across vulnerability types
2. **Study High-Impact Fixes**: Focus on signatures with exploitability_score >= 8.0
3. **Compare Across Plugins**: Identify systemic issues vs. plugin-specific problems
4. **Track Evolution**: Monitor how fix patterns change over time

### For Automated Analysis

```python
# Example: Load and filter high-quality signatures
import json

def load_trusted_signatures(min_quality=0.8, min_exploitability=7.0):
    """Load only high-quality, high-impact signatures"""
    with open('vulnerability_signatures.json') as f:
        data = json.load(f)

    return [
        sig for sig in data['signatures']
        if sig.get('context', {}).get('quality_score', 0) >= min_quality
        and sig.get('exploitability_score', 0) >= min_exploitability
        and sig.get('validated', False)
    ]

# Use in your security scanner
trusted_sigs = load_trusted_signatures()
print(f"Loaded {len(trusted_sigs)} trusted signatures")
```

## Advanced Analysis

### Signature Clustering

Group signatures by pattern similarity to find common vulnerability classes:

```bash
# Find all CSRF signatures and their patterns
jq -r '.signatures[] |
    select(.vuln_type | contains("CSRF")) |
    .context.detected_patterns[] ' vulnerability_signatures.json |
    sort | uniq -c | sort -rn
```

### Cross-Plugin Analysis

Identify vulnerabilities that appear across multiple plugins:

```bash
# Find common patterns across plugins
jq -r '.signatures[] |
    "\(.pattern) | \(.plugin_slug)"' vulnerability_signatures.json |
    cut -d'|' -f1 | sort | uniq -c | sort -rn | head -20
```

## Summary

The generated signatures provide valuable insights into WordPress vulnerability patterns. When used with proper validation and filtering, they can:

- **Accelerate security scanning** by identifying high-probability vulnerability patterns
- **Guide security research** by revealing common weaknesses in WordPress plugins
- **Inform secure development** by highlighting security functions that prevent vulnerabilities
- **Enable proactive defense** by detecting similar issues before they're exploited

Always combine automated signature analysis with manual review and validation for production security applications.
