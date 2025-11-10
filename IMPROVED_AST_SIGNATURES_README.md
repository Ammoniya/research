# Improved AST-Based Vulnerability Signatures

This document describes the **correct** approach to generating AST-based vulnerability signatures from unified diffs.

## The Problem with the Old Approach

The previous AST signature generation had critical flaws:
1. **Tried to parse incomplete code snippets** - resulted in invalid PHP that couldn't be parsed
2. **No line-range mapping** - couldn't pinpoint which AST nodes actually changed
3. **No normalization** - patterns were too specific to be reusable
4. **Poor minimal node selection** - often captured meaningless tokens instead of meaningful constructs

## The New Approach

### Architecture Overview

```
Unified Diff
    ↓
[UnifiedDiffParser]
    ↓
Full Before/After Files + Line Ranges
    ↓
[PHPASTParser (tree-sitter)]
    ↓
Complete ASTs
    ↓
[ASTLineMapper] + Line Ranges
    ↓
Nodes in Changed Regions
    ↓
[Filter to Meaningful Nodes]
    ↓
Minimal Differing Subtree
    ↓
[ASTNormalizer]
    ↓
Reusable Signature Pattern
```

### Step-by-Step Process

#### 1. Parse Unified Diff
**Module:** `unified_diff_parser.py`

Properly parse unified diff format to extract:
- File paths (before/after)
- Hunks with line numbers
- Changed line ranges

```python
parser = UnifiedDiffParser()
file_diffs = parser.parse(unified_diff_text)
```

#### 2. Reconstruct Full Files
**Module:** `unified_diff_parser.py`

Reconstruct complete before/after file contents:
- Apply hunks to rebuild full files
- Track which lines changed
- Ensure valid, parseable PHP

```python
vuln_code, vuln_ranges = parser.reconstruct_file(hunks, version='old')
patch_code, patch_ranges = parser.reconstruct_file(hunks, version='new')
```

**Key insight:** Parse FULL FILES, not snippets. Full files are valid PHP.

#### 3. Parse into ASTs
**Module:** `ast_parser.py`

Use tree-sitter to parse complete, valid PHP files:

```python
parser = PHPASTParser()
vuln_ast = parser.parse(vuln_code)
patch_ast = parser.parse(patch_code)
```

#### 4. Map Line Ranges to AST Nodes
**Module:** `ast_line_mapper.py`

Find all AST nodes that intersect with changed line ranges:

```python
mapper = ASTLineMapper()
vuln_nodes = []
for start, end in vuln_ranges:
    vuln_nodes.extend(mapper.find_nodes_in_range(vuln_ast, start, end))
```

#### 5. Filter to Meaningful Nodes
**Module:** `improved_signature_generator.py`

Filter nodes to statement/expression level, not tiny tokens:

```python
# Meaningful types: echo_statement, binary_expression, function_call_expression, etc.
# Exclude: tiny tokens like '(', ')', ';', individual quotes, etc.
meaningful_nodes = self._filter_to_meaningful_nodes(vuln_nodes)
```

#### 6. Find Minimal Differing Pair
**Module:** `improved_signature_generator.py`

Identify the smallest *meaningful* node that differs:

```python
vuln_node, patch_node = self._find_smallest_differing_pair(
    meaningful_vuln_nodes,
    meaningful_patch_nodes
)
```

#### 7. Normalize Patterns
**Module:** `ast_normalizer.py`

Create reusable patterns by normalizing:
- **Variable names** → `$VAR1`, `$VAR2`, etc.
- **Security functions** → Preserved and marked as `security_relevant: true`
- **String literals** → Optional fuzzing (kept by default for XSS context)

```python
normalizer = ASTNormalizer(
    normalize_vars=True,
    normalize_strings=False,
    normalize_function_names=False
)
pattern = normalizer.create_pattern_signature(vuln_node, patch_node)
```

#### 8. Generate Detection Rule
**Module:** `ast_normalizer.py`

Create detection rules with metadata:

```python
rule = normalizer.create_detection_rule(
    vulnerable_pattern,
    metadata={'cve': cve, 'type': vuln_type, 'severity': 'high'}
)
```

## Example: amCharts XSS (CVE-2022-36405)

### Input
```php
// Vulnerable
echo '[amcharts id="' . $post_id . '"]';

// Patched
echo '[amcharts id="' . esc_textarea( $post_id ) . '"]';
```

### Generated Signature

**Vulnerable Pattern:**
```json
{
  "type": "binary_expression",
  "children": [
    {"type": "string", "value": "'[amcharts id=\"'"},
    {"type": ".", "value": "."},
    {"type": "variable_name", "value": "$VAR1", "normalized": true}
  ]
}
```

**Patched Pattern:**
```json
{
  "type": "binary_expression",
  "children": [
    {"type": "string", "value": "'[amcharts id=\"'"},
    {"type": ".", "value": "."},
    {
      "type": "function_call_expression",
      "children": [
        {
          "type": "name",
          "value": "esc_textarea",
          "security_relevant": true
        },
        {
          "type": "arguments",
          "children": [
            {"type": "variable_name", "value": "$VAR1", "normalized": true}
          ]
        }
      ]
    }
  ]
}
```

**Pattern Type:** `missing_output_escaping`
**Security Functions Added:** `esc_textarea`
**Severity:** `high`

## Signature Database Schema

```json
{
  "cve": "CVE-2022-36405",
  "plugin_slug": "amcharts-charts-and-maps",
  "vuln_type": "Cross-site Scripting",
  "title": "...",
  "file_path": "includes/editing.php",

  "vulnerable_pattern": { /* Normalized AST */ },
  "patched_pattern": { /* Normalized AST */ },
  "pattern_type": "missing_output_escaping",

  "security_functions_added": ["esc_textarea"],
  "security_functions_removed": [],

  "constraints": {
    "file_extension": ".php",
    "node_type": "binary_expression",
    "changed_lines": [[2, 2]]
  },

  "detection_rule": {
    "pattern": { /* Vulnerable pattern */ },
    "match_type": "structural",
    "metadata": {
      "cve": "CVE-2022-36405",
      "type": "Cross-site Scripting",
      "severity": "high"
    }
  }
}
```

## Usage

### Generate Signatures from Unified Diff

```bash
python generate_improved_signatures.py \
  --input cve_data.json \
  --output data/output/improved_signatures \
  --verbose
```

### Input JSON Format

```json
{
  "cve": "CVE-YYYY-XXXXX",
  "plugin_slug": "plugin-name",
  "vuln_type": "Cross-site Scripting",
  "title": "...",
  "unified_diff": "diff -ruN ...",
  "vulnerable_version": "1.0",
  "patched_version": "1.0.1"
}
```

## Pattern Types Detected

The system automatically infers pattern types:

- **`missing_output_escaping`** - Output not escaped (XSS)
- **`missing_input_sanitization`** - Input not sanitized
- **`sql_injection`** - Missing SQL prepared statements
- **`missing_nonce_verification`** - CSRF protection missing
- **`missing_capability_check`** - Authorization missing
- **`unsafe_deserialization`** - Dangerous unserialize()
- **`security_function_missing`** - Generic security function addition

## Key Benefits

1. **Accurate** - Parses valid PHP, not broken snippets
2. **Precise** - Uses line ranges to locate exact changed nodes
3. **Reusable** - Normalized patterns work across different codebases
4. **Semantic** - Captures meaningful constructs, not tokens
5. **Actionable** - Identifies specific security functions added/missing

## Modules

- **`unified_diff_parser.py`** - Parse unified diffs, reconstruct files
- **`ast_parser.py`** - Parse PHP into ASTs using tree-sitter
- **`ast_line_mapper.py`** - Map line ranges to AST nodes
- **`ast_normalizer.py`** - Normalize AST patterns for reusability
- **`improved_signature_generator.py`** - Main orchestration
- **`generate_improved_signatures.py`** - CLI script

## Dependencies

```bash
pip install tree-sitter tree-sitter-php
```

## Future Improvements

1. **Structural matching** - Match patterns against target codebases
2. **Fuzzy matching** - Handle slight variations in patterns
3. **Control flow analysis** - Detect complex vulnerability patterns
4. **Multi-file analysis** - Track data flow across files
5. **Machine learning** - Learn from large corpus of CVEs
