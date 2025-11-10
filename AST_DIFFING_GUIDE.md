# AST Diffing for Vulnerability Pattern Extraction

## Overview

This guide explains how to extract vulnerability patterns from security patches using Abstract Syntax Tree (AST) diffing. The extracted patterns can be used to scan thousands of plugins to find vulnerability clones.

## Concept

### The Problem

When a vulnerability is patched, the diff shows what changed. But how do you find similar vulnerabilities in other plugins?

**Traditional approach**: Simple text search
- Problem: Misses variations (different variable names, formatting)
- Problem: Many false positives

**AST-based approach**: Structural pattern matching
- Solution: Match code structure, not just text
- Solution: More accurate, fewer false positives

### The Solution: Pre-Patch and Post-Patch AST Patterns

1. **Pre-Patch AST** (Vulnerable Pattern): The structure of vulnerable code
   - This is your "vulnerability signature"
   - What you search for in other plugins

2. **Post-Patch AST** (Patched Pattern): The structure of fixed code
   - This is your "answer key"
   - Used to avoid false positives from already-fixed code

3. **Smart Matching**: Match vulnerable pattern BUT NOT patched pattern
   - If code matches Pre-Patch AST only → Real vulnerability!
   - If code matches both → Already patched (skip)
   - If code matches neither → Different code (skip)

## Example: CVE-2024-9425 (XSS)

### The Vulnerability

**Vulnerable Code** (Pre-Patch):
```php
echo $classes;
```

**Patched Code** (Post-Patch):
```php
echo esc_attr($classes);
```

### The AST Structures

**Pre-Patch AST** (Your vulnerability signature 🎯):
```
echo_statement
  ├── echo
  └── variable_name: $classes
```

**Post-Patch AST** (The "answer key"):
```
echo_statement
  ├── echo
  └── function_call_expression: esc_attr
      └── variable_name: $classes
```

### The Diff

**What changed?**
- The `variable_name` node was wrapped by a `function_call_expression` node
- The function is `esc_attr` (escaping function)

**This tells us:**
- Vulnerability type: Missing output escaping (XSS)
- Fix: Wrap output with `esc_attr()`
- Pattern: Look for echo statements with unescaped variables

## Usage

### 1. Demonstration Script

Run the demonstration to see AST diffing in action:

```bash
python demo_ast_diff.py
```

This demonstrates:
- Parsing PHP code into ASTs
- Finding differences between vulnerable and patched code
- Extracting minimal differing subtrees
- Pattern matching examples
- Saving patterns to JSON

**Output**:
- Console output showing the full process
- `pattern_example_cve_2024_9425.json` - Example vulnerability pattern

### 2. Extract Patterns from CVE Data

Process your existing CVE signatures to extract patterns:

```bash
# Extract patterns from all signatures
python extract_vulnerability_patterns.py --input-dir signatures/

# Extract from first 10 signatures (for testing)
python extract_vulnerability_patterns.py --input-dir signatures/ --limit 10

# Quiet mode
python extract_vulnerability_patterns.py --input-dir signatures/ --quiet
```

**Output**:
- `vulnerability_patterns/` - Directory containing extracted patterns
- `vulnerability_patterns/[plugin_slug]/[cve]_pattern.json` - Individual patterns
- `vulnerability_patterns/patterns_[type].json` - Patterns grouped by vulnerability type
- `vulnerability_patterns/extraction_summary.json` - Statistics

### 3. Pattern File Format

Each extracted pattern includes:

```json
{
  "metadata": {
    "cve": "CVE-2024-9425",
    "plugin_slug": "example-plugin",
    "vuln_type": "Cross-Site Scripting (XSS)",
    "vulnerable_version": "1.2.3",
    "patched_version": "1.2.4"
  },

  "vulnerable_pattern": {
    "code": "<?php echo $classes; ?>",
    "ast": { ... },
    "signature": "program(php_tag,echo_statement(echo,variable_name(...)))"
  },

  "patched_pattern": {
    "code": "<?php echo esc_attr($classes); ?>",
    "ast": { ... },
    "signature": "program(php_tag,echo_statement(echo,function_call_expression(...)))"
  },

  "diffs": [
    {
      "type": "modified",
      "description": "Node type changed: variable_name -> function_call_expression",
      "path": ["program", "echo_statement", "variable_name"],
      "vulnerable_node": { ... },
      "patched_node": { ... }
    }
  ],

  "security_functions": {
    "added": ["esc_attr"],
    "removed": []
  },

  "pattern_hash": "a3f5c8d9e2b1f4a7"
}
```

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                    AST Diffing Pipeline                      │
└─────────────────────────────────────────────────────────────┘

1. PHPASTParser (ast_parser.py)
   ├── Parses PHP code using tree-sitter
   ├── Converts to ASTNode data structure
   └── Simplifies ASTs for storage

2. ASTDiffer (ast_differ.py)
   ├── Compares two ASTs recursively
   ├── Identifies structural differences
   ├── Filters to minimal diffs
   └── Extracts security-relevant changes

3. ASTSignatureGenerator (ast_signature_generator.py)
   ├── Orchestrates the pipeline
   ├── Loads CVE data
   ├── Generates AST signatures
   └── Saves patterns to disk

4. Demo & Extraction Scripts
   ├── demo_ast_diff.py - Interactive demonstration
   └── extract_vulnerability_patterns.py - Batch processing
```

### Data Models

```python
# ASTNode - Represents a node in the syntax tree
ASTNode(
    node_type: str,           # e.g., "echo_statement", "function_call"
    text: str,                # Source code text
    children: List[ASTNode],  # Child nodes
    field_name: Optional[str] # Named field (e.g., "arguments")
)

# ASTDiff - Represents a difference between two nodes
ASTDiff(
    diff_type: str,                      # "added", "removed", "modified"
    vulnerable_node: Optional[ASTNode],  # Node from vulnerable version
    patched_node: Optional[ASTNode],     # Node from patched version
    path: List[str],                     # Path in tree
    description: str                     # Human-readable description
)

# ASTSignature - Complete vulnerability signature
ASTSignature(
    vulnerable_ast: ASTNode,       # Pre-patch AST
    patched_ast: ASTNode,          # Post-patch AST
    minimal_diffs: List[ASTDiff],  # Minimal differences
    vulnerable_code: str,          # Original vulnerable code
    patched_code: str              # Original patched code
)
```

## Real-World Examples

### Example 1: Cross-Site Scripting (XSS)

**Pattern**: Echo statement without escaping

**Vulnerable**:
```php
echo $user_data;
echo $post_title;
echo $_GET['name'];
```

**Patched**:
```php
echo esc_html($user_data);
echo esc_html($post_title);
echo esc_html($_GET['name']);
```

**AST Pattern**:
- Pre-Patch: `echo_statement -> variable`
- Post-Patch: `echo_statement -> function_call(esc_html) -> variable`

### Example 2: SQL Injection

**Pattern**: Direct SQL query without prepare()

**Vulnerable**:
```php
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$results = $wpdb->get_results($query);
```

**Patched**:
```php
$query = $wpdb->prepare("SELECT * FROM users WHERE id = %d", $_GET['id']);
$results = $wpdb->get_results($query);
```

**AST Pattern**:
- Pre-Patch: `assignment -> binary_expression (concatenation with $_GET)`
- Post-Patch: `assignment -> method_call($wpdb->prepare)`

### Example 3: Authorization Bypass

**Pattern**: Missing capability check

**Vulnerable**:
```php
function delete_user() {
    wp_delete_user($_POST['user_id']);
}
```

**Patched**:
```php
function delete_user() {
    if (!current_user_can('delete_users')) {
        return;
    }
    wp_delete_user($_POST['user_id']);
}
```

**AST Pattern**:
- Added: `if_statement -> function_call(current_user_can)`
- Location: Beginning of function body

## Scanning for Vulnerabilities

### How to Use Patterns for Scanning

Once you have extracted patterns, you can scan other plugins:

```python
from wordpress_vulnerability_analyzer.ast_parser import PHPASTParser
from wordpress_vulnerability_analyzer.ast_differ import ASTDiffer

# Load your pattern
with open('vulnerability_patterns/example-plugin/CVE-2024-9425_pattern.json') as f:
    pattern = json.load(f)

vulnerable_pattern = pattern['vulnerable_pattern']
patched_pattern = pattern['patched_pattern']

# Parse target plugin code
parser = PHPASTParser()
target_ast = parser.parse(target_code)

# Check if it matches the vulnerable pattern
# (Implementation depends on your matching algorithm)

# Also check if it matches the patched pattern
# If it matches vulnerable but NOT patched → Real vulnerability!
```

### Matching Strategies

1. **Exact Structural Match**
   - Match AST structure exactly
   - High precision, may miss variations

2. **Fuzzy Structural Match**
   - Allow some variation (different variable names)
   - Better recall, some false positives

3. **Semantic Match**
   - Match based on semantic meaning
   - Most robust, computationally expensive

## Performance Considerations

### AST Simplification

To reduce storage and improve matching speed:

```python
# Simplify AST to max depth of 8 levels
simplified_ast = parser.simplify_ast(full_ast, max_depth=8)

# This reduces:
# - File size (less storage)
# - Comparison time (faster matching)
# - Memory usage (more patterns in RAM)
```

### Pattern Deduplication

```python
# Patterns are deduplicated by hash
pattern_hash = compute_hash(vulnerable_ast, patched_ast)

# Skip if hash already exists
if pattern_hash in seen_patterns:
    skip()
```

### Batch Processing

```bash
# Process in batches
python extract_vulnerability_patterns.py --limit 100

# Resume from checkpoint if interrupted
# (Progress is saved automatically)
```

## Advanced Features

### Security-Relevant Filtering

The differ can identify security-specific changes:

```python
differ = ASTDiffer()
all_diffs = differ.diff(vuln_ast, patch_ast)

# Filter to only security changes
security_diffs = differ.get_security_relevant_diffs(all_diffs)

# This filters for changes involving:
# - WordPress security functions (esc_*, sanitize_*, wp_nonce_*)
# - Authorization functions (current_user_can, is_admin)
# - Database functions (prepare, wpdb)
# - PHP security functions (htmlspecialchars, filter_*, etc.)
```

### Minimal Diff Extraction

Get only the most specific changes:

```python
# All differences (may include parent and child)
all_diffs = differ.diff(vuln_ast, patch_ast)

# Only most specific (child) differences
minimal_diffs = differ.get_minimal_diffs(all_diffs)

# This reduces noise and focuses on the actual change point
```

### Diff Visualization

```python
# Human-readable diff visualization
for diff in diffs:
    print(differ.visualize_diff(diff))

# Output:
# [MODIFIED] Node type changed: variable_name -> function_call_expression
# Path: program -> echo_statement -> variable_name
# Vulnerable:
#   variable_name
#   Text: $classes
# Patched:
#   function_call_expression
#   Text: esc_attr($classes)
```

## Troubleshooting

### Parse Errors

If code fails to parse:

1. **Check PHP syntax**: Code must be valid PHP
2. **Add PHP tags**: Ensure code starts with `<?php`
3. **Check encoding**: File must be UTF-8
4. **Simplify code**: Try with just the changed function

### No Diffs Found

If no differences are detected:

1. **Check code is different**: Verify pre/post code actually differs
2. **Whitespace**: Use `ignore_whitespace=True`
3. **Comments**: Use `ignore_comments=True`
4. **Increase depth**: May need to compare deeper in tree

### False Positives

If getting too many matches:

1. **Use patched pattern**: Check code doesn't match patched version
2. **Increase specificity**: Use more context in pattern
3. **Add semantic checks**: Verify function names, not just structure

## Next Steps

1. **Extract patterns** from your CVE database
2. **Build pattern database** organized by vulnerability type
3. **Create scanner** that uses patterns to scan plugins
4. **Implement matching algorithm** (exact or fuzzy)
5. **Scale up** to scan 100k+ plugins

## References

- `ast_parser.py` - PHP AST parser using tree-sitter
- `ast_differ.py` - AST comparison and diffing
- `ast_signature_generator.py` - Signature generation pipeline
- `models.py` - Data models (ASTNode, ASTDiff, ASTSignature)
- `demo_ast_diff.py` - Interactive demonstration
- `extract_vulnerability_patterns.py` - Batch extraction

## Questions?

For issues or questions, check:
- The demo script for working examples
- The code comments for implementation details
- The generated JSON files for data structure examples
