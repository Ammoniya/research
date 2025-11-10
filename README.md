# WordPress Vulnerability Pattern Extraction

A comprehensive toolkit for extracting, analyzing, and matching vulnerability patterns in WordPress plugins using Abstract Syntax Tree (AST) analysis.

## Overview

This project enables large-scale vulnerability detection in WordPress plugins by:

1. **Extracting** vulnerability patches from CVE data
2. **Analyzing** differences using AST diffing
3. **Generating** reusable vulnerability patterns
4. **Scanning** plugins for vulnerability clones

## Key Features

### 🔍 AST-Based Pattern Extraction

Extract structural patterns from security patches:
- Parse PHP code into Abstract Syntax Trees
- Compare vulnerable vs. patched code
- Identify minimal differing subtrees
- Generate reusable vulnerability signatures

### 🎯 Smart Pattern Matching

Avoid false positives with dual-pattern matching:
- **Pre-Patch Pattern**: The vulnerable code structure (what to find)
- **Post-Patch Pattern**: The fixed code structure (what to ignore)
- Only flag code that matches vulnerable but not patched patterns

### 📊 Vulnerability Database

Process CVE data and build searchable patterns:
- WordPress plugin vulnerabilities from Wordfence
- Organized by plugin, CVE, and vulnerability type
- Includes AST signatures for accurate matching

## Quick Start

### 1. Run the Demonstration

See AST diffing in action:

```bash
python demo_ast_diff.py
```

This demonstrates:
- Parsing vulnerable and patched PHP code
- Finding structural differences
- Extracting vulnerability patterns
- Pattern matching examples

**Output**: `pattern_example_cve_2024_9425.json`

### 2. Extract Patterns from CVE Data

Process your signature database:

```bash
# Extract all patterns
python extract_vulnerability_patterns.py --input-dir signatures/

# Test with first 10 signatures
python extract_vulnerability_patterns.py --input-dir signatures/ --limit 10
```

**Output**: `vulnerability_patterns/` directory with:
- Individual pattern files per CVE
- Patterns grouped by vulnerability type
- Extraction statistics

### 3. Generate Signatures from CVE Database

```bash
python generate_signatures.py
```

This will:
- Load vulnerability data
- Extract diffs from WordPress plugin SVN
- Generate signatures with AST patterns
- Save to `signatures/` directory

## Example: XSS Vulnerability (CVE-2024-9425)

### The Vulnerability

**Vulnerable Code**:
```php
echo $classes;
```

**Patched Code**:
```php
echo esc_attr($classes);
```

### The AST Pattern

**Pre-Patch AST** (Vulnerability Signature 🎯):
```
echo_statement
  └── variable_name: $classes
```

**Post-Patch AST** (Fixed Pattern ✅):
```
echo_statement
  └── function_call: esc_attr
      └── variable_name: $classes
```

**The Diff**: Variable wrapped by `esc_attr()` function

### Scanning for Clones

```python
# Scan plugin-A
code = "echo $user_input;"

Match Pre-Patch? ✓
Match Post-Patch? ✗
Result: 🚨 VULNERABILITY FOUND

# Scan plugin-B
code = "echo esc_attr($user_input);"

Match Pre-Patch? ✗ (different structure - has function call)
Match Post-Patch? ✓
Result: ✅ SAFE (already patched)
```

## Project Structure

```
.
├── demo_ast_diff.py                     # Interactive demonstration
├── extract_vulnerability_patterns.py    # Batch pattern extraction
├── generate_signatures.py               # CVE signature generation
├── AST_DIFFING_GUIDE.md                # Comprehensive guide
│
├── wordpress_vulnerability_analyzer/    # Core library
│   ├── ast_parser.py                   # PHP AST parser
│   ├── ast_differ.py                   # AST comparison
│   ├── ast_signature_generator.py      # Signature generation
│   ├── models.py                       # Data models
│   └── ...                             # Other components
│
├── signatures/                          # CVE signatures (generated)
├── vulnerability_patterns/              # Extracted patterns (generated)
└── pattern_example_cve_2024_9425.json  # Example pattern (demo output)
```

## Documentation

- **[AST_DIFFING_GUIDE.md](AST_DIFFING_GUIDE.md)** - Complete guide to AST diffing
  - Concept and architecture
  - Usage examples
  - Pattern format
  - Scanning strategies
  - Troubleshooting

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Pipeline Overview                         │
└─────────────────────────────────────────────────────────────┘

1. CVE Data → 2. Signature Extraction → 3. AST Diffing → 4. Pattern DB

┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ CVE Database │→→→│  Extract     │→→→│  Parse &     │→→→│  Searchable  │
│ (Wordfence)  │   │  Diffs       │   │  Diff ASTs   │   │  Patterns    │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
                         ↓                    ↓                   ↓
                   Pre/Post Code         AST Trees          Pattern Files
```

### Key Components

1. **PHPASTParser** (`ast_parser.py`)
   - Parses PHP using tree-sitter
   - Converts to ASTNode structure
   - Simplifies for storage

2. **ASTDiffer** (`ast_differ.py`)
   - Compares AST structures
   - Identifies minimal differences
   - Filters security-relevant changes

3. **ASTSignatureGenerator** (`ast_signature_generator.py`)
   - Orchestrates pipeline
   - Generates complete signatures
   - Manages storage

## Use Cases

### 1. Find Vulnerability Clones

Scan 100k+ WordPress plugins for similar vulnerabilities:
- Extract pattern from known CVE
- Match against plugin codebase
- Flag vulnerable code

### 2. Security Research

Analyze vulnerability trends:
- Common vulnerability patterns
- Fix patterns across plugins
- Evolution of security practices

### 3. Automated Code Review

Integrate into CI/CD:
- Check commits against vulnerability patterns
- Warn about dangerous patterns
- Suggest secure alternatives

### 4. Plugin Security Rating

Rate plugin security:
- Check for known vulnerability patterns
- Identify missing security functions
- Generate security score

## Real-World Examples

### Cross-Site Scripting (XSS)
```php
// Vulnerable
echo $user_data;

// Patched
echo esc_html($user_data);

// Pattern: Missing output escaping
```

### SQL Injection
```php
// Vulnerable
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];

// Patched
$query = $wpdb->prepare("SELECT * FROM users WHERE id = %d", $_GET['id']);

// Pattern: Missing prepared statement
```

### Authorization Bypass
```php
// Vulnerable
function delete_user() {
    wp_delete_user($_POST['user_id']);
}

// Patched
function delete_user() {
    if (!current_user_can('delete_users')) return;
    wp_delete_user($_POST['user_id']);
}

// Pattern: Missing capability check
```

## Advanced Features

### Security Function Detection

Automatically identifies security-relevant changes:
- WordPress: `esc_*`, `sanitize_*`, `wp_nonce_*`, `current_user_can`
- PHP: `htmlspecialchars`, `filter_*`, `password_hash`
- Database: `prepare`, `wpdb`

### Pattern Deduplication

Prevents duplicate patterns:
- Hash-based deduplication
- Structural similarity detection
- Reduces storage and improves performance

### Minimal Diff Extraction

Focuses on actual changes:
- Filters out unchanged code
- Identifies minimal differing subtrees
- Reduces noise in patterns

## Dependencies

```bash
pip install tree-sitter tree-sitter-php
```

## Performance

- **Pattern Extraction**: ~1-5 seconds per CVE
- **AST Parsing**: ~10-50ms per file
- **Pattern Matching**: ~5-20ms per comparison
- **Storage**: ~10-50KB per pattern (simplified AST)

## Roadmap

- [ ] Pattern matching engine for large-scale scanning
- [ ] Fuzzy matching for code variations
- [ ] Web UI for pattern visualization
- [ ] Integration with WordPress.org plugin scanner
- [ ] Machine learning for pattern generalization
- [ ] Real-time vulnerability detection

## Contributing

This is a research project for WordPress security analysis. See the documentation for implementation details.

## License

This project is for security research and educational purposes.

## References

- WordPress Plugins: https://wordpress.org/plugins/
- Wordfence Vulnerability Database: https://www.wordfence.com/threat-intel/
- Tree-sitter: https://tree-sitter.github.io/
- PHP AST: https://github.com/tree-sitter/tree-sitter-php

## Output Examples

### Pattern File Structure

```json
{
  "metadata": {
    "cve": "CVE-2024-9425",
    "plugin_slug": "example-plugin",
    "vuln_type": "Cross-Site Scripting (XSS)"
  },
  "vulnerable_pattern": {
    "code": "echo $classes;",
    "ast": { ... },
    "signature": "echo_statement(variable_name)"
  },
  "patched_pattern": {
    "code": "echo esc_attr($classes);",
    "ast": { ... },
    "signature": "echo_statement(function_call(variable_name))"
  },
  "diffs": [
    {
      "type": "modified",
      "description": "Variable wrapped with esc_attr()",
      "path": ["program", "echo_statement"]
    }
  ],
  "security_functions": {
    "added": ["esc_attr"]
  }
}
```

## Getting Started

1. **Install dependencies**: `pip install tree-sitter tree-sitter-php`
2. **Run demo**: `python demo_ast_diff.py`
3. **Read guide**: [AST_DIFFING_GUIDE.md](AST_DIFFING_GUIDE.md)
4. **Extract patterns**: `python extract_vulnerability_patterns.py`
5. **Build scanner** (coming soon)

## Support

For questions or issues:
- Check the [AST_DIFFING_GUIDE.md](AST_DIFFING_GUIDE.md)
- Run the demo script for examples
- Review the generated pattern files
