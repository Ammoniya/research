# AST-Based Vulnerability Signatures

This document describes the AST (Abstract Syntax Tree) signature generation system for WordPress plugin vulnerabilities.

## Overview

The AST signature system parses PHP code from CVE patches into structured abstract syntax trees, then compares vulnerable and patched versions to identify the minimal code changes that represent the vulnerability pattern.

## Architecture

### Components

1. **models.py** - Extended with AST data structures:
   - `ASTNode`: Represents a node in the abstract syntax tree
   - `ASTDiff`: Represents a difference between two AST nodes
   - `ASTSignature`: Complete AST-based signature for a vulnerability

2. **ast_parser.py** - PHP AST Parser using tree-sitter:
   - Parses PHP code into AST structures
   - Extracts functions and classes
   - Simplifies ASTs for storage

3. **ast_differ.py** - AST Comparison Engine:
   - Compares two ASTs and finds differences
   - Identifies minimal differing subtrees
   - Filters security-relevant changes

4. **ast_signature_generator.py** - Main Orchestrator:
   - Coordinates the entire pipeline
   - Generates signatures from code or unified diffs
   - Saves signatures to disk

5. **generate_ast_signatures.py** - CLI Script:
   - Command-line interface for generating AST signatures
   - Supports batch processing
   - Progress tracking and statistics

### Data Flow

```
CVE JSON / Signature Files
          ↓
Extract unified_diff
          ↓
Parse pre_patch_code → Vulnerable AST
Parse post_patch_code → Patched AST
          ↓
Diff ASTs → Find minimal differences
          ↓
Generate ASTSignature
          ↓
Save to data/output/ast_signatures/{plugin_slug}/{CVE}_ast.json
```

## Usage

### Generate AST Signatures from Existing Signatures

```bash
# Process all existing signatures
python3 generate_ast_signatures.py --input-dir data/output/signatures

# Process with verbose output
python3 generate_ast_signatures.py --input-dir data/output/signatures --verbose

# Limit to first 10
python3 generate_ast_signatures.py --input-dir data/output/signatures --limit 10
```

### Generate AST Signatures from CVE JSON

```bash
# Process CVEs from JSON file
python3 generate_ast_signatures.py --input-json data/input/plugin_vulnerabilities.json

# Process specific file with limit
python3 generate_ast_signatures.py --input-json mycves.json --limit 5 --verbose
```

### Programmatic Usage

```python
from wordpress_vulnerability_analyzer.ast_signature_generator import ASTSignatureGenerator

# Create generator
generator = ASTSignatureGenerator(verbose=True)

# Generate from code
signature = generator.generate_from_code(
    cve="CVE-2024-12345",
    plugin_slug="my-plugin",
    vuln_type="Cross-Site Scripting (XSS)",
    title="XSS in user input",
    vulnerable_code="<?php echo $_GET['input']; ?>",
    patched_code="<?php echo esc_html($_GET['input']); ?>",
    vulnerable_version="1.0.0",
    patched_version="1.0.1"
)

# Save signature
from data_paths import OUTPUT_AST_SIGNATURES_DIR
generator.save_signature(signature, OUTPUT_AST_SIGNATURES_DIR)
```

## Output Format

AST signatures are saved as JSON files with the following structure:

```json
{
  "cve": "CVE-2024-12345",
  "plugin_slug": "my-plugin",
  "vuln_type": "Cross-Site Scripting (XSS)",
  "title": "XSS in user input",
  "vulnerable_version": "1.0.0",
  "patched_version": "1.0.1",
  "file_path": "includes/ajax.php",

  "vulnerable_ast": {
    "node_type": "program",
    "text": "...",
    "children": [...]
  },

  "patched_ast": {
    "node_type": "program",
    "text": "...",
    "children": [...]
  },

  "minimal_diffs": [
    {
      "diff_type": "added",
      "vulnerable_node": {...},
      "patched_node": {...},
      "path": ["program", "function_definition", "compound_statement"],
      "description": "Node added: function_call_expression"
    }
  ],

  "vulnerable_code": "<?php echo $_GET['input']; ?>",
  "patched_code": "<?php echo esc_html($_GET['input']); ?>",
  "extracted_at": "2024-11-10T12:34:56",
  "references": ["https://..."]
}
```

## Storage Structure

```
data/output/ast_signatures/
├── plugin-slug-1/
│   ├── CVE-2021-12345_ast.json
│   ├── CVE-2022-67890_ast.json
│   └── ...
├── plugin-slug-2/
│   ├── CVE-2023-11111_ast.json
│   └── ...
└── ...
```

## Key Features

### 1. AST Parsing
- Uses tree-sitter with PHP grammar
- Handles partial/invalid code gracefully
- Preserves source locations and structure

### 2. AST Diffing
- Identifies added, removed, and modified nodes
- Finds minimal differing subtrees
- Filters security-relevant changes (nonce checks, sanitization, etc.)

### 3. Signature Storage
- Stores both full ASTs and minimal diffs
- Includes original source code for reference
- JSON format for easy querying and analysis

### 4. Batch Processing
- Process entire directories of signatures
- Resume capability via progress tracking
- Detailed statistics and error reporting

## Dependencies

- **tree-sitter**: Fast, robust parser generator
- **tree-sitter-php**: PHP grammar for tree-sitter

Install with:
```bash
pip3 install tree-sitter tree-sitter-php
```

## Testing

Run the test suite to verify the system:

```bash
python3 test_ast_signatures.py
```

This tests:
- XSS vulnerability signature generation
- SQL injection signature generation
- AST parsing and diffing
- Signature storage

## Use Cases

### 1. Pattern Matching
Search for similar vulnerability patterns across plugins by comparing AST structures.

### 2. Vulnerability Detection
Match AST patterns from known vulnerabilities against target codebases to find similar issues.

### 3. Impact Analysis
Analyze the structural changes made to fix vulnerabilities to understand their severity and scope.

### 4. Clone Detection
Find vulnerability clones by matching AST patterns rather than exact code.

### 5. Security Research
Study common vulnerability patterns and fix patterns at the syntactic level.

## Limitations

- Only processes PHP files (`.php` extension)
- Requires valid unified diff format
- AST simplification may lose some detail (configurable depth)
- Field names may not be preserved for all node types

## Future Enhancements

- [ ] Support for other languages (JavaScript, Python)
- [ ] AST similarity scoring for pattern matching
- [ ] Integration with static analysis tools
- [ ] Visualization of AST diffs
- [ ] Machine learning on AST patterns

## References

- tree-sitter: https://tree-sitter.github.io/
- tree-sitter-php: https://github.com/tree-sitter/tree-sitter-php
- PHP Language Specification: https://www.php.net/manual/
