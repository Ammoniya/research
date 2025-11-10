# WordPress Vulnerability Pattern Extraction

A comprehensive toolkit for extracting, analyzing, and matching vulnerability patterns in WordPress plugins using Abstract Syntax Tree (AST) analysis.

## Overview

This project enables large-scale vulnerability detection in WordPress plugins by:

1. **Extracting** vulnerability patches from CVE data
2. **Analyzing** differences using AST diffing
3. **Generating** reusable vulnerability patterns
4. **Scanning** plugins for vulnerability clones

## Table of Contents

- [Key Features](#key-features)
- [Quick Start](#quick-start)
- [AST Generation for WordPress Plugins](#ast-generation-for-wordpress-plugins)
- [Example: XSS Vulnerability (CVE-2024-9425)](#example-xss-vulnerability-cve-2024-9425)
- [Project Structure](#project-structure)
- [Documentation](#documentation)
- [Architecture](#architecture)
- [Use Cases](#use-cases)
- [Real-World Examples](#real-world-examples)
- [Advanced Features](#advanced-features)
- [Dependencies](#dependencies)
- [Performance](#performance)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [References](#references)
- [Support](#support)

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

## AST Generation for WordPress Plugins

### Overview

The `generate_plugin_asts.py` script allows you to:
- Find the latest release tag for each plugin
- Generate ASTs for all PHP files in that release
- Store them in a structured directory format: `ast_signatures/{plugin-slug}-{version}/`

### Prerequisites

1. **WordPress.org SVN repositories** must be downloaded locally:
   - Default location: `/home/ravindu/compweb/svn_wordpress_org/`
   - Or set custom location via `SVN_REPOS_DIR` environment variable
   - Each plugin should have structure: `{svn_dir}/{plugin-slug}/tags/{version}/`

2. **Python dependencies**:
   ```bash
   pip install tree-sitter tree-sitter-php
   ```

3. **Initial setup**:
   ```bash
   # Ensure data directories are created
   python -c "from data_paths import ensure_data_directories; ensure_data_directories()"
   ```

### Setting Up SVN Repositories

If you don't have the SVN repositories yet, you can either:

**Option 1: Use custom SVN directory**
```bash
export SVN_REPOS_DIR=/path/to/your/svn/repos
python generate_plugin_asts.py --plugin your-plugin
```

**Option 2: Download specific plugins**
```bash
# Create a directory for SVN repos
mkdir -p ~/wordpress-svn

# Download a specific plugin
svn checkout https://plugins.svn.wordpress.org/akismet/ ~/wordpress-svn/akismet

# Set the environment variable
export SVN_REPOS_DIR=~/wordpress-svn
```

**Option 3: Mirror entire WordPress.org plugin repository (requires significant disk space)**
```bash
# This will download ALL plugins - only do this if you have hundreds of GB available
rsync -avz --delete plugins.svn.wordpress.org::plugin-repository /path/to/svn_wordpress_org/
```

### Usage

#### Generate ASTs for Top Plugins

First, fetch the list of top plugins:
```bash
python utils/fetch_plugins.py
```

Then generate ASTs for all (or limited number of) plugins:
```bash
# Process all plugins from the list
python generate_plugin_asts.py

# Process only first 10 plugins
python generate_plugin_asts.py --limit 10

# Process with verbose logging
python generate_plugin_asts.py --limit 5 --verbose
```

#### Generate ASTs for a Single Plugin

```bash
python generate_plugin_asts.py --plugin akismet
```

#### Use Custom Plugin List

```bash
python generate_plugin_asts.py --plugins-file /path/to/custom_plugins.txt --limit 50
```

#### Use Custom Output Directory

```bash
python generate_plugin_asts.py --plugin akismet --output-dir /custom/path/ast_signatures
```

### Output Structure

The script creates the following directory structure:

```
data/output/ast_signatures/
├── akismet-5.3/
│   ├── akismet.php.json
│   ├── class.akismet.php.json
│   ├── class.akismet-admin.php.json
│   ├── views_config.php.json
│   ├── includes_helper.php.json
│   └── _summary.json
├── jetpack-13.1/
│   ├── jetpack.php.json
│   ├── class.jetpack.php.json
│   └── _summary.json
└── ...
```

Each directory is named `{plugin-slug}-{version}` and contains:
- **Individual AST files**: One JSON file per PHP file (path separators replaced with underscores)
- **_summary.json**: Metadata about the generation process

### AST File Format

Each AST JSON file contains:

```json
{
  "ast": {
    "type": "program",
    "children": [...]
  },
  "functions": [
    {
      "name": "akismet_init",
      "start_line": 10,
      "end_line": 25,
      "ast": {...}
    }
  ],
  "file_size": 12345,
  "parse_timestamp": "2025-11-10T12:30:45.123456",
  "plugin_slug": "akismet",
  "version": "5.3",
  "file_path": "class.akismet.php",
  "absolute_path": "/home/ravindu/compweb/svn_wordpress_org/akismet/tags/5.3/class.akismet.php"
}
```

### Summary File Format

The `_summary.json` file contains:

```json
{
  "plugin_slug": "akismet",
  "version": "5.3",
  "total_files": 42,
  "asts_generated": 42,
  "generation_timestamp": "2025-11-10T12:35:00.123456",
  "output_directory": "/home/user/research/data/output/ast_signatures/akismet-5.3"
}
```

### Command Line Options

```
--plugins-file FILE   File containing plugin slugs (one per line)
                      Default: data/input/top_10k_plugin_slugs.txt

--plugin SLUG         Process a single plugin by slug

--limit N             Limit number of plugins to process

--output-dir PATH     Custom output directory
                      Default: data/output/ast_signatures/

--verbose             Enable verbose logging
```

### Vulnerability Detection Workflow

Once ASTs are generated, you can use them to detect vulnerabilities by:

1. **Loading Generated ASTs**: Read the AST files for a plugin
2. **Loading Vulnerability Signatures**: Load known vulnerability signatures from `data/output/ast_signatures/{plugin}/`
3. **Matching Patterns**: Use `ASTDiffer` and `ASTNormalizer` to compare generated ASTs against vulnerability signatures
4. **Reporting Matches**: Flag files/functions that match known vulnerable patterns

Example workflow:
```python
from wordpress_vulnerability_analyzer.ast_differ import ASTDiffer
from wordpress_vulnerability_analyzer.ast_normalizer import ASTNormalizer

# Load generated AST for a plugin file
with open('ast_signatures/plugin-1.0/file.php.json') as f:
    plugin_ast = json.load(f)

# Load vulnerability signature
with open('ast_signatures/plugin/CVE-2024-1234_ast.json') as f:
    vuln_signature = json.load(f)

# Compare and detect matches
differ = ASTDiffer()
normalizer = ASTNormalizer()

# Check if plugin AST matches vulnerable pattern
matches = normalizer.compare_security_functions(
    plugin_ast['ast'],
    vuln_signature['vulnerable_pattern']
)

if matches:
    print(f"Potential vulnerability detected!")
```

### Troubleshooting

**No tags found for plugin**
- Ensure the plugin SVN repository is downloaded locally
- Check that the plugin slug is correct
- Verify the SVN_REPOS_DIR path in config

**Cannot find latest version**
- Some plugins may not have version tags
- Check the SVN repository structure manually

**Parsing errors**
- Some PHP files may have syntax errors
- The script will log errors and continue with other files
- Check verbose output for details

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
├── generate_plugin_asts.py              # Generate ASTs for plugins
├── AST_DIFFING_GUIDE.md                # Comprehensive guide
│
├── wordpress_vulnerability_analyzer/    # Core library
│   ├── ast_parser.py                   # PHP AST parser
│   ├── ast_differ.py                   # AST comparison
│   ├── ast_signature_generator.py      # Signature generation
│   ├── ast_normalizer.py               # AST normalization
│   ├── models.py                       # Data models
│   └── ...                             # Other components
│
├── signatures/                          # CVE signatures (generated)
├── vulnerability_patterns/              # Extracted patterns (generated)
├── data/
│   ├── input/
│   │   └── top_10k_plugin_slugs.txt   # Top plugins list
│   └── output/
│       └── ast_signatures/             # Generated ASTs for plugins
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
4. **Generate plugin ASTs**: `python generate_plugin_asts.py --plugin akismet`
5. **Extract patterns**: `python extract_vulnerability_patterns.py`
6. **Build scanner** (coming soon)

## Support

For questions or issues:
- Check the [AST_DIFFING_GUIDE.md](AST_DIFFING_GUIDE.md)
- Run the demo script for examples
- Review the generated pattern files
