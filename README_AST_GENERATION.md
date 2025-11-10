# AST Generation for WordPress Plugins

This document explains how to generate ASTs for all files in the latest releases of WordPress plugins.

## Overview

The `generate_plugin_asts.py` script:
- Finds the latest release tag for each plugin
- Generates ASTs for all PHP files in that release
- Stores them in a structured directory format: `ast_signatures/{plugin-slug}-{version}/`

## Prerequisites

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

## Usage

### 1. Generate ASTs for Top Plugins

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

### 2. Generate ASTs for a Single Plugin

```bash
python generate_plugin_asts.py --plugin akismet
```

### 3. Use Custom Plugin List

```bash
python generate_plugin_asts.py --plugins-file /path/to/custom_plugins.txt --limit 50
```

### 4. Use Custom Output Directory

```bash
python generate_plugin_asts.py --plugin akismet --output-dir /custom/path/ast_signatures
```

## Output Structure

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

## AST File Format

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

## Summary File Format

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

## Command Line Options

```
--plugins-file FILE   File containing plugin slugs (one per line)
                      Default: data/input/top_10k_plugin_slugs.txt

--plugin SLUG         Process a single plugin by slug

--limit N             Limit number of plugins to process

--output-dir PATH     Custom output directory
                      Default: data/output/ast_signatures/

--verbose             Enable verbose logging
```

## Next Steps: Vulnerability Detection

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

## Troubleshooting

### No tags found for plugin
- Ensure the plugin SVN repository is downloaded locally
- Check that the plugin slug is correct
- Verify the SVN_REPOS_DIR path in config

### Cannot find latest version
- Some plugins may not have version tags
- Check the SVN repository structure manually

### Parsing errors
- Some PHP files may have syntax errors
- The script will log errors and continue with other files
- Check verbose output for details

## Statistics

After processing, the script prints:
- Plugins processed successfully
- Plugins failed
- Files processed
- Files failed
- Total ASTs generated
- Output directory path
