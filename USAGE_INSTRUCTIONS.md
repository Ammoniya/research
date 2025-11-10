# Usage Instructions for Pattern Extraction

## Running on Your Local Machine

Based on your file structure at `~/compweb/plugin_svn`, here's how to run the pattern extraction:

### 1. Check Your Signature Files

First, verify one of your signature files has the necessary `pre_patch_code` and `post_patch_code` fields:

```bash
cd ~/compweb/plugin_svn

# Check a signature file structure
python -c "
import json
with open('data/output/signatures/accordions/CVE-2020-13644.json') as f:
    sig = json.load(f)
    print('Keys in signature:', list(sig.keys()))
    print('Has pre_patch_code:', 'pre_patch_code' in sig)
    print('Has post_patch_code:', 'post_patch_code' in sig)
"
```

### 2. Run Pattern Extraction

Run the extraction script pointing to your signature directory:

```bash
# Extract patterns from all signatures
python extract_vulnerability_patterns.py \
    --input-dir data/output/signatures/ \
    --output-dir data/output/vulnerability_patterns/

# Or test with just 10 signatures first
python extract_vulnerability_patterns.py \
    --input-dir data/output/signatures/ \
    --output-dir data/output/vulnerability_patterns/ \
    --limit 10

# Quiet mode (less output)
python extract_vulnerability_patterns.py \
    --input-dir data/output/signatures/ \
    --output-dir data/output/vulnerability_patterns/ \
    --quiet
```

### 3. Check the Output

After running, you should see:

```bash
# View summary
cat data/output/vulnerability_patterns/extraction_summary.json

# See patterns by type
ls data/output/vulnerability_patterns/patterns_*.json

# View a specific pattern
ls data/output/vulnerability_patterns/accordions/
cat data/output/vulnerability_patterns/accordions/CVE-2020-13644_pattern.json | jq .
```

## Expected Signature File Format

Your signature files in `data/output/signatures/` should have this structure:

```json
{
  "cve": "CVE-2024-9425",
  "plugin_slug": "example-plugin",
  "vuln_type": "Cross-Site Scripting (XSS)",
  "title": "XSS vulnerability in example plugin",
  "vulnerable_version": "1.2.3",
  "patched_version": "1.2.4",
  "wordfence_uuid": "...",
  "pre_patch_code": "<?php echo $classes; ?>",
  "post_patch_code": "<?php echo esc_attr($classes); ?>",
  "unified_diff": "...",
  "patch_location": "1.2.3 -> 1.2.4",
  "files_changed": 1,
  "lines_added": 1,
  "lines_removed": 1
}
```

**Critical fields for pattern extraction:**
- `pre_patch_code` - The vulnerable code (REQUIRED)
- `post_patch_code` - The patched code (REQUIRED)

If these fields are missing, the pattern extractor will skip that signature.

## Understanding the Output

### Individual Pattern Files

Located in: `data/output/vulnerability_patterns/[plugin_slug]/[cve]_pattern.json`

Each pattern contains:
- **metadata**: CVE info, plugin, versions
- **vulnerable_pattern**: Pre-patch AST (what to search for)
- **patched_pattern**: Post-patch AST (what to ignore)
- **diffs**: Structural differences between the two
- **security_functions**: Functions added/removed in the patch

### Grouped Pattern Files

Located in: `data/output/vulnerability_patterns/patterns_[type].json`

Patterns grouped by vulnerability type:
- `patterns_cross-site_scripting_(xss).json`
- `patterns_sql_injection.json`
- `patterns_authorization_bypass.json`
- etc.

### Summary File

Located in: `data/output/vulnerability_patterns/extraction_summary.json`

Contains:
- Total signatures processed
- Success/failure counts
- Patterns by vulnerability type
- Unique pattern count

## Common Issues

### Issue 1: "No signature files found"

**Problem**: The input directory is wrong or empty

**Solution**:
```bash
# Check your signatures exist
ls data/output/signatures/ | wc -l

# Use absolute path
python extract_vulnerability_patterns.py \
    --input-dir /full/path/to/data/output/signatures/
```

### Issue 2: "No pre/post patch code found"

**Problem**: Signature files don't have the required code fields

**Solution**:
- Check if your signature generation included these fields
- Run `generate_signatures.py` again if needed
- Or regenerate signatures with the updated code

### Issue 3: "Failed to parse vulnerable code"

**Problem**: The PHP code in the signature is invalid or malformed

**Solution**:
- Check the `pre_patch_code` in the signature file
- Ensure it's valid PHP (starts with `<?php`)
- The script will skip unparseable files and continue

### Issue 4: "No differences found"

**Problem**: Pre and post patch code are identical (shouldn't happen)

**Solution**:
- Check the signature file manually
- This might indicate a bug in signature generation

## Performance Tips

### For Large Datasets

If you have thousands of signatures:

```bash
# Process in batches
python extract_vulnerability_patterns.py \
    --input-dir data/output/signatures/ \
    --limit 100

# Then increase
python extract_vulnerability_patterns.py \
    --input-dir data/output/signatures/ \
    --limit 500

# Finally do all
python extract_vulnerability_patterns.py \
    --input-dir data/output/signatures/
```

### Parallel Processing

For even faster extraction (if you have many signatures):

```bash
# Split signatures by plugin and process in parallel
# (Advanced - requires modifying the script)
```

## Next Steps

After extracting patterns:

1. **Review the patterns**: Check `extraction_summary.json` for stats
2. **Examine by type**: Look at `patterns_*.json` files
3. **Verify quality**: Spot-check a few pattern files
4. **Build scanner**: Use these patterns to scan other plugins

## Example Workflow

```bash
# 1. Navigate to project
cd ~/compweb/plugin_svn

# 2. Test with 5 signatures
python extract_vulnerability_patterns.py \
    --input-dir data/output/signatures/ \
    --output-dir data/output/vulnerability_patterns/ \
    --limit 5

# 3. Check results
cat data/output/vulnerability_patterns/extraction_summary.json

# 4. If looks good, extract all
python extract_vulnerability_patterns.py \
    --input-dir data/output/signatures/ \
    --output-dir data/output/vulnerability_patterns/

# 5. Analyze results
ls data/output/vulnerability_patterns/patterns_*.json
```

## Getting Help

If you encounter issues:

1. Check this file for common issues
2. Run with `--limit 1` to debug single signature
3. Check the signature file format manually
4. Ensure `tree-sitter` and `tree-sitter-php` are installed:
   ```bash
   pip install tree-sitter tree-sitter-php
   ```

## Complete Example

Here's a complete example checking everything:

```bash
cd ~/compweb/plugin_svn

# Check signature count
echo "Total signatures:"
find data/output/signatures/ -name "*.json" -type f | wc -l

# Check one signature format
echo -e "\nSample signature structure:"
python -c "
import json
import glob

# Find first JSON file
files = glob.glob('data/output/signatures/*/*.json')
if files:
    with open(files[0]) as f:
        sig = json.load(f)
        print(f'File: {files[0]}')
        print(f'Keys: {list(sig.keys())}')
        print(f'Has pre_patch_code: {\"pre_patch_code\" in sig}')
        print(f'Has post_patch_code: {\"post_patch_code\" in sig}')
        if 'pre_patch_code' in sig:
            print(f'Pre-patch code length: {len(sig[\"pre_patch_code\"])} chars')
        if 'post_patch_code' in sig:
            print(f'Post-patch code length: {len(sig[\"post_patch_code\"])} chars')
"

# Run extraction on 3 signatures
echo -e "\nRunning extraction (3 signatures test):"
python extract_vulnerability_patterns.py \
    --input-dir data/output/signatures/ \
    --output-dir data/output/vulnerability_patterns/ \
    --limit 3

# Check results
echo -e "\nResults:"
if [ -f "data/output/vulnerability_patterns/extraction_summary.json" ]; then
    cat data/output/vulnerability_patterns/extraction_summary.json | \
        python -m json.tool | head -20
else
    echo "No summary file generated"
fi
```
