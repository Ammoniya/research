# WordPress Vulnerability Research

## Vulnerability Analysis Scripts

```bash
python generate_signatures.py

python generate_ast_signatures.py

python extract_vulnerability_pattern.py --ast-signatures data/output/ast_signatures/ --output-dir data/output/vulnerability_patterns/
```

## Malicious JavaScript Detection

Scan JavaScript files for malicious patterns and security vulnerabilities:

```bash
# Scan diff_results directory (default)
python3 detect_malicious_js.py

# Scan custom directory
python3 detect_malicious_js.py --dir /path/to/js/files

# Generate report
python3 detect_malicious_js.py --output report.txt

# JSON output
python3 detect_malicious_js.py --json --output results.json
```

See [MALICIOUS_JS_DETECTION.md](MALICIOUS_JS_DETECTION.md) for detailed documentation.

### Prepare diff_results Directory

```bash
# Create directory structure
python3 prepare_diff_results.py --create

# Scan directory contents
python3 prepare_diff_results.py --scan
```