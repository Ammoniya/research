# Patch Impact Analysis - Usage Guide

This guide shows you how to use the patch impact analyzer with your generated signatures.

## Your Current Setup

Based on your `generate_signatures.py` output, your signatures are:

- **Format**: Markdown (`.md` files)
- **Location**: `data/output/signatures/<plugin-name>/<CVE-ID>.md`
- **Structure**: Each plugin has its own subdirectory

Example paths from your output:
```
data/output/signatures/rsvp/CVE-2022-1054.md
data/output/signatures/wpdiscuz/CVE-2023-47185.md
data/output/signatures/gallery-portfolio/CVE-2023-32585.md
```

## Usage Scenarios

### 1. Compare Two Specific CVEs

To compare two CVE patches from your generated signatures:

```bash
python analyze_patch_impact.py \
    --cve1 data/output/signatures/rsvp/CVE-2022-1054.md \
    --cve2 data/output/signatures/rsvp/CVE-2017-18563.md \
    --output results/rsvp_impact_analysis.md \
    --verbose
```

This will:
- Load both markdown signature files
- Analyze function calls, data flows, and control flow
- Calculate impact score (0-100)
- Generate a detailed markdown report

### 2. Compare CVEs from Different Plugins

```bash
python analyze_patch_impact.py \
    --cve1 data/output/signatures/rsvp/CVE-2022-1054.md \
    --cve2 data/output/signatures/wpdiscuz/CVE-2023-47185.md \
    --output results/cross_plugin_analysis.md
```

### 3. Batch Analysis - Compare All Signatures

To compare all your generated signatures and find relationships:

```bash
python analyze_patch_impact.py \
    --signatures-dir data/output/signatures \
    --compare-all \
    --output-dir data/output/impact_analysis \
    --verbose
```

This will:
- Recursively find all `.md` files in `data/output/signatures/`
- Perform pairwise comparisons between all CVEs
- Identify high-impact relationships (score ≥ 60)
- Save results to `data/output/impact_analysis/patch_impact_analysis.json`

**Note**: With 18 signatures, this will perform (18 × 17) / 2 = 153 comparisons

### 4. Analyze Same-Plugin CVEs

To focus on CVEs within a single plugin:

```bash
python analyze_patch_impact.py \
    --signatures-dir data/output/signatures/rsvp \
    --compare-all \
    --output-dir results/rsvp_internal_analysis
```

## Understanding the Output

### Impact Score (0-100)

- **0-20 (NONE/LOW)**: CVEs are independent, minimal code overlap
- **20-40 (LOW)**: Some shared code, limited interaction
- **40-60 (MEDIUM)**: Significant overlap, related functionality
- **60-80 (HIGH)**: Strong dependencies, likely related fixes
- **80-100 (CRITICAL)**: Deeply interrelated, possible incomplete fix

### Example Output

```
============================================================
Patch Impact Analysis: CVE-2022-1054 → CVE-2017-18563
============================================================

Impact Score: 65.00/100
Impact Level: HIGH

Shared Functions: 5
  - process_rsvp_submission()
  - validate_user_input()
  - sanitize_email_field()

Shared Variables: 8
  - $user_email
  - $rsvp_data
  - $submission_id

Call Graph Overlap: 62.0%

Key Relationships:
  1. function_overlap: Found 5 shared functions (confidence: 0.50)
  2. data_flow_chain: Found 3 data flow chains (confidence: 0.60)
  3. control_flow_change: Similar control flow (confidence: 0.75)
```

### Report Contents

The generated markdown report includes:

1. **Overall Impact**: Score and level
2. **Code Overlap**: Functions, variables, files
3. **Call Graph Relationships**: Upstream/downstream impacts
4. **Data Flow Relationships**: Variable flow chains
5. **Control Flow Changes**: Execution path modifications
6. **Detailed Relationships**: Evidence and confidence scores

## Real-World Examples from Your Data

### Example 1: Temporal Analysis

Since you have multiple CVEs for the same plugin (e.g., RSVP has CVE-2022-1054, CVE-2017-18563), you can analyze how earlier patches affect later ones:

```bash
# Compare earlier CVE to later CVE
python analyze_patch_impact.py \
    --cve1 data/output/signatures/rsvp/CVE-2017-18563.md \
    --cve2 data/output/signatures/rsvp/CVE-2022-1054.md \
    --output results/rsvp_temporal_analysis.md
```

**Interpretation**:
- High impact score → Later patch likely addresses issues missed by earlier patch
- Shared functions → Both patches fix the same code area
- Data flow chains → Both patches sanitize the same variables

### Example 2: Cross-Plugin Analysis

Compare similar vulnerability types across plugins:

```bash
# Compare two Missing Authorization vulnerabilities
python analyze_patch_impact.py \
    --cve1 data/output/signatures/gallery-portfolio/CVE-2023-32585.md \
    --cve2 data/output/signatures/advanced-post-block/CVE-2024-0908.md \
    --output results/missing_auth_comparison.md
```

**Use Case**: Identify common patterns in how different plugins fix the same vulnerability type

### Example 3: Find Related Fixes

Find all CVE pairs with high impact scores:

```bash
python analyze_patch_impact.py \
    --signatures-dir data/output/signatures \
    --compare-all \
    --output-dir data/output/impact_analysis

# Then check the JSON output for high-impact pairs
cat data/output/impact_analysis/patch_impact_analysis.json | jq '.high_impact_pairs'
```

## Programmatic Usage

For custom analysis in Python:

```python
from pathlib import Path
from patch_impact_analyzer import PatchImpactAnalyzer
import json

# Load your markdown signature
def load_md_signature(path):
    # Your markdown files are automatically parsed
    with open(path) as f:
        content = f.read()
    # Extract code sections...
    return signature_dict

# Initialize analyzer
analyzer = PatchImpactAnalyzer()

# Load your signatures
cve1_path = Path("data/output/signatures/rsvp/CVE-2022-1054.md")
cve2_path = Path("data/output/signatures/rsvp/CVE-2017-18563.md")

# The script handles markdown parsing automatically
# Just use the command-line tool for your analysis

# Or use the Python API directly:
from analyze_patch_impact import load_cve_signature

cve1_data = load_cve_signature(cve1_path)
cve2_data = load_cve_signature(cve2_path)

impact = analyzer.analyze_patch_impact(cve1_data, cve2_data, verbose=True)

print(f"Impact Score: {impact.impact_score:.2f}")
print(f"Shared Functions: {len(impact.shared_functions)}")

# Generate report
report = analyzer.generate_report(impact, output_file="custom_report.md")
```

## Tips for Your Research

1. **Start Small**: Begin with same-plugin comparisons to understand the tool
2. **Focus on High Scores**: Investigate pairs with scores ≥ 60 first
3. **Check Temporal Order**: For same-plugin CVEs, check if later patches address earlier issues
4. **Look for Patterns**: Use batch analysis to find common vulnerability patterns
5. **Verify Findings**: High impact scores suggest manual code review is warranted

## Troubleshooting

### No Signatures Found

```
Error: Need at least 2 signatures for comparison. Found 0
```

**Solution**:
- Ensure you're pointing to the correct directory
- The tool now searches recursively and supports `.md` files
- Check: `ls -R data/output/signatures/`

### Empty Code Sections

If impact analysis shows zero relationships:
- Check that your markdown files have code blocks
- Verify the sections are titled "Pre-Patch Code" and "Post-Patch Code"
- Ensure code blocks are wrapped with ` ```php ` or ` ``` `

### Memory Issues with Large Batch Analysis

For very large signature sets:
- Process plugins individually first
- Use `--max-signatures` flag (if implemented)
- Filter by vulnerability type before analysis

## Next Steps

1. **Generate more signatures**: Continue running `generate_signatures.py`
2. **Run batch analysis**: Get overview of all relationships
3. **Investigate high-impact pairs**: Focus on scores ≥ 60
4. **Document findings**: Use generated markdown reports
5. **Validate manually**: Verify high-impact relationships in actual code

## Questions?

- Check `docs/PATCH_IMPACT_ANALYSIS.md` for detailed documentation
- See `patch_impact_analyzer/README.md` for API reference
- Run `python analyze_patch_impact.py --help` for all options
