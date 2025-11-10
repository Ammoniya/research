# Patch Impact Analysis

This document describes the patch impact analysis system for understanding how one CVE patch relates to another.

## Overview

The patch impact analyzer examines relationships between CVE patches using multiple analysis techniques:

1. **Call Graph Analysis** - Identifies function call relationships and dependencies
2. **Data Flow Analysis** - Tracks variable usage and data flow between patches
3. **Control Flow Graph Analysis** - Analyzes execution paths and control flow changes

## Architecture

### Components

```
patch_impact_analyzer/
├── __init__.py              # Package initialization
├── models.py                # Data models for analysis results
├── php_parser.py            # PHP code parser (regex-based)
├── call_graph.py            # Call graph builder
├── data_flow.py             # Data flow analyzer
├── control_flow.py          # Control flow graph builder
└── impact_analyzer.py       # Main impact analysis coordinator
```

### Data Flow

```
CVE Patch Data (JSON)
       ↓
   PHP Parser
       ↓
   ┌───┴────┬─────────┐
   ↓        ↓         ↓
Call Graph  Data Flow  Control Flow
 Builder    Analyzer    Builder
   ↓        ↓         ↓
   └───┬────┴─────────┘
       ↓
  Impact Analyzer
       ↓
  ImpactAnalysis
   (Results)
```

## Key Concepts

### Call Graph

A **call graph** represents function call relationships:
- **Nodes**: Functions and methods
- **Edges**: Function calls (caller → callee)

Example:
```
function_a()
    ↓ calls
function_b()
    ↓ calls
function_c()
```

The analyzer identifies:
- Shared functions between patches
- Upstream impacts (Patch 1 calls Patch 2 functions)
- Downstream impacts (Patch 2 calls Patch 1 functions)
- Call graph overlap percentage

### Data Flow Graph

A **data flow graph** tracks variable usage and data dependencies:
- **Nodes**: Variable read/write operations
- **Edges**: Data flow between operations
- **Sources**: User input, external data
- **Sinks**: Critical operations (echo, query, eval)
- **Sanitizers**: Security functions (esc_html, sanitize_text_field)

Example:
```
$user_input ← $_GET['id']  (source)
     ↓
$sanitized ← sanitize($user_input)  (sanitizer)
     ↓
echo $sanitized  (sink - safe)
```

The analyzer identifies:
- Shared variables between patches
- Tainted data flows (source → sink without sanitization)
- Data flow chains connecting patches

### Control Flow Graph

A **control flow graph** represents execution paths:
- **Nodes**: Code blocks (statements, conditions, loops)
- **Edges**: Control flow transitions
- **Entry node**: First executable statement
- **Exit nodes**: Return/end statements

Example:
```
    [Entry]
       ↓
   [if condition]
    ↙    ↘
  [then] [else]
    ↘    ↙
    [Exit]
```

The analyzer identifies:
- Execution path changes
- Branching complexity changes
- Structural similarities

## Usage

### Basic Pairwise Analysis

Compare two CVE patches:

```bash
python analyze_patch_impact.py \
    --cve1 data/output/signatures/CVE-2023-1234.json \
    --cve2 data/output/signatures/CVE-2023-5678.json \
    --output results/impact_report.md \
    --verbose
```

### Batch Analysis

Compare all signatures in a directory:

```bash
python analyze_patch_impact.py \
    --signatures-dir data/output/signatures \
    --compare-all \
    --output-dir data/output/impact_analysis \
    --verbose
```

### Example Analysis

Run with example code to test the system:

```bash
python analyze_patch_impact.py --example --verbose
```

### Programmatic Usage

```python
from patch_impact_analyzer import PatchImpactAnalyzer

# Initialize analyzer
analyzer = PatchImpactAnalyzer()

# CVE data structure
cve1_data = {
    'cve': 'CVE-2023-1234',
    'plugin_slug': 'example-plugin',
    'pre_patch_code': '...',  # Vulnerable code
    'post_patch_code': '...',  # Patched code
    'patch_location': 'file.php'
}

cve2_data = {
    'cve': 'CVE-2023-5678',
    # ... similar structure
}

# Analyze impact
impact = analyzer.analyze_patch_impact(cve1_data, cve2_data, verbose=True)

# Access results
print(f"Impact Score: {impact.impact_score}")
print(f"Impact Level: {impact.impact_level}")
print(f"Shared Functions: {len(impact.shared_functions)}")
print(f"Shared Variables: {len(impact.shared_variables)}")

# Generate report
report = analyzer.generate_report(impact, output_file='report.md')
```

## Analysis Metrics

### Impact Score

The **impact score** (0-100) represents the overall relationship strength:

- **0-20**: Minimal impact (independent patches)
- **20-40**: Low impact (some shared code)
- **40-60**: Medium impact (significant overlap)
- **60-80**: High impact (strong dependencies)
- **80-100**: Critical impact (deeply interrelated)

Score calculation:
```
Score = Σ(relationship_confidence × relationship_weight × 100) / Σ(weights)

Weights:
- Function overlap: 0.3
- Variable overlap: 0.2
- Data flow chains: 0.3
- Control flow changes: 0.2
```

### Relationship Types

1. **function_overlap**: Shared functions between patches
   - Indicates patches modify same/related functionality
   - High confidence when >5 shared functions

2. **variable_overlap**: Shared variables
   - Indicates patches work with same data
   - High confidence when >10 shared variables

3. **data_flow_chain**: Connected data flows
   - Indicates variable dependencies between patches
   - High confidence when multiple chains exist

4. **control_flow_change**: Similar execution paths
   - Indicates structural similarities
   - High confidence when >50% structural similarity

## Output Format

### Markdown Report

The analyzer generates detailed markdown reports:

```markdown
# Patch Impact Analysis: CVE-2023-1234 → CVE-2023-5678

## Overall Impact

- **Impact Score**: 65.00/100
- **Impact Level**: HIGH

## Code Overlap

- **Shared Functions**: 8
- **Shared Variables**: 12
- **Call Graph Overlap**: 45.0%

### Shared Functions

- `process_user_input(user_id)`
- `validate_permissions()`
- ...

## Call Graph Relationships

### Upstream Impact (CVE-1 calls CVE-2 functions)

- process_data() -> sanitize_input()
- ...

## Data Flow Relationships

Found 3 data flow chain(s) connecting the patches.

### Chain 1

$_GET['id'] → $user_id → $query

## Detailed Relationships

### 1. Function Overlap

- **Description**: Found 8 shared functions between patches
- **Confidence**: 0.80
- **Evidence**:
  - Shared function: process_user_input(user_id)
  - ...
```

### JSON Output

For batch analysis, results are saved as JSON:

```json
{
  "total_cves": 10,
  "comparisons": [
    {
      "cve1": "CVE-2023-1234",
      "cve2": "CVE-2023-5678",
      "impact_score": 65.0,
      "impact_level": "HIGH",
      "shared_functions": 8,
      "shared_variables": 12,
      "relationships": 4
    }
  ],
  "high_impact_pairs": [
    {
      "pair": "CVE-2023-1234 <-> CVE-2023-5678",
      "score": 65.0,
      "level": "HIGH"
    }
  ],
  "summary": {
    "average_impact_score": 42.5,
    "max_impact_score": 65.0,
    "high_impact_count": 1,
    "total_comparisons": 45
  }
}
```

## Interpretation Guide

### High Impact Relationships

When patches show **high impact** (score ≥ 60):

1. **Investigate temporal ordering**
   - Did one patch introduce code that the other patches?
   - Are they addressing related vulnerabilities?

2. **Check for incomplete fixes**
   - Did the first patch miss something?
   - Is the second patch a follow-up fix?

3. **Analyze function dependencies**
   - Review upstream/downstream impacts
   - Identify critical function chains

4. **Examine data flows**
   - Check if both patches sanitize the same inputs
   - Verify security properties are maintained

### Medium Impact Relationships

When patches show **medium impact** (40-60):

1. **Review shared code areas**
   - Same files or related functionality
   - Potential for code refactoring

2. **Check variable usage**
   - Are they working with same data structures?
   - Any shared security-sensitive variables?

### Low/Minimal Impact

When patches show **low impact** (<40):

- Patches likely address independent issues
- Limited code/data overlap
- Can be treated as separate concerns

## Temporal Analysis

For chronologically ordered CVEs, use `analyze_temporal_impact()`:

```python
# Analyze how earlier patch affects later patch
temporal_impact = analyzer.analyze_temporal_impact(
    earlier_cve=cve1_data,
    later_cve=cve2_data,
    verbose=True
)

# Check code continuity
if temporal_impact['code_continuity'] > 0.7:
    print("Later patch likely builds on earlier patch")
```

## Limitations

### Current Limitations

1. **Regex-based parsing**: Not a full PHP AST parser
   - May miss complex syntax
   - Limited handling of nested structures

2. **Intra-procedural analysis**: Limited cross-file analysis
   - Analyzes individual functions
   - May miss global dependencies

3. **Simplified data flow**: Basic taint tracking
   - No path-sensitive analysis
   - Limited interprocedural flow

4. **Heuristic-based**: Pattern matching for security functions
   - May have false positives/negatives
   - WordPress-specific patterns

### Future Enhancements

Potential improvements:

1. **Full AST parsing**: Use php-parser or similar
2. **Interprocedural analysis**: Cross-function data flow
3. **Path-sensitive analysis**: Consider execution conditions
4. **Machine learning**: Train models on known relationships
5. **Visualization**: Generate graphical representations

## Examples

### Example 1: SQL Injection Patches

**CVE-1** (Vulnerable):
```php
function get_user($id) {
    global $wpdb;
    $query = "SELECT * FROM users WHERE id = $id";
    return $wpdb->get_row($query);
}
```

**CVE-2** (Patch):
```php
function get_user($id) {
    global $wpdb;
    $id = intval($id);
    $query = $wpdb->prepare("SELECT * FROM users WHERE id = %d", $id);
    return $wpdb->get_row($query);
}
```

**Impact Analysis**:
- Shared functions: `get_user`
- Shared variables: `id`, `query`, `wpdb`
- Data flow: `$id` sanitized with `intval()`
- Impact: HIGH (same function, security fix)

### Example 2: XSS Patches

**CVE-1** (Vulnerable):
```php
function display_message($msg) {
    echo $msg;
}
```

**CVE-2** (Patch):
```php
function display_message($msg) {
    echo esc_html($msg);
}
```

**Impact Analysis**:
- Shared functions: `display_message`
- Shared variables: `msg`
- Data flow: `$msg` sanitized with `esc_html()`
- Impact: HIGH (same function, output escaping added)

## Integration with Existing Pipeline

The patch impact analyzer integrates with the existing research pipeline:

```
Phase 1: Signature Generation (generate_signatures.py)
    ↓
    Signatures saved to data/output/signatures/
    ↓
Patch Impact Analysis (analyze_patch_impact.py)
    ↓
    Impact analysis saved to data/output/impact_analysis/
    ↓
Phase 2: Vulnerability Mining (mine_vulnerability_clones.py)
    (can use impact analysis to prioritize targets)
```

## References

- **Call Graphs**: Aho et al., "Compilers: Principles, Techniques, and Tools"
- **Data Flow Analysis**: Khedker et al., "Data Flow Analysis: Theory and Practice"
- **Control Flow Graphs**: Allen, "Control Flow Analysis"
- **Taint Analysis**: Schwartz et al., "All You Ever Wanted to Know About Dynamic Taint Analysis"

## Contact

For questions or issues with patch impact analysis, please open an issue on GitHub.
