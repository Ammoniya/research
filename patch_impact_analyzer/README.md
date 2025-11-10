# Patch Impact Analyzer

A comprehensive analysis framework for understanding relationships between CVE patches through call graph analysis, data flow tracking, and control flow comparison.

## Features

- **Call Graph Analysis**: Build and compare function call relationships
- **Data Flow Tracking**: Trace variable usage and identify tainted data flows
- **Control Flow Analysis**: Analyze execution paths and branching complexity
- **Impact Scoring**: Quantitative measure of patch relationships (0-100)
- **Security Analysis**: Detect sources, sinks, and sanitization patterns
- **Temporal Analysis**: Understand how earlier patches affect later ones

## Quick Start

### Installation

The package is part of the WordPress Vulnerability Research project:

```bash
cd /home/user/research
# No additional dependencies required - uses standard library
```

### Basic Usage

```python
from patch_impact_analyzer import PatchImpactAnalyzer

# Initialize analyzer
analyzer = PatchImpactAnalyzer()

# Prepare CVE data
cve1_data = {
    'cve': 'CVE-2023-1234',
    'plugin_slug': 'example-plugin',
    'post_patch_code': '<?php ... ?>',
    'patch_location': 'file.php'
}

cve2_data = {
    'cve': 'CVE-2023-5678',
    'plugin_slug': 'example-plugin',
    'post_patch_code': '<?php ... ?>',
    'patch_location': 'file.php'
}

# Analyze impact
impact = analyzer.analyze_patch_impact(cve1_data, cve2_data)

print(f"Impact Score: {impact.impact_score:.2f}")
print(f"Impact Level: {impact.impact_level}")
print(f"Shared Functions: {len(impact.shared_functions)}")
```

### Command Line

```bash
# Pairwise comparison
python analyze_patch_impact.py \
    --cve1 data/output/signatures/CVE-1.json \
    --cve2 data/output/signatures/CVE-2.json \
    --output results/impact.md

# Batch analysis
python analyze_patch_impact.py \
    --signatures-dir data/output/signatures \
    --compare-all \
    --output-dir data/output/impact_analysis

# Run example
python analyze_patch_impact.py --example
```

## Components

### PHPCodeParser

Parses PHP code to extract functions, variables, and calls:

```python
from patch_impact_analyzer import PHPCodeParser

parser = PHPCodeParser()
parsed = parser.parse_code(php_code, 'file.php')

print(f"Functions: {len(parsed['functions'])}")
print(f"Function calls: {len(parsed['calls'])}")
print(f"Variables: {len(parsed['variables'])}")
```

### CallGraphBuilder

Builds call graphs showing function relationships:

```python
from patch_impact_analyzer import CallGraphBuilder

builder = CallGraphBuilder()
call_graph = builder.build_call_graph(php_code, 'file.php')

# Get all functions
functions = call_graph.get_all_functions()

# Get function dependencies
for func in functions:
    callees = call_graph.get_callees(func)
    callers = call_graph.get_callers(func)
    print(f"{func} calls: {callees}")
    print(f"{func} called by: {callers}")
```

### DataFlowAnalyzer

Analyzes variable data flows and detects tainted data:

```python
from patch_impact_analyzer import DataFlowAnalyzer

analyzer = DataFlowAnalyzer()
data_flow = analyzer.build_data_flow_graph(php_code, 'file.php')

# Find tainted flows
tainted_paths = analyzer.analyze_tainted_flows(data_flow)

for path in tainted_paths:
    print("Tainted flow detected:")
    for node in path:
        print(f"  {node.variable} at line {node.location.line_number}")
```

### ControlFlowGraphBuilder

Builds control flow graphs showing execution paths:

```python
from patch_impact_analyzer import ControlFlowGraphBuilder

builder = ControlFlowGraphBuilder()
cfg = builder.build_control_flow_graph(php_code, 'file.php')

# Get execution paths
paths = builder.get_execution_paths(cfg, max_paths=10)
print(f"Found {len(paths)} execution paths")

# Visualize
print(builder.visualize_cfg(cfg))
```

## Data Models

### ImpactAnalysis

Result of patch impact comparison:

```python
@dataclass
class ImpactAnalysis:
    cve1: str
    cve2: str

    # Overlaps
    shared_functions: List[str]
    shared_variables: List[str]
    shared_files: List[str]

    # Call graph
    call_graph_overlap: float
    upstream_impacts: List[str]
    downstream_impacts: List[str]

    # Data flow
    data_flow_chains: List[List[str]]
    tainted_variables: List[str]

    # Control flow
    control_flow_changes: List[str]

    # Overall metrics
    impact_score: float  # 0-100
    impact_level: str    # NONE, LOW, MEDIUM, HIGH, CRITICAL

    relationships: List[ImpactRelationship]
```

### ImpactRelationship

Individual relationship between patches:

```python
@dataclass
class ImpactRelationship:
    relationship_type: str  # function_overlap, variable_overlap, etc.
    description: str
    confidence: float  # 0.0 to 1.0
    evidence: List[str]
    locations: List[CodeLocation]
```

## Analysis Workflow

1. **Parse Code**: Extract functions, variables, calls from PHP
2. **Build Graphs**:
   - Call graph: function → function edges
   - Data flow graph: variable usage nodes and edges
   - Control flow graph: execution path nodes and edges
3. **Compare Graphs**: Find overlaps and relationships
4. **Score Impact**: Calculate weighted impact score
5. **Generate Report**: Create markdown report with findings

## Security Patterns

The analyzer recognizes WordPress security patterns:

### Sources (User Input)
- `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`
- `get_query_var()`, `get_option()`, `get_post_meta()`

### Sinks (Critical Operations)
- `echo`, `print`, `eval`, `system`, `exec`
- `wpdb->query()`, `file_put_contents()`

### Sanitizers (Security Functions)
- `sanitize_text_field()`, `esc_html()`, `esc_attr()`
- `intval()`, `absint()`, `wp_kses()`

## Impact Score Interpretation

- **0-20 (NONE/LOW)**: Independent patches, minimal overlap
- **20-40 (LOW)**: Some shared code, limited interaction
- **40-60 (MEDIUM)**: Significant overlap, related functionality
- **60-80 (HIGH)**: Strong dependencies, related fixes
- **80-100 (CRITICAL)**: Deeply interrelated, potential incomplete fix

## Example Output

```
============================================================
Patch Impact Analysis: CVE-2023-1234 → CVE-2023-5678
============================================================

Overall Impact
- Impact Score: 65.00/100
- Impact Level: HIGH

Code Overlap
- Shared Functions: 8
- Shared Variables: 12
- Call Graph Overlap: 45.0%

Call Graph Relationships
Upstream Impact (CVE-1 calls CVE-2 functions)
- process_data() -> sanitize_input()
- validate_user() -> check_permissions()

Data Flow Relationships
Found 3 data flow chain(s) connecting the patches.

Detailed Relationships
1. Function Overlap
   Description: Found 8 shared functions between patches
   Confidence: 0.80
   Evidence:
     - Shared function: process_user_input()
     - Shared function: validate_permissions()
```

## Advanced Usage

### Temporal Analysis

Analyze how an earlier patch affects a later patch:

```python
temporal_impact = analyzer.analyze_temporal_impact(
    earlier_cve=cve1_data,
    later_cve=cve2_data
)

print(f"Code continuity: {temporal_impact['code_continuity']:.2%}")
print(f"Note: {temporal_impact['note']}")
```

### Batch Analysis

Compare multiple patches:

```python
signatures = [cve1_data, cve2_data, cve3_data, ...]

results = analyzer.compare_multiple_patches(
    signatures,
    output_dir=Path('results'),
    verbose=True
)

print(f"Average impact: {results['summary']['average_impact_score']:.2f}")
print(f"High impact pairs: {results['summary']['high_impact_count']}")
```

### Custom Analysis

Build custom analyses using individual components:

```python
from patch_impact_analyzer import (
    PHPCodeParser,
    CallGraphBuilder,
    DataFlowAnalyzer
)

# Parse code
parser = PHPCodeParser()
parsed = parser.parse_code(code)

# Build call graph
call_builder = CallGraphBuilder()
call_graph = call_builder.build_call_graph(code)

# Analyze data flow
flow_analyzer = DataFlowAnalyzer()
data_flow = flow_analyzer.build_data_flow_graph(code)

# Custom analysis logic
for func in call_graph.get_all_functions():
    deps = call_builder.get_function_dependencies(call_graph, func)
    print(f"{func} dependencies: {deps['direct']}")
```

## Limitations

- Regex-based PHP parsing (not full AST)
- Intra-procedural analysis (limited cross-file)
- Heuristic security pattern detection
- WordPress-specific patterns

See [PATCH_IMPACT_ANALYSIS.md](../docs/PATCH_IMPACT_ANALYSIS.md) for detailed documentation.

## API Reference

### PatchImpactAnalyzer

Main analysis coordinator.

**Methods**:
- `analyze_patch_impact(cve1_data, cve2_data, verbose=False) -> ImpactAnalysis`
- `analyze_temporal_impact(earlier_cve, later_cve, verbose=False) -> Dict`
- `compare_multiple_patches(cve_data_list, output_dir=None, verbose=False) -> Dict`
- `generate_report(analysis, output_file=None) -> str`

### CallGraphBuilder

**Methods**:
- `build_call_graph(code, file_path='') -> CallGraph`
- `build_call_graph_from_diff(pre_code, post_code, file_path='') -> Dict`
- `compare_call_graphs(graph1, graph2) -> Dict`
- `get_function_dependencies(graph, function_name) -> Dict`
- `get_function_impact(graph, function_name) -> Dict`

### DataFlowAnalyzer

**Methods**:
- `build_data_flow_graph(code, file_path='') -> DataFlowGraph`
- `analyze_tainted_flows(graph) -> List[List[DataFlowNode]]`
- `compare_data_flows(graph1, graph2) -> Dict`
- `get_variable_flow_summary(graph, variable_name) -> Dict`

### ControlFlowGraphBuilder

**Methods**:
- `build_control_flow_graph(code, file_path='') -> ControlFlowGraph`
- `compare_control_flow_graphs(cfg1, cfg2) -> Dict`
- `get_execution_paths(cfg, max_paths=100) -> List[List[int]]`
- `visualize_cfg(cfg, max_nodes=30) -> str`

## Testing

Run example analysis to test the system:

```bash
python analyze_patch_impact.py --example --verbose
```

## Contributing

Contributions welcome! Areas for improvement:

1. Full PHP AST parser integration
2. Interprocedural analysis
3. Machine learning for relationship detection
4. Visualization (DOT/GraphViz output)
5. Additional security pattern detection

## License

Part of the WordPress Vulnerability Research project.
