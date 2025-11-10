"""Data models for patch impact analysis."""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any, Tuple
from enum import Enum


class CodeElementType(Enum):
    """Types of code elements."""
    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    VARIABLE = "variable"
    CONSTANT = "constant"
    HOOK = "hook"


@dataclass
class CodeLocation:
    """Location of code element."""
    file_path: str
    line_number: int
    column: int = 0
    context: str = ""  # Surrounding code for context


@dataclass
class FunctionDefinition:
    """Represents a function or method definition."""
    name: str
    parameters: List[str] = field(default_factory=list)
    location: Optional[CodeLocation] = None
    body: str = ""
    is_method: bool = False
    class_name: Optional[str] = None
    return_type: Optional[str] = None
    visibility: str = "public"  # public, private, protected

    def get_signature(self) -> str:
        """Get function signature."""
        params = ", ".join(self.parameters)
        if self.is_method and self.class_name:
            return f"{self.class_name}::{self.name}({params})"
        return f"{self.name}({params})"


@dataclass
class FunctionCall:
    """Represents a function call."""
    name: str
    arguments: List[str] = field(default_factory=list)
    location: Optional[CodeLocation] = None
    is_method_call: bool = False
    object_name: Optional[str] = None

    def get_full_name(self) -> str:
        """Get full function call name."""
        if self.is_method_call and self.object_name:
            return f"{self.object_name}->{self.name}"
        return self.name


@dataclass
class VariableUsage:
    """Represents variable usage (read or write)."""
    name: str
    is_write: bool  # True for assignment, False for read
    location: Optional[CodeLocation] = None
    scope: str = "unknown"  # local, global, parameter, class
    value: Optional[str] = None  # For assignments


@dataclass
class CodeElement:
    """Generic code element for analysis."""
    element_type: CodeElementType
    name: str
    location: Optional[CodeLocation] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CallGraph:
    """Call graph representation."""
    nodes: Dict[str, FunctionDefinition] = field(default_factory=dict)  # function_name -> definition
    edges: Dict[str, List[str]] = field(default_factory=dict)  # caller -> [callees]
    reverse_edges: Dict[str, List[str]] = field(default_factory=dict)  # callee -> [callers]

    def add_function(self, func: FunctionDefinition):
        """Add a function to the graph."""
        self.nodes[func.get_signature()] = func
        if func.get_signature() not in self.edges:
            self.edges[func.get_signature()] = []
        if func.get_signature() not in self.reverse_edges:
            self.reverse_edges[func.get_signature()] = []

    def add_call(self, caller: str, callee: str):
        """Add a function call edge."""
        if caller not in self.edges:
            self.edges[caller] = []
        if callee not in self.reverse_edges:
            self.reverse_edges[callee] = []

        if callee not in self.edges[caller]:
            self.edges[caller].append(callee)
        if caller not in self.reverse_edges[callee]:
            self.reverse_edges[callee].append(caller)

    def get_callees(self, function: str) -> List[str]:
        """Get functions called by this function."""
        return self.edges.get(function, [])

    def get_callers(self, function: str) -> List[str]:
        """Get functions that call this function."""
        return self.reverse_edges.get(function, [])

    def get_all_functions(self) -> List[str]:
        """Get all function names in the graph."""
        return list(self.nodes.keys())


@dataclass
class DataFlowNode:
    """Node in data flow graph."""
    variable: str
    location: CodeLocation
    is_source: bool = False  # True if this is where variable is defined
    is_sink: bool = False  # True if this is critical usage
    operation: str = ""  # read, write, sanitize, validate, etc.


@dataclass
class DataFlowGraph:
    """Data flow graph representation."""
    nodes: List[DataFlowNode] = field(default_factory=list)
    edges: List[Tuple[int, int]] = field(default_factory=list)  # (from_node_index, to_node_index)
    variable_flows: Dict[str, List[int]] = field(default_factory=dict)  # variable -> [node_indices]

    def add_node(self, node: DataFlowNode) -> int:
        """Add a node and return its index."""
        self.nodes.append(node)
        index = len(self.nodes) - 1

        if node.variable not in self.variable_flows:
            self.variable_flows[node.variable] = []
        self.variable_flows[node.variable].append(index)

        return index

    def add_edge(self, from_index: int, to_index: int):
        """Add a data flow edge."""
        edge = (from_index, to_index)
        if edge not in self.edges:
            self.edges.append(edge)

    def get_flows_for_variable(self, variable: str) -> List[DataFlowNode]:
        """Get all data flow nodes for a variable."""
        indices = self.variable_flows.get(variable, [])
        return [self.nodes[i] for i in indices]


@dataclass
class ControlFlowNode:
    """Node in control flow graph."""
    node_id: int
    node_type: str  # entry, exit, statement, condition, loop
    code: str = ""
    location: Optional[CodeLocation] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ControlFlowGraph:
    """Control flow graph representation."""
    nodes: Dict[int, ControlFlowNode] = field(default_factory=dict)
    edges: List[Tuple[int, int, str]] = field(default_factory=list)  # (from, to, label)
    entry_node: Optional[int] = None
    exit_nodes: List[int] = field(default_factory=list)

    def add_node(self, node: ControlFlowNode) -> int:
        """Add a node and return its ID."""
        self.nodes[node.node_id] = node
        return node.node_id

    def add_edge(self, from_id: int, to_id: int, label: str = ""):
        """Add a control flow edge."""
        edge = (from_id, to_id, label)
        if edge not in self.edges:
            self.edges.append(edge)

    def get_successors(self, node_id: int) -> List[int]:
        """Get successor nodes."""
        return [to_id for from_id, to_id, _ in self.edges if from_id == node_id]

    def get_predecessors(self, node_id: int) -> List[int]:
        """Get predecessor nodes."""
        return [from_id for from_id, to_id, _ in self.edges if to_id == node_id]


@dataclass
class ImpactRelationship:
    """Represents a relationship between two patches."""
    relationship_type: str  # function_overlap, variable_overlap, data_flow_chain, control_flow_change
    description: str
    confidence: float  # 0.0 to 1.0
    evidence: List[str] = field(default_factory=list)
    locations: List[CodeLocation] = field(default_factory=list)


@dataclass
class ImpactAnalysis:
    """Result of patch impact analysis."""
    cve1: str
    cve2: str

    # Graph overlaps
    shared_functions: List[str] = field(default_factory=list)
    shared_variables: List[str] = field(default_factory=list)
    shared_files: List[str] = field(default_factory=list)

    # Call graph relationships
    call_graph_overlap: float = 0.0  # Percentage of overlap
    upstream_impacts: List[str] = field(default_factory=list)  # CVE1 functions that call CVE2 functions
    downstream_impacts: List[str] = field(default_factory=list)  # CVE1 functions called by CVE2 functions

    # Data flow relationships
    data_flow_chains: List[List[str]] = field(default_factory=list)  # Chains of variable flows
    tainted_variables: List[str] = field(default_factory=list)  # Variables affected by both patches

    # Control flow relationships
    control_flow_changes: List[str] = field(default_factory=list)
    execution_path_changes: List[str] = field(default_factory=list)

    # Impact relationships
    relationships: List[ImpactRelationship] = field(default_factory=list)

    # Overall metrics
    impact_score: float = 0.0  # Overall impact score (0-100)
    impact_level: str = "NONE"  # NONE, LOW, MEDIUM, HIGH, CRITICAL

    def add_relationship(self, rel: ImpactRelationship):
        """Add an impact relationship."""
        self.relationships.append(rel)
        # Update impact score based on relationships
        self._update_impact_score()

    def _update_impact_score(self):
        """Calculate overall impact score based on relationships."""
        if not self.relationships:
            self.impact_score = 0.0
            self.impact_level = "NONE"
            return

        # Weight different relationship types
        weights = {
            "function_overlap": 0.3,
            "variable_overlap": 0.2,
            "data_flow_chain": 0.3,
            "control_flow_change": 0.2
        }

        total_score = 0.0
        total_weight = 0.0

        for rel in self.relationships:
            weight = weights.get(rel.relationship_type, 0.1)
            total_score += rel.confidence * weight * 100
            total_weight += weight

        if total_weight > 0:
            self.impact_score = total_score / total_weight

        # Determine impact level
        if self.impact_score >= 80:
            self.impact_level = "CRITICAL"
        elif self.impact_score >= 60:
            self.impact_level = "HIGH"
        elif self.impact_score >= 40:
            self.impact_level = "MEDIUM"
        elif self.impact_score >= 20:
            self.impact_level = "LOW"
        else:
            self.impact_level = "NONE"

    def to_markdown(self) -> str:
        """Generate markdown report of impact analysis."""
        md = f"# Patch Impact Analysis: {self.cve1} → {self.cve2}\n\n"

        md += f"## Overall Impact\n\n"
        md += f"- **Impact Score**: {self.impact_score:.2f}/100\n"
        md += f"- **Impact Level**: {self.impact_level}\n\n"

        md += f"## Code Overlap\n\n"
        md += f"- **Shared Functions**: {len(self.shared_functions)}\n"
        md += f"- **Shared Variables**: {len(self.shared_variables)}\n"
        md += f"- **Shared Files**: {len(self.shared_files)}\n"
        md += f"- **Call Graph Overlap**: {self.call_graph_overlap:.1f}%\n\n"

        if self.shared_functions:
            md += f"### Shared Functions\n\n"
            for func in self.shared_functions[:10]:  # Limit to 10
                md += f"- `{func}`\n"
            if len(self.shared_functions) > 10:
                md += f"- ... and {len(self.shared_functions) - 10} more\n"
            md += "\n"

        if self.upstream_impacts or self.downstream_impacts:
            md += f"## Call Graph Relationships\n\n"

            if self.upstream_impacts:
                md += f"### Upstream Impact (CVE-1 calls CVE-2 functions)\n\n"
                for impact in self.upstream_impacts[:10]:
                    md += f"- {impact}\n"
                if len(self.upstream_impacts) > 10:
                    md += f"- ... and {len(self.upstream_impacts) - 10} more\n"
                md += "\n"

            if self.downstream_impacts:
                md += f"### Downstream Impact (CVE-2 calls CVE-1 functions)\n\n"
                for impact in self.downstream_impacts[:10]:
                    md += f"- {impact}\n"
                if len(self.downstream_impacts) > 10:
                    md += f"- ... and {len(self.downstream_impacts) - 10} more\n"
                md += "\n"

        if self.data_flow_chains:
            md += f"## Data Flow Relationships\n\n"
            md += f"Found {len(self.data_flow_chains)} data flow chain(s) connecting the patches.\n\n"
            for i, chain in enumerate(self.data_flow_chains[:5], 1):
                md += f"### Chain {i}\n\n"
                md += " → ".join(chain) + "\n\n"

        if self.tainted_variables:
            md += f"### Tainted Variables\n\n"
            md += "Variables affected by both patches:\n\n"
            for var in self.tainted_variables[:10]:
                md += f"- `{var}`\n"
            if len(self.tainted_variables) > 10:
                md += f"- ... and {len(self.tainted_variables) - 10} more\n"
            md += "\n"

        if self.relationships:
            md += f"## Detailed Relationships\n\n"
            for i, rel in enumerate(self.relationships, 1):
                md += f"### {i}. {rel.relationship_type.replace('_', ' ').title()}\n\n"
                md += f"- **Description**: {rel.description}\n"
                md += f"- **Confidence**: {rel.confidence:.2f}\n"
                if rel.evidence:
                    md += f"- **Evidence**:\n"
                    for evidence in rel.evidence[:5]:
                        md += f"  - {evidence}\n"
                md += "\n"

        return md
