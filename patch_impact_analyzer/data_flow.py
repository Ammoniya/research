"""Data flow analyzer for tracking variable usage and dependencies."""

import re
from typing import List, Dict, Set, Optional, Tuple
from .models import DataFlowGraph, DataFlowNode, CodeLocation, VariableUsage
from .php_parser import PHPCodeParser


class DataFlowAnalyzer:
    """
    Analyzes data flow in PHP code to track variable dependencies.
    """

    def __init__(self):
        """Initialize the data flow analyzer."""
        self.parser = PHPCodeParser()

        # Security-sensitive operations
        self.sources = {
            # User input
            '$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SERVER', '$_FILES',
            'get_query_var', 'get_option', 'get_post_meta', 'get_user_meta'
        }

        self.sinks = {
            # Critical operations
            'echo', 'print', 'printf', 'eval', 'system', 'exec', 'passthru',
            'shell_exec', 'file_put_contents', 'fwrite', 'wpdb->query',
            'wp_redirect', 'header'
        }

        self.sanitizers = {
            # Sanitization functions
            'sanitize_text_field', 'sanitize_email', 'sanitize_url',
            'esc_html', 'esc_attr', 'esc_url', 'esc_js', 'esc_sql',
            'wp_kses', 'wp_kses_post', 'absint', 'intval', 'floatval'
        }

    def build_data_flow_graph(self, code: str, file_path: str = "") -> DataFlowGraph:
        """
        Build a data flow graph from PHP code.

        Args:
            code: PHP source code
            file_path: Path to the file being analyzed

        Returns:
            DataFlowGraph object
        """
        graph = DataFlowGraph()

        # Parse code to extract variables
        parsed = self.parser.parse_code(code, file_path)
        variables = parsed['variables']
        calls = parsed['calls']

        # Build nodes for each variable usage
        for var in variables:
            if not var.location:
                continue

            # Determine if this is a source or sink
            is_source = self._is_source(var, code)
            is_sink = self._is_sink(var, code, calls)

            operation = "write" if var.is_write else "read"

            # Check if variable is sanitized
            if self._is_sanitized(var, code):
                operation = "sanitize"

            node = DataFlowNode(
                variable=var.name,
                location=var.location,
                is_source=is_source,
                is_sink=is_sink,
                operation=operation
            )

            graph.add_node(node)

        # Build edges based on data flow
        self._build_flow_edges(graph, variables)

        return graph

    def analyze_tainted_flows(self, graph: DataFlowGraph) -> List[List[DataFlowNode]]:
        """
        Find tainted data flows (source to sink without sanitization).

        Args:
            graph: Data flow graph

        Returns:
            List of flow paths (each path is a list of nodes)
        """
        tainted_paths = []

        # Find all source nodes
        sources = [i for i, node in enumerate(graph.nodes) if node.is_source]

        for source_idx in sources:
            # Trace flows from this source
            paths = self._trace_flows(graph, source_idx)

            for path in paths:
                # Check if path reaches a sink without sanitization
                has_sanitization = any(graph.nodes[idx].operation == "sanitize" for idx in path)
                reaches_sink = any(graph.nodes[idx].is_sink for idx in path)

                if reaches_sink and not has_sanitization:
                    # This is a tainted flow
                    node_path = [graph.nodes[idx] for idx in path]
                    tainted_paths.append(node_path)

        return tainted_paths

    def compare_data_flows(self, graph1: DataFlowGraph, graph2: DataFlowGraph) -> Dict[str, any]:
        """
        Compare two data flow graphs.

        Args:
            graph1: First data flow graph
            graph2: Second data flow graph

        Returns:
            Dict containing comparison results
        """
        vars1 = set(graph1.variable_flows.keys())
        vars2 = set(graph2.variable_flows.keys())

        shared_variables = vars1.intersection(vars2)
        only_in_graph1 = vars1 - vars2
        only_in_graph2 = vars2 - vars1

        # Find shared data flow patterns
        flow_chains = self._find_flow_chains(graph1, graph2, shared_variables)

        # Find tainted variables in both graphs
        tainted1 = self._get_tainted_variables(graph1)
        tainted2 = self._get_tainted_variables(graph2)
        tainted_in_both = tainted1.intersection(tainted2)

        return {
            'shared_variables': list(shared_variables),
            'only_in_graph1': list(only_in_graph1),
            'only_in_graph2': list(only_in_graph2),
            'flow_chains': flow_chains,
            'tainted_variables': list(tainted_in_both),
            'tainted_only_in_graph1': list(tainted1 - tainted2),
            'tainted_only_in_graph2': list(tainted2 - tainted1)
        }

    def _is_source(self, var: VariableUsage, code: str) -> bool:
        """
        Check if a variable is a data source (user input, etc.).

        Args:
            var: Variable usage
            code: Source code

        Returns:
            True if this is a data source
        """
        # Check if variable name matches known sources
        if f"${var.name}" in self.sources:
            return True

        # Check if variable is assigned from a source
        if var.value:
            for source in self.sources:
                if source in var.value:
                    return True

        # Check context around the variable
        if var.location:
            context = var.location.context
            for source in self.sources:
                if source in context:
                    return True

        return False

    def _is_sink(self, var: VariableUsage, code: str, calls: List) -> bool:
        """
        Check if a variable flows to a sink (critical operation).

        Args:
            var: Variable usage
            code: Source code
            calls: List of function calls

        Returns:
            True if this flows to a sink
        """
        if not var.location:
            return False

        # Check if variable is used in a sink function call
        context = var.location.context

        for sink in self.sinks:
            if sink in context and f"${var.name}" in context:
                return True

        return False

    def _is_sanitized(self, var: VariableUsage, code: str) -> bool:
        """
        Check if a variable is sanitized.

        Args:
            var: Variable usage
            code: Source code

        Returns:
            True if variable is sanitized
        """
        # Check if assigned value uses a sanitizer
        if var.value:
            for sanitizer in self.sanitizers:
                if sanitizer in var.value:
                    return True

        # Check context
        if var.location:
            context = var.location.context
            for sanitizer in self.sanitizers:
                if sanitizer in context:
                    return True

        return False

    def _build_flow_edges(self, graph: DataFlowGraph, variables: List[VariableUsage]):
        """
        Build edges between data flow nodes.

        Args:
            graph: Data flow graph to populate
            variables: List of variable usages
        """
        # Group variables by name
        var_groups = {}
        for i, var_usage in enumerate(variables):
            if var_usage.name not in var_groups:
                var_groups[var_usage.name] = []
            var_groups[var_usage.name].append(i)

        # For each variable, connect writes to subsequent reads
        for var_name, indices in var_groups.items():
            nodes_for_var = [graph.nodes[i] for i in indices if i < len(graph.nodes)]

            # Sort by line number
            sorted_nodes = sorted(zip(indices, nodes_for_var),
                                key=lambda x: x[1].location.line_number if x[1].location else 0)

            # Connect each write to subsequent reads
            last_write_idx = None
            for idx, node in sorted_nodes:
                if node.operation == "write" or node.operation == "sanitize":
                    last_write_idx = idx
                elif node.operation == "read" and last_write_idx is not None:
                    graph.add_edge(last_write_idx, idx)

    def _trace_flows(self, graph: DataFlowGraph, start_idx: int,
                     visited: Optional[Set[int]] = None) -> List[List[int]]:
        """
        Trace all data flows from a starting node.

        Args:
            graph: Data flow graph
            start_idx: Starting node index
            visited: Set of visited nodes

        Returns:
            List of paths (each path is a list of node indices)
        """
        if visited is None:
            visited = set()

        if start_idx in visited:
            return []

        visited = visited.copy()
        visited.add(start_idx)

        paths = [[start_idx]]

        # Find outgoing edges from this node
        outgoing = [to_idx for from_idx, to_idx in graph.edges if from_idx == start_idx]

        if not outgoing:
            return paths

        # Recursively trace from each outgoing edge
        all_paths = []
        for next_idx in outgoing:
            sub_paths = self._trace_flows(graph, next_idx, visited)
            for sub_path in sub_paths:
                all_paths.append([start_idx] + sub_path)

        return all_paths if all_paths else paths

    def _find_flow_chains(self, graph1: DataFlowGraph, graph2: DataFlowGraph,
                          shared_variables: Set[str]) -> List[List[str]]:
        """
        Find data flow chains that span both graphs.

        Args:
            graph1: First data flow graph
            graph2: Second data flow graph
            shared_variables: Variables present in both graphs

        Returns:
            List of flow chains
        """
        chains = []

        for var in shared_variables:
            # Get flows for this variable in both graphs
            flows1 = graph1.get_flows_for_variable(var)
            flows2 = graph2.get_flows_for_variable(var)

            if flows1 and flows2:
                # Create a chain representation
                chain = [
                    f"Graph1: {var} ({len(flows1)} uses)",
                    f"Graph2: {var} ({len(flows2)} uses)"
                ]
                chains.append(chain)

        return chains

    def _get_tainted_variables(self, graph: DataFlowGraph) -> Set[str]:
        """
        Get variables with tainted flows.

        Args:
            graph: Data flow graph

        Returns:
            Set of tainted variable names
        """
        tainted = set()

        tainted_paths = self.analyze_tainted_flows(graph)

        for path in tainted_paths:
            for node in path:
                tainted.add(node.variable)

        return tainted

    def get_variable_flow_summary(self, graph: DataFlowGraph, variable_name: str) -> Dict[str, any]:
        """
        Get a summary of how a variable flows through the code.

        Args:
            graph: Data flow graph
            variable_name: Variable to analyze

        Returns:
            Dict with flow summary
        """
        nodes = graph.get_flows_for_variable(variable_name)

        sources = [n for n in nodes if n.is_source]
        sinks = [n for n in nodes if n.is_sink]
        sanitizations = [n for n in nodes if n.operation == "sanitize"]

        return {
            'variable': variable_name,
            'total_uses': len(nodes),
            'sources': len(sources),
            'sinks': len(sinks),
            'sanitizations': len(sanitizations),
            'is_tainted': len(sources) > 0 and len(sinks) > 0 and len(sanitizations) == 0,
            'flow_nodes': nodes
        }
