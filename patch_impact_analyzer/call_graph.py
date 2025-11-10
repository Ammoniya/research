"""Call graph builder for analyzing function call relationships."""

from typing import List, Dict, Set, Optional
from .models import CallGraph, FunctionDefinition, FunctionCall
from .php_parser import PHPCodeParser


class CallGraphBuilder:
    """
    Builds call graphs from PHP code to show function call relationships.
    """

    def __init__(self):
        """Initialize the call graph builder."""
        self.parser = PHPCodeParser()

    def build_call_graph(self, code: str, file_path: str = "") -> CallGraph:
        """
        Build a call graph from PHP code.

        Args:
            code: PHP source code
            file_path: Path to the file being analyzed

        Returns:
            CallGraph object representing function relationships
        """
        graph = CallGraph()

        # Parse code to extract functions and calls
        parsed = self.parser.parse_code(code, file_path)

        functions = parsed['functions']
        all_calls = parsed['calls']

        # Add all function definitions to the graph
        for func in functions:
            graph.add_function(func)

        # Build a map of function bodies to their calls
        function_calls_map = self._map_calls_to_functions(functions, all_calls)

        # Add edges for function calls
        for func in functions:
            func_sig = func.get_signature()
            calls_in_func = function_calls_map.get(func_sig, [])

            for call in calls_in_func:
                # Try to match the call to a defined function
                callee_sig = self._match_call_to_function(call, functions)

                if callee_sig:
                    graph.add_call(func_sig, callee_sig)
                else:
                    # External function call (WordPress core, PHP built-in, etc.)
                    # Create a placeholder signature
                    callee_sig = call.get_full_name()
                    graph.add_call(func_sig, callee_sig)

        return graph

    def build_call_graph_from_diff(self, pre_code: str, post_code: str, file_path: str = "") -> Dict[str, CallGraph]:
        """
        Build call graphs for both pre and post patch code.

        Args:
            pre_code: Code before patch
            post_code: Code after patch
            file_path: Path to the file

        Returns:
            Dict with 'pre' and 'post' CallGraph objects
        """
        pre_graph = self.build_call_graph(pre_code, f"{file_path}:pre")
        post_graph = self.build_call_graph(post_code, f"{file_path}:post")

        return {
            'pre': pre_graph,
            'post': post_graph
        }

    def compare_call_graphs(self, graph1: CallGraph, graph2: CallGraph) -> Dict[str, any]:
        """
        Compare two call graphs to find similarities and differences.

        Args:
            graph1: First call graph
            graph2: Second call graph

        Returns:
            Dict containing comparison results
        """
        funcs1 = set(graph1.get_all_functions())
        funcs2 = set(graph2.get_all_functions())

        # Find overlaps
        shared_functions = funcs1.intersection(funcs2)
        only_in_graph1 = funcs1 - funcs2
        only_in_graph2 = funcs2 - funcs1

        # Calculate overlap percentage
        total_unique = len(funcs1.union(funcs2))
        overlap_percentage = (len(shared_functions) / total_unique * 100) if total_unique > 0 else 0.0

        # Find call relationships between the graphs
        cross_calls = self._find_cross_graph_calls(graph1, graph2, shared_functions)

        return {
            'shared_functions': list(shared_functions),
            'only_in_graph1': list(only_in_graph1),
            'only_in_graph2': list(only_in_graph2),
            'overlap_percentage': overlap_percentage,
            'cross_calls': cross_calls,
            'graph1_upstream': cross_calls['graph1_calls_graph2'],  # Graph1 calls Graph2 functions
            'graph1_downstream': cross_calls['graph2_calls_graph1']  # Graph2 calls Graph1 functions
        }

    def _map_calls_to_functions(self, functions: List[FunctionDefinition],
                                 all_calls: List[FunctionCall]) -> Dict[str, List[FunctionCall]]:
        """
        Map function calls to the functions that contain them.

        Args:
            functions: List of function definitions
            all_calls: List of all function calls found

        Returns:
            Dict mapping function signatures to their calls
        """
        result = {}

        for func in functions:
            func_sig = func.get_signature()
            result[func_sig] = []

            # Find calls that are within this function's body
            if not func.body or not func.location:
                continue

            func_start_line = func.location.line_number
            # Estimate function end line by counting newlines in body
            func_end_line = func_start_line + func.body.count('\n')

            for call in all_calls:
                if call.location and func_start_line <= call.location.line_number <= func_end_line:
                    result[func_sig].append(call)

        return result

    def _match_call_to_function(self, call: FunctionCall,
                                functions: List[FunctionDefinition]) -> Optional[str]:
        """
        Try to match a function call to a defined function.

        Args:
            call: Function call to match
            functions: List of defined functions

        Returns:
            Function signature if matched, None otherwise
        """
        # For method calls, try to match by method name
        if call.is_method_call:
            for func in functions:
                if func.is_method and func.name == call.name:
                    return func.get_signature()
        else:
            # For regular calls, match by function name
            for func in functions:
                if not func.is_method and func.name == call.name:
                    return func.get_signature()

        return None

    def _find_cross_graph_calls(self, graph1: CallGraph, graph2: CallGraph,
                                shared_functions: Set[str]) -> Dict[str, List[str]]:
        """
        Find function calls that cross between two graphs.

        Args:
            graph1: First call graph
            graph2: Second call graph
            shared_functions: Functions present in both graphs

        Returns:
            Dict with cross-graph call relationships
        """
        graph1_calls_graph2 = []  # Functions in graph1 that call graph2 functions
        graph2_calls_graph1 = []  # Functions in graph2 that call graph1 functions

        funcs1 = set(graph1.get_all_functions())
        funcs2 = set(graph2.get_all_functions())

        # Check graph1 -> graph2 calls
        for func in funcs1:
            callees = graph1.get_callees(func)
            for callee in callees:
                if callee in funcs2 and callee not in shared_functions:
                    graph1_calls_graph2.append(f"{func} -> {callee}")

        # Check graph2 -> graph1 calls
        for func in funcs2:
            callees = graph2.get_callees(func)
            for callee in callees:
                if callee in funcs1 and callee not in shared_functions:
                    graph2_calls_graph1.append(f"{func} -> {callee}")

        return {
            'graph1_calls_graph2': graph1_calls_graph2,
            'graph2_calls_graph1': graph2_calls_graph1
        }

    def get_function_dependencies(self, graph: CallGraph, function_name: str) -> Dict[str, List[str]]:
        """
        Get all dependencies for a specific function.

        Args:
            graph: Call graph
            function_name: Function to analyze

        Returns:
            Dict with direct and transitive dependencies
        """
        direct_deps = graph.get_callees(function_name)

        # Get transitive dependencies (functions called by dependencies)
        transitive_deps = set()
        visited = set()

        def traverse(func):
            if func in visited:
                return
            visited.add(func)

            for callee in graph.get_callees(func):
                transitive_deps.add(callee)
                traverse(callee)

        for dep in direct_deps:
            traverse(dep)

        return {
            'direct': direct_deps,
            'transitive': list(transitive_deps - set(direct_deps)),
            'all': list(set(direct_deps) | transitive_deps)
        }

    def get_function_impact(self, graph: CallGraph, function_name: str) -> Dict[str, List[str]]:
        """
        Get all functions impacted by changes to a specific function.

        Args:
            graph: Call graph
            function_name: Function to analyze

        Returns:
            Dict with direct and transitive callers
        """
        direct_callers = graph.get_callers(function_name)

        # Get transitive callers (functions that call the callers)
        transitive_callers = set()
        visited = set()

        def traverse(func):
            if func in visited:
                return
            visited.add(func)

            for caller in graph.get_callers(func):
                transitive_callers.add(caller)
                traverse(caller)

        for caller in direct_callers:
            traverse(caller)

        return {
            'direct': direct_callers,
            'transitive': list(transitive_callers - set(direct_callers)),
            'all': list(set(direct_callers) | transitive_callers)
        }

    def visualize_graph(self, graph: CallGraph, max_nodes: int = 50) -> str:
        """
        Create a text-based visualization of the call graph.

        Args:
            graph: Call graph to visualize
            max_nodes: Maximum number of nodes to include

        Returns:
            Text representation of the graph
        """
        lines = ["Call Graph Visualization:", "=" * 50, ""]

        functions = graph.get_all_functions()[:max_nodes]

        for func in functions:
            callees = graph.get_callees(func)
            callers = graph.get_callers(func)

            lines.append(f"Function: {func}")

            if callers:
                lines.append(f"  Called by: {', '.join(callers[:5])}")
                if len(callers) > 5:
                    lines.append(f"    ... and {len(callers) - 5} more")

            if callees:
                lines.append(f"  Calls: {', '.join(callees[:5])}")
                if len(callees) > 5:
                    lines.append(f"    ... and {len(callees) - 5} more")

            lines.append("")

        if len(graph.get_all_functions()) > max_nodes:
            lines.append(f"... and {len(graph.get_all_functions()) - max_nodes} more functions")

        return "\n".join(lines)
