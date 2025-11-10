"""Control flow graph builder for analyzing execution paths."""

import re
from typing import List, Dict, Set, Optional, Tuple
from .models import ControlFlowGraph, ControlFlowNode, CodeLocation


class ControlFlowGraphBuilder:
    """
    Builds control flow graphs to show execution paths in code.
    """

    def __init__(self):
        """Initialize the control flow graph builder."""
        self.node_counter = 0

    def build_control_flow_graph(self, code: str, file_path: str = "") -> ControlFlowGraph:
        """
        Build a control flow graph from PHP code.

        Args:
            code: PHP source code
            file_path: Path to the file being analyzed

        Returns:
            ControlFlowGraph object
        """
        graph = ControlFlowGraph()
        self.node_counter = 0

        # Extract basic blocks (simplified)
        blocks = self._extract_basic_blocks(code, file_path)

        # Create CFG nodes for each block
        node_map = {}
        for block in blocks:
            node_id = self._create_node_id()
            node = ControlFlowNode(
                node_id=node_id,
                node_type=block['type'],
                code=block['code'],
                location=block.get('location'),
                metadata=block.get('metadata', {})
            )
            graph.add_node(node)
            node_map[block['id']] = node_id

        # Set entry node
        if blocks:
            graph.entry_node = node_map[blocks[0]['id']]

        # Build edges based on control flow
        for block in blocks:
            from_id = node_map[block['id']]

            # Add edges to successors
            for succ_block_id in block.get('successors', []):
                if succ_block_id in node_map:
                    to_id = node_map[succ_block_id]
                    label = block.get('edge_labels', {}).get(succ_block_id, "")
                    graph.add_edge(from_id, to_id, label)

            # Track exit nodes (nodes with no successors)
            if not block.get('successors'):
                graph.exit_nodes.append(from_id)

        return graph

    def compare_control_flow_graphs(self, cfg1: ControlFlowGraph,
                                    cfg2: ControlFlowGraph) -> Dict[str, any]:
        """
        Compare two control flow graphs.

        Args:
            cfg1: First control flow graph
            cfg2: Second control flow graph

        Returns:
            Dict containing comparison results
        """
        # Compare structure
        nodes1 = len(cfg1.nodes)
        nodes2 = len(cfg2.nodes)
        edges1 = len(cfg1.edges)
        edges2 = len(cfg2.edges)

        # Find similar code patterns
        similar_blocks = self._find_similar_blocks(cfg1, cfg2)

        # Analyze execution path differences
        path_changes = self._analyze_path_changes(cfg1, cfg2)

        return {
            'node_count_diff': nodes2 - nodes1,
            'edge_count_diff': edges2 - edges1,
            'structural_similarity': len(similar_blocks) / max(nodes1, nodes2) if max(nodes1, nodes2) > 0 else 0,
            'similar_blocks': similar_blocks,
            'path_changes': path_changes,
            'complexity_change': (edges2 - edges1) / max(edges1, 1)  # Cyclomatic complexity change
        }

    def get_execution_paths(self, cfg: ControlFlowGraph,
                           max_paths: int = 100, max_depth: int = 100) -> List[List[int]]:
        """
        Get all possible execution paths through the CFG.

        Args:
            cfg: Control flow graph
            max_paths: Maximum number of paths to return
            max_depth: Maximum depth of path traversal (prevents stack overflow)

        Returns:
            List of paths (each path is a list of node IDs)
        """
        if cfg.entry_node is None:
            return []

        paths = []
        self._traverse_paths(cfg, cfg.entry_node, [], paths, max_paths, visited=None, depth=0, max_depth=max_depth)

        return paths

    def visualize_cfg(self, cfg: ControlFlowGraph, max_nodes: int = 30) -> str:
        """
        Create a text-based visualization of the control flow graph.

        Args:
            cfg: Control flow graph
            max_nodes: Maximum number of nodes to display

        Returns:
            Text representation of the CFG
        """
        lines = ["Control Flow Graph:", "=" * 50, ""]

        if cfg.entry_node is not None:
            lines.append(f"Entry Node: {cfg.entry_node}")
            lines.append(f"Exit Nodes: {', '.join(map(str, cfg.exit_nodes))}")
            lines.append("")

        node_ids = sorted(cfg.nodes.keys())[:max_nodes]

        for node_id in node_ids:
            node = cfg.nodes[node_id]
            lines.append(f"Node {node_id} [{node.node_type}]:")

            # Show code (truncated)
            code_preview = node.code[:80].replace('\n', ' ')
            if len(node.code) > 80:
                code_preview += "..."
            lines.append(f"  Code: {code_preview}")

            # Show successors
            successors = cfg.get_successors(node_id)
            if successors:
                lines.append(f"  -> {', '.join(map(str, successors))}")

            lines.append("")

        if len(cfg.nodes) > max_nodes:
            lines.append(f"... and {len(cfg.nodes) - max_nodes} more nodes")

        return "\n".join(lines)

    def _create_node_id(self) -> int:
        """Create a unique node ID."""
        node_id = self.node_counter
        self.node_counter += 1
        return node_id

    def _extract_basic_blocks(self, code: str, file_path: str) -> List[Dict]:
        """
        Extract basic blocks from code (simplified version).

        A basic block is a sequence of statements with one entry and one exit.

        Args:
            code: PHP source code
            file_path: File path

        Returns:
            List of basic block dictionaries
        """
        blocks = []
        lines = code.split('\n')

        current_block = {
            'id': len(blocks),
            'type': 'entry',
            'code': '',
            'successors': [],
            'edge_labels': {},
            'location': None
        }

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # Check for control flow statements
            if re.match(r'\s*(if|while|for|foreach|switch)\s*\(', stripped):
                # End current block
                if current_block['code']:
                    blocks.append(current_block)

                # Create condition block
                condition_block = {
                    'id': len(blocks),
                    'type': 'condition',
                    'code': stripped,
                    'successors': [],
                    'edge_labels': {},
                    'location': CodeLocation(file_path=file_path, line_number=i+1)
                }

                # Link previous block to this one
                if blocks:
                    blocks[-1]['successors'].append(condition_block['id'])

                blocks.append(condition_block)

                # Start new block for body
                current_block = {
                    'id': len(blocks),
                    'type': 'statement',
                    'code': '',
                    'successors': [],
                    'edge_labels': {},
                    'location': CodeLocation(file_path=file_path, line_number=i+2)
                }

                # Link condition to body
                condition_block['successors'].append(current_block['id'])
                condition_block['edge_labels'][current_block['id']] = "true"

            elif re.match(r'\s*else\s*{?', stripped):
                # End current block
                if current_block['code']:
                    blocks.append(current_block)

                # Create else block
                else_block = {
                    'id': len(blocks),
                    'type': 'statement',
                    'code': '',
                    'successors': [],
                    'edge_labels': {},
                    'location': CodeLocation(file_path=file_path, line_number=i+1)
                }

                # Link previous condition to else block
                # Find the last condition block
                for block in reversed(blocks):
                    if block['type'] == 'condition':
                        block['successors'].append(else_block['id'])
                        block['edge_labels'][else_block['id']] = "false"
                        break

                current_block = else_block

            elif re.match(r'\s*(return|break|continue)', stripped):
                # End of execution path
                current_block['code'] += line + '\n'

                if current_block['code']:
                    blocks.append(current_block)

                # Start new block
                current_block = {
                    'id': len(blocks),
                    'type': 'statement',
                    'code': '',
                    'successors': [],
                    'edge_labels': {},
                    'location': CodeLocation(file_path=file_path, line_number=i+2)
                }

            else:
                # Regular statement
                current_block['code'] += line + '\n'

        # Add final block if it has content
        if current_block['code'].strip():
            blocks.append(current_block)

        # Link blocks sequentially if they don't have successors
        for i in range(len(blocks) - 1):
            if not blocks[i]['successors'] and blocks[i]['type'] != 'exit':
                blocks[i]['successors'].append(blocks[i + 1]['id'])

        return blocks

    def _find_similar_blocks(self, cfg1: ControlFlowGraph,
                            cfg2: ControlFlowGraph) -> List[Tuple[int, int]]:
        """
        Find similar basic blocks between two CFGs.

        Args:
            cfg1: First CFG
            cfg2: Second CFG

        Returns:
            List of (node_id1, node_id2) tuples for similar blocks
        """
        similar = []

        for id1, node1 in cfg1.nodes.items():
            for id2, node2 in cfg2.nodes.items():
                # Compare code similarity (simple string comparison)
                code1 = node1.code.strip()
                code2 = node2.code.strip()

                if code1 and code2:
                    # Calculate similarity ratio
                    similarity = self._code_similarity(code1, code2)

                    if similarity > 0.8:  # 80% similar
                        similar.append((id1, id2))

        return similar

    def _code_similarity(self, code1: str, code2: str) -> float:
        """
        Calculate similarity between two code snippets.

        Args:
            code1: First code snippet
            code2: Second code snippet

        Returns:
            Similarity score (0.0 to 1.0)
        """
        # Simple token-based similarity
        tokens1 = set(re.findall(r'\w+', code1.lower()))
        tokens2 = set(re.findall(r'\w+', code2.lower()))

        if not tokens1 or not tokens2:
            return 0.0

        intersection = tokens1.intersection(tokens2)
        union = tokens1.union(tokens2)

        return len(intersection) / len(union)

    def _analyze_path_changes(self, cfg1: ControlFlowGraph,
                              cfg2: ControlFlowGraph) -> List[str]:
        """
        Analyze changes in execution paths between two CFGs.

        Args:
            cfg1: First CFG
            cfg2: Second CFG

        Returns:
            List of path change descriptions
        """
        changes = []

        # Compare number of paths
        paths1 = self.get_execution_paths(cfg1, max_paths=50)
        paths2 = self.get_execution_paths(cfg2, max_paths=50)

        if len(paths2) > len(paths1):
            changes.append(f"Added {len(paths2) - len(paths1)} new execution paths")
        elif len(paths1) > len(paths2):
            changes.append(f"Removed {len(paths1) - len(paths2)} execution paths")

        # Compare branching
        branches1 = sum(1 for node in cfg1.nodes.values() if node.node_type == 'condition')
        branches2 = sum(1 for node in cfg2.nodes.values() if node.node_type == 'condition')

        if branches2 > branches1:
            changes.append(f"Added {branches2 - branches1} conditional branches")
        elif branches1 > branches2:
            changes.append(f"Removed {branches1 - branches2} conditional branches")

        return changes

    def _traverse_paths(self, cfg: ControlFlowGraph, current_node: int,
                       current_path: List[int], all_paths: List[List[int]],
                       max_paths: int, visited: Optional[Set[int]] = None,
                       depth: int = 0, max_depth: int = 100):
        """
        Recursively traverse the CFG to find all paths.

        Args:
            cfg: Control flow graph
            current_node: Current node ID
            current_path: Current path being built
            all_paths: Accumulator for all paths
            max_paths: Maximum number of paths to find
            visited: Set of visited nodes (for cycle detection)
            depth: Current recursion depth
            max_depth: Maximum recursion depth allowed
        """
        # Early termination checks
        if len(all_paths) >= max_paths:
            return

        # Prevent stack overflow by limiting recursion depth
        if depth >= max_depth:
            # Reached max depth, save current path and stop
            if current_path:
                all_paths.append(current_path + [current_node])
            return

        if visited is None:
            visited = set()

        # Avoid infinite loops - if we've seen this node in current path, we have a cycle
        if current_node in visited:
            # Save path with cycle detected and stop this branch
            all_paths.append(current_path + [current_node])
            return

        # Create a new visited set for this path branch
        visited = visited.copy()
        visited.add(current_node)

        current_path = current_path + [current_node]

        # Get successors
        successors = cfg.get_successors(current_node)

        if not successors:
            # This is an exit node
            all_paths.append(current_path)
        else:
            # Continue traversal to successors
            for succ in successors:
                # Check if we've already found enough paths before recursing
                if len(all_paths) >= max_paths:
                    break
                self._traverse_paths(cfg, succ, current_path, all_paths, max_paths, visited, depth + 1, max_depth)
