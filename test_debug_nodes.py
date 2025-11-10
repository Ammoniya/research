#!/usr/bin/env python3
"""Debug which nodes are found in the changed range."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from wordpress_vulnerability_analyzer.ast_parser import PHPASTParser
from wordpress_vulnerability_analyzer.ast_line_mapper import ASTLineMapper

# Test with amCharts example
vuln_code = """<?php
\techo '[amcharts id="' . $post_id . '"]';
?>"""

parser = PHPASTParser()
mapper = ASTLineMapper()

vuln_ast = parser.parse(vuln_code)

# Find nodes in line 2 (where the echo statement is)
changed_ranges = [(2, 2)]
nodes = mapper.find_minimal_changed_nodes(vuln_ast, changed_ranges)

print(f"Found {len(nodes)} nodes in changed range:")
for i, node in enumerate(nodes, 1):
    text_preview = node.text[:50].replace('\n', '\\n') if node.text else ''
    print(f"{i}. {node.node_type:30s} | lines {node.start_point[0]+1:2d}-{node.end_point[0]+1:2d} | {text_preview}")
