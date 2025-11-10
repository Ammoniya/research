#!/usr/bin/env python3
"""Debug script to view AST structure."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from wordpress_vulnerability_analyzer.ast_parser import PHPASTParser
from wordpress_vulnerability_analyzer.models import ASTNode

def print_ast(node: ASTNode, indent: int = 0):
    """Print AST structure."""
    ind = "  " * indent
    text_preview = node.text[:50].replace('\n', '\\n') if node.text else ''
    print(f"{ind}{node.node_type} | {text_preview}")

    for child in node.children:
        print_ast(child, indent + 1)


# Test with amCharts example
vuln_code = """<?php
\techo '[amcharts id="' . $post_id . '"]';
?>"""

patch_code = """<?php
\techo '[amcharts id="' . esc_textarea( $post_id ) . '"]';
?>"""

parser = PHPASTParser()

print("=== VULNERABLE CODE ===")
vuln_ast = parser.parse(vuln_code)
if vuln_ast:
    print_ast(vuln_ast)

print("\n=== PATCHED CODE ===")
patch_ast = parser.parse(patch_code)
if patch_ast:
    print_ast(patch_ast)
