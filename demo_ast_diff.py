#!/usr/bin/env python3
"""
Demonstration of AST Diffing for Vulnerability Pattern Extraction

This script shows how to:
1. Parse vulnerable and patched code into ASTs
2. Find the minimal differing subtrees
3. Extract vulnerability patterns
4. Use patterns for matching other code

Example based on CVE-2024-9425 (XSS vulnerability)
"""

import sys
import json
from pathlib import Path

# Add package to path
sys.path.insert(0, str(Path(__file__).parent))

from wordpress_vulnerability_analyzer.ast_parser import PHPASTParser
from wordpress_vulnerability_analyzer.ast_differ import ASTDiffer
from wordpress_vulnerability_analyzer.models import ASTNode


def print_section(title: str):
    """Print a section header."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print('=' * 80)


def print_ast(node: ASTNode, indent: int = 0, max_depth: int = 5):
    """Pretty print an AST."""
    if indent > max_depth:
        return

    indent_str = "  " * indent
    field_prefix = f"[{node.field_name}] " if node.field_name else ""

    # Show node type and text preview
    text_preview = ""
    if node.text and len(node.text) < 50 and '\n' not in node.text:
        text_preview = f' "{node.text}"'
    elif node.text:
        # Show first line only
        first_line = node.text.split('\n')[0]
        if len(first_line) > 40:
            first_line = first_line[:40] + "..."
        text_preview = f' "{first_line}"'

    print(f"{indent_str}{field_prefix}{node.node_type}{text_preview}")

    # Print children
    for child in node.children:
        # Skip whitespace and comments for cleaner output
        if child.node_type not in {'comment', 'text', 'white_space', 'whitespace'}:
            print_ast(child, indent + 1, max_depth)


def print_diff(diff, differ):
    """Pretty print a diff."""
    print(differ.visualize_diff(diff))


def example_1_simple_xss():
    """
    Example 1: Simple XSS - Missing Escaping

    CVE-2024-9425 style vulnerability where output is not escaped.
    """
    print_section("Example 1: Simple XSS - Missing Escaping")

    # Vulnerable code: echo without escaping
    vulnerable_code = """<?php
echo $classes;
"""

    # Patched code: echo with esc_attr()
    patched_code = """<?php
echo esc_attr($classes);
"""

    print("\n[*] Vulnerable Code:")
    print(vulnerable_code)

    print("\n[*] Patched Code:")
    print(patched_code)

    # Parse into ASTs
    parser = PHPASTParser()

    print("\n[*] Parsing vulnerable code...")
    vuln_ast = parser.parse(vulnerable_code)

    print("\n[*] Parsing patched code...")
    patch_ast = parser.parse(patched_code)

    if not vuln_ast or not patch_ast:
        print("[!] Failed to parse code")
        return None, None, None

    print("\n[*] Vulnerable AST Structure:")
    print_ast(vuln_ast, max_depth=6)

    print("\n[*] Patched AST Structure:")
    print_ast(patch_ast, max_depth=6)

    # Diff the ASTs
    print("\n[*] Computing AST differences...")
    differ = ASTDiffer(ignore_whitespace=True, ignore_comments=True)
    diffs = differ.diff(vuln_ast, patch_ast)

    print(f"\n[*] Found {len(diffs)} total differences")

    # Get minimal diffs
    minimal_diffs = differ.get_minimal_diffs(diffs)
    print(f"\n[*] Minimal differences: {len(minimal_diffs)}")

    print("\n[*] Diff Details:")
    for i, diff in enumerate(minimal_diffs, 1):
        print(f"\n--- Diff {i} ---")
        print_diff(diff, differ)

    # Show the vulnerability pattern
    print("\n" + "=" * 80)
    print("  VULNERABILITY PATTERN EXTRACTED")
    print("=" * 80)

    print("\n[*] Pre-Patch Pattern (Vulnerable Signature):")
    for diff in minimal_diffs:
        if diff.vulnerable_node:
            print(f"  Node Type: {diff.vulnerable_node.node_type}")
            print(f"  Code: {diff.vulnerable_node.text}")

    print("\n[*] Post-Patch Pattern (Fixed Signature):")
    for diff in minimal_diffs:
        if diff.patched_node:
            print(f"  Node Type: {diff.patched_node.node_type}")
            print(f"  Code: {diff.patched_node.text}")

    # Generate summary
    summary = differ.diff_summary(diffs)
    print("\n[*] Diff Summary:")
    print(f"  Total diffs: {summary['total_diffs']}")
    print(f"  Added: {summary['added']}")
    print(f"  Removed: {summary['removed']}")
    print(f"  Modified: {summary['modified']}")

    return vuln_ast, patch_ast, minimal_diffs


def example_2_sql_injection():
    """
    Example 2: SQL Injection - Missing prepare() call
    """
    print_section("Example 2: SQL Injection - Missing prepare()")

    # Vulnerable code: direct query with user input
    vulnerable_code = """<?php
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$results = $wpdb->get_results($query);
"""

    # Patched code: using prepare()
    patched_code = """<?php
$query = $wpdb->prepare("SELECT * FROM users WHERE id = %d", $_GET['id']);
$results = $wpdb->get_results($query);
"""

    print("\n[*] Vulnerable Code:")
    print(vulnerable_code)

    print("\n[*] Patched Code:")
    print(patched_code)

    # Parse into ASTs
    parser = PHPASTParser()
    differ = ASTDiffer(ignore_whitespace=True, ignore_comments=True)

    vuln_ast = parser.parse(vulnerable_code)
    patch_ast = parser.parse(patched_code)

    if not vuln_ast or not patch_ast:
        print("[!] Failed to parse code")
        return

    # Diff the ASTs
    diffs = differ.diff(vuln_ast, patch_ast)
    minimal_diffs = differ.get_minimal_diffs(diffs)

    print(f"\n[*] Found {len(diffs)} total differences")
    print(f"[*] Minimal differences: {len(minimal_diffs)}")

    print("\n[*] Diff Details:")
    for i, diff in enumerate(minimal_diffs, 1):
        print(f"\n--- Diff {i} ---")
        print_diff(diff, differ)

    # Check for security-relevant diffs
    security_diffs = differ.get_security_relevant_diffs(minimal_diffs)
    print(f"\n[*] Security-relevant differences: {len(security_diffs)}")

    return vuln_ast, patch_ast, minimal_diffs


def example_3_authorization():
    """
    Example 3: Missing Authorization Check
    """
    print_section("Example 3: Missing Authorization Check")

    # Vulnerable code: no capability check
    vulnerable_code = """<?php
function delete_user_data() {
    global $wpdb;
    $user_id = $_POST['user_id'];
    $wpdb->delete('user_data', array('user_id' => $user_id));
}
"""

    # Patched code: with capability check
    patched_code = """<?php
function delete_user_data() {
    if (!current_user_can('manage_options')) {
        return;
    }
    global $wpdb;
    $user_id = $_POST['user_id'];
    $wpdb->delete('user_data', array('user_id' => $user_id));
}
"""

    print("\n[*] Vulnerable Code:")
    print(vulnerable_code)

    print("\n[*] Patched Code:")
    print(patched_code)

    # Parse into ASTs
    parser = PHPASTParser()
    differ = ASTDiffer(ignore_whitespace=True, ignore_comments=True)

    vuln_ast = parser.parse(vulnerable_code)
    patch_ast = parser.parse(patched_code)

    if not vuln_ast or not patch_ast:
        print("[!] Failed to parse code")
        return

    # Diff the ASTs
    diffs = differ.diff(vuln_ast, patch_ast)
    minimal_diffs = differ.get_minimal_diffs(diffs)
    security_diffs = differ.get_security_relevant_diffs(minimal_diffs)

    print(f"\n[*] Found {len(diffs)} total differences")
    print(f"[*] Minimal differences: {len(minimal_diffs)}")
    print(f"[*] Security-relevant differences: {len(security_diffs)}")

    print("\n[*] Security-Relevant Diffs:")
    for i, diff in enumerate(security_diffs, 1):
        print(f"\n--- Security Diff {i} ---")
        print_diff(diff, differ)

    return vuln_ast, patch_ast, security_diffs


def demo_pattern_matching():
    """
    Demo: Using extracted patterns to find vulnerable code
    """
    print_section("Pattern Matching Demo")

    print("\n[*] This demonstrates how you would use the extracted patterns")
    print("    to scan other plugins for similar vulnerabilities.")

    # The vulnerable pattern from Example 1
    print("\n[1] VULNERABLE PATTERN (Pre-Patch AST):")
    print("    Echo statement with unescaped variable")
    print("    Structure: echo_statement -> variable")

    # The patched pattern from Example 1
    print("\n[2] PATCHED PATTERN (Post-Patch AST):")
    print("    Echo statement with escaped variable")
    print("    Structure: echo_statement -> function_call(esc_attr) -> variable")

    # Example plugin code to scan
    print("\n[*] Scanning example plugin code...")

    test_cases = [
        ("plugin-A.php", "<?php echo $user_input; ?>", "VULNERABLE"),
        ("plugin-B.php", "<?php echo esc_html($user_input); ?>", "SAFE"),
        ("plugin-C.php", "<?php echo esc_attr($classes); ?>", "SAFE"),
        ("plugin-D.php", "<?php echo $data['name']; ?>", "VULNERABLE"),
    ]

    parser = PHPASTParser()

    for filename, code, expected in test_cases:
        print(f"\n--- Scanning: {filename} ---")
        print(f"Code: {code}")

        ast = parser.parse(code)
        if ast:
            # In a real implementation, you would compare this AST
            # against your vulnerability pattern here
            print(f"Expected result: {expected}")

            # Simple heuristic check (simplified)
            has_echo = "echo" in code.lower()
            has_esc_function = any(fn in code for fn in ['esc_attr', 'esc_html', 'esc_js', 'esc_url'])

            if has_echo and not has_esc_function:
                print("⚠️  POTENTIAL VULNERABILITY: Echo without escaping detected!")
            else:
                print("✓ Safe: Proper escaping detected")


def save_patterns_to_json():
    """
    Demo: Saving extracted patterns to JSON for later use
    """
    print_section("Saving Patterns to JSON")

    vulnerable_code = "<?php echo $classes; ?>"
    patched_code = "<?php echo esc_attr($classes); ?>"

    parser = PHPASTParser()
    differ = ASTDiffer(ignore_whitespace=True, ignore_comments=True)

    vuln_ast = parser.parse(vulnerable_code)
    patch_ast = parser.parse(patched_code)

    if not vuln_ast or not patch_ast:
        print("[!] Failed to parse code")
        return

    diffs = differ.diff(vuln_ast, patch_ast)
    minimal_diffs = differ.get_minimal_diffs(diffs)

    # Create pattern data structure
    pattern_data = {
        "cve": "CVE-2024-9425",
        "vulnerability_type": "Cross-Site Scripting (XSS)",
        "description": "Missing output escaping",
        "vulnerable_pattern": {
            "code": vulnerable_code,
            "ast": vuln_ast.to_dict() if vuln_ast else None
        },
        "patched_pattern": {
            "code": patched_code,
            "ast": patch_ast.to_dict() if patch_ast else None
        },
        "diffs": [diff.to_dict() for diff in minimal_diffs]
    }

    # Save to JSON
    output_file = Path("pattern_example_cve_2024_9425.json")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(pattern_data, f, indent=2, ensure_ascii=False)

    print(f"\n[+] Pattern saved to: {output_file}")
    print(f"[+] File size: {output_file.stat().st_size} bytes")

    print("\n[*] Pattern structure:")
    print(f"  - Vulnerable code AST: {len(str(pattern_data['vulnerable_pattern']['ast']))} chars")
    print(f"  - Patched code AST: {len(str(pattern_data['patched_pattern']['ast']))} chars")
    print(f"  - Number of diffs: {len(pattern_data['diffs'])}")

    return pattern_data


def main():
    """Run all demonstrations."""
    print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║        AST DIFF DEMONSTRATION FOR VULNERABILITY PATTERN EXTRACTION        ║
║                                                                           ║
║  This script demonstrates how to extract vulnerability patterns from      ║
║  pre-patch and post-patch code using AST diffing.                        ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
    """)

    # Run examples
    try:
        # Example 1: XSS vulnerability
        vuln_ast, patch_ast, diffs = example_1_simple_xss()

        if vuln_ast and patch_ast:
            print("\n✓ Example 1 completed successfully!")

        # Example 2: SQL Injection
        example_2_sql_injection()
        print("\n✓ Example 2 completed successfully!")

        # Example 3: Authorization
        example_3_authorization()
        print("\n✓ Example 3 completed successfully!")

        # Pattern matching demo
        demo_pattern_matching()

        # Save patterns
        pattern_data = save_patterns_to_json()

        # Final summary
        print_section("Summary")
        print("""
[*] What we demonstrated:

1. PARSING: Converting PHP code into Abstract Syntax Trees (ASTs)
   - Pre-patch code (vulnerable version)
   - Post-patch code (patched version)

2. DIFFING: Finding structural differences between ASTs
   - Total differences
   - Minimal differences (most specific changes)
   - Security-relevant differences

3. PATTERN EXTRACTION: Extracting vulnerability signatures
   - Vulnerable Pattern (Pre-Patch AST) = What to search for
   - Patched Pattern (Post-Patch AST) = What the fix looks like

4. PATTERN MATCHING: Using patterns to scan other code
   - Match vulnerable pattern → Potential vulnerability
   - Also matches patched pattern → False positive (already fixed)
   - Only matches vulnerable pattern → Real vulnerability!

[*] Next steps:
   - Use these patterns to scan 100k+ WordPress plugins
   - Find vulnerability clones across the ecosystem
   - Generate automated security reports

[*] Output files:
   - pattern_example_cve_2024_9425.json (example pattern)
        """)

        print("\n✓ All demonstrations completed successfully!")

    except Exception as e:
        print(f"\n[!] Error during demonstration: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
