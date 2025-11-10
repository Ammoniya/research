#!/usr/bin/env python3
"""
Test script for AST signature generation.

Creates a sample CVE with vulnerable and patched PHP code,
then generates an AST signature to verify the pipeline works.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from wordpress_vulnerability_analyzer.ast_signature_generator import ASTSignatureGenerator
from data_paths import OUTPUT_AST_SIGNATURES_DIR


def test_basic_xss_vulnerability():
    """Test AST signature generation for a basic XSS vulnerability."""

    print("\n" + "="*70)
    print("Testing AST Signature Generation - XSS Vulnerability")
    print("="*70 + "\n")

    # Sample vulnerable code (missing sanitization)
    vulnerable_code = """<?php
function display_user_input($input) {
    echo $input;
}
?>"""

    # Sample patched code (with sanitization)
    patched_code = """<?php
function display_user_input($input) {
    echo esc_html($input);
}
?>"""

    # Create generator
    generator = ASTSignatureGenerator(verbose=True)

    # Generate signature
    signature = generator.generate_from_code(
        cve="CVE-2024-TEST-XSS",
        plugin_slug="test-plugin",
        vuln_type="Cross-Site Scripting (XSS)",
        title="XSS vulnerability in display_user_input function",
        vulnerable_code=vulnerable_code,
        patched_code=patched_code,
        vulnerable_version="1.0.0",
        patched_version="1.0.1",
        references=["https://example.com/cve-2024-test-xss"]
    )

    if signature:
        print("\n" + "="*70)
        print("✓ AST Signature Generated Successfully!")
        print("="*70 + "\n")

        print(f"CVE: {signature.cve}")
        print(f"Plugin: {signature.plugin_slug}")
        print(f"Type: {signature.vuln_type}")
        print(f"Versions: {signature.vulnerable_version} → {signature.patched_version}")
        print(f"\nMinimal Diffs Found: {len(signature.minimal_diffs)}")

        for i, diff in enumerate(signature.minimal_diffs, 1):
            print(f"\n  Diff {i}:")
            print(f"    Type: {diff.diff_type}")
            print(f"    Description: {diff.description}")
            print(f"    Path: {' → '.join(diff.path)}")

        # Save the signature
        output_path = generator.save_signature(signature, OUTPUT_AST_SIGNATURES_DIR)
        print(f"\n✓ Signature saved to: {output_path}")

        return True
    else:
        print("\n✗ Failed to generate AST signature")
        return False


def test_sql_injection_vulnerability():
    """Test AST signature generation for SQL injection vulnerability."""

    print("\n" + "="*70)
    print("Testing AST Signature Generation - SQL Injection")
    print("="*70 + "\n")

    # Vulnerable code (unsanitized SQL)
    vulnerable_code = """<?php
global $wpdb;
$user_id = $_GET['user_id'];
$query = "SELECT * FROM users WHERE id = " . $user_id;
$results = $wpdb->query($query);
?>"""

    # Patched code (using prepared statements)
    patched_code = """<?php
global $wpdb;
$user_id = intval($_GET['user_id']);
$query = $wpdb->prepare("SELECT * FROM users WHERE id = %d", $user_id);
$results = $wpdb->query($query);
?>"""

    generator = ASTSignatureGenerator(verbose=True)

    signature = generator.generate_from_code(
        cve="CVE-2024-TEST-SQL",
        plugin_slug="test-plugin",
        vuln_type="SQL Injection",
        title="SQL injection in user query",
        vulnerable_code=vulnerable_code,
        patched_code=patched_code,
        vulnerable_version="2.0.0",
        patched_version="2.0.1",
        references=["https://example.com/cve-2024-test-sql"]
    )

    if signature:
        print("\n" + "="*70)
        print("✓ AST Signature Generated Successfully!")
        print("="*70 + "\n")

        print(f"CVE: {signature.cve}")
        print(f"Plugin: {signature.plugin_slug}")
        print(f"Type: {signature.vuln_type}")
        print(f"\nMinimal Diffs Found: {len(signature.minimal_diffs)}")

        # Save the signature
        output_path = generator.save_signature(signature, OUTPUT_AST_SIGNATURES_DIR)
        print(f"\n✓ Signature saved to: {output_path}")

        return True
    else:
        print("\n✗ Failed to generate AST signature")
        return False


def main():
    """Run all tests."""
    print("\n" + "="*70)
    print("AST Signature Generation Test Suite")
    print("="*70)

    results = []

    # Test 1: XSS vulnerability
    results.append(("XSS Vulnerability", test_basic_xss_vulnerability()))

    # Test 2: SQL Injection
    results.append(("SQL Injection", test_sql_injection_vulnerability()))

    # Print summary
    print("\n" + "="*70)
    print("Test Summary")
    print("="*70 + "\n")

    for test_name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status}: {test_name}")

    total_passed = sum(1 for _, passed in results if passed)
    print(f"\nPassed: {total_passed}/{len(results)}")

    if total_passed == len(results):
        print("\n✓ All tests passed!")
        return 0
    else:
        print("\n✗ Some tests failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
