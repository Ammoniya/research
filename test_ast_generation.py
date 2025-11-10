#!/usr/bin/env python3
"""Test script to verify AST generation works correctly."""

import json
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))

from generate_plugin_asts import PluginASTGenerator

# Sample PHP code to test
TEST_PHP_CODE = """<?php
/**
 * Plugin Name: Test Plugin
 */

function test_function($param1, $param2) {
    if ($param1 > 0) {
        echo esc_html($param2);
    }
    return true;
}

class TestClass {
    public function test_method() {
        return "Hello World";
    }
}
?>
"""

def test_ast_generation():
    """Test that AST generation and JSON serialization works."""
    print("Testing AST generation and JSON serialization...")

    # Create a temporary PHP file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as f:
        f.write(TEST_PHP_CODE)
        temp_file = Path(f.name)

    try:
        # Create generator
        generator = PluginASTGenerator()

        # Generate AST for the test file
        print(f"Generating AST for {temp_file}...")
        ast_data = generator.generate_ast_for_file(temp_file)

        if not ast_data:
            print("❌ FAILED: AST generation returned None")
            return False

        print("✓ AST generated successfully")

        # Verify structure
        if 'ast' not in ast_data:
            print("❌ FAILED: 'ast' key missing")
            return False

        if 'functions' not in ast_data:
            print("❌ FAILED: 'functions' key missing")
            return False

        print(f"✓ Found {len(ast_data['functions'])} functions")

        # Try to serialize to JSON
        try:
            json_str = json.dumps(ast_data, indent=2)
            print("✓ JSON serialization successful")

            # Try to deserialize
            parsed = json.loads(json_str)
            print("✓ JSON deserialization successful")

            # Print some info
            print(f"\nAST Summary:")
            print(f"  - Root node type: {parsed['ast']['node_type']}")
            print(f"  - File size: {parsed['file_size']} bytes")
            print(f"  - Functions found: {len(parsed['functions'])}")

            if parsed['functions']:
                print(f"\n  Functions:")
                for func in parsed['functions']:
                    print(f"    - {func['name']} (lines {func['start_line']}-{func['end_line']})")

            # Save to a test file to verify file I/O
            test_output = Path('/tmp/test_ast_output.json')
            with open(test_output, 'w') as f:
                json.dump(ast_data, f, indent=2)

            print(f"\n✓ Successfully saved to {test_output}")
            print(f"  File size: {test_output.stat().st_size} bytes")

            # Read it back
            with open(test_output) as f:
                reloaded = json.load(f)

            print("✓ Successfully reloaded from file")

            return True

        except TypeError as e:
            print(f"❌ FAILED: JSON serialization error: {e}")
            return False
        except Exception as e:
            print(f"❌ FAILED: Unexpected error: {e}")
            return False

    finally:
        # Cleanup
        temp_file.unlink()
        print(f"\nCleaned up temporary file")

if __name__ == '__main__':
    print("=" * 60)
    print("AST Generation Test")
    print("=" * 60)
    print()

    success = test_ast_generation()

    print()
    print("=" * 60)
    if success:
        print("✅ ALL TESTS PASSED")
    else:
        print("❌ TESTS FAILED")
    print("=" * 60)

    sys.exit(0 if success else 1)
