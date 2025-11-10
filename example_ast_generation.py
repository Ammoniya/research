#!/usr/bin/env python3
"""
Example script showing how to use the PluginASTGenerator programmatically.

This demonstrates:
1. How to generate ASTs for a single plugin
2. How to generate ASTs for multiple plugins
3. How to customize output directory
4. How to process plugin files
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from generate_plugin_asts import PluginASTGenerator
from data_paths import OUTPUT_AST_SIGNATURES_DIR


def example_single_plugin():
    """Example: Generate ASTs for a single plugin."""
    print("=" * 60)
    print("Example 1: Single Plugin AST Generation")
    print("=" * 60)

    # Create generator
    generator = PluginASTGenerator()

    # Process a single plugin (finds latest version automatically)
    plugin_slug = "akismet"
    success = generator.process_plugin(plugin_slug)

    if success:
        print(f"Successfully generated ASTs for {plugin_slug}")
        print(f"Output directory: {generator.output_base_dir}")
    else:
        print(f"Failed to generate ASTs for {plugin_slug}")

    # Print statistics
    generator.print_statistics()


def example_multiple_plugins():
    """Example: Generate ASTs for multiple plugins."""
    print("\n" + "=" * 60)
    print("Example 2: Multiple Plugins AST Generation")
    print("=" * 60)

    # Create generator
    generator = PluginASTGenerator()

    # List of plugins to process
    plugins = ["akismet", "jetpack", "wordfence", "contact-form-7"]

    for plugin_slug in plugins:
        print(f"\nProcessing {plugin_slug}...")
        generator.process_plugin(plugin_slug)

    # Print overall statistics
    generator.print_statistics()


def example_specific_version():
    """Example: Generate ASTs for a specific plugin version."""
    print("\n" + "=" * 60)
    print("Example 3: Specific Version AST Generation")
    print("=" * 60)

    # Create generator
    generator = PluginASTGenerator()

    # Generate ASTs for a specific version (not just latest)
    plugin_slug = "akismet"
    version = "5.0"

    success = generator.generate_asts_for_plugin(plugin_slug, version)

    if success:
        print(f"Successfully generated ASTs for {plugin_slug} version {version}")
        output_dir = generator.output_base_dir / f"{plugin_slug}-{version}"
        print(f"Output directory: {output_dir}")

        # List generated files
        if output_dir.exists():
            ast_files = list(output_dir.glob("*.json"))
            print(f"Generated {len(ast_files)} AST files")
            print("\nSample files:")
            for f in ast_files[:5]:
                print(f"  - {f.name}")


def example_custom_output():
    """Example: Use custom output directory."""
    print("\n" + "=" * 60)
    print("Example 4: Custom Output Directory")
    print("=" * 60)

    # Create generator with custom output directory
    custom_dir = Path("/tmp/my_custom_asts")
    generator = PluginASTGenerator(output_base_dir=custom_dir)

    print(f"Using custom output directory: {custom_dir}")

    # Process plugin
    plugin_slug = "hello-dolly"
    generator.process_plugin(plugin_slug)

    generator.print_statistics()


def example_from_file():
    """Example: Process plugins from a file."""
    print("\n" + "=" * 60)
    print("Example 5: Process Plugins from File")
    print("=" * 60)

    # Create a temporary file with plugin slugs
    plugins_file = Path("/tmp/test_plugins.txt")
    plugins_file.write_text("akismet\njetpack\nwordfence\n")

    print(f"Created test file: {plugins_file}")

    # Create generator
    generator = PluginASTGenerator()

    # Process plugins from file (limit to 2)
    generator.process_plugins_from_file(plugins_file, limit=2)

    generator.print_statistics()

    # Cleanup
    plugins_file.unlink()


def example_inspect_results():
    """Example: Inspect generated AST results."""
    print("\n" + "=" * 60)
    print("Example 6: Inspecting Generated ASTs")
    print("=" * 60)

    import json

    # Look for any generated AST files
    ast_dir = OUTPUT_AST_SIGNATURES_DIR

    if not ast_dir.exists():
        print(f"No AST directory found at {ast_dir}")
        return

    # Find plugin directories
    plugin_dirs = [d for d in ast_dir.iterdir() if d.is_dir()]

    if not plugin_dirs:
        print("No plugin ASTs generated yet")
        return

    print(f"Found {len(plugin_dirs)} plugin directories:")

    for plugin_dir in plugin_dirs[:3]:  # Show first 3
        print(f"\n{plugin_dir.name}:")

        # Read summary
        summary_file = plugin_dir / "_summary.json"
        if summary_file.exists():
            with open(summary_file) as f:
                summary = json.load(f)
            print(f"  Plugin: {summary['plugin_slug']}")
            print(f"  Version: {summary['version']}")
            print(f"  Total files: {summary['total_files']}")
            print(f"  ASTs generated: {summary['asts_generated']}")

        # Show sample AST file
        ast_files = list(plugin_dir.glob("*.json"))
        ast_files = [f for f in ast_files if f.name != "_summary.json"]

        if ast_files:
            sample_file = ast_files[0]
            print(f"\n  Sample AST file: {sample_file.name}")

            with open(sample_file) as f:
                ast_data = json.load(f)

            print(f"    File path: {ast_data.get('file_path', 'N/A')}")
            print(f"    File size: {ast_data.get('file_size', 'N/A')} bytes")
            print(f"    Functions found: {len(ast_data.get('functions', []))}")

            if ast_data.get('functions'):
                print(f"    Sample functions:")
                for func in ast_data['functions'][:3]:
                    print(f"      - {func['name']} (lines {func['start_line']}-{func['end_line']})")


if __name__ == '__main__':
    print("WordPress Plugin AST Generator - Usage Examples")
    print("=" * 60)
    print()
    print("Note: These examples require SVN repositories to be available.")
    print("Set SVN_REPOS_DIR environment variable if using custom location.")
    print()

    # You can uncomment any example to run it:

    # example_single_plugin()
    # example_multiple_plugins()
    # example_specific_version()
    # example_custom_output()
    # example_from_file()
    example_inspect_results()

    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)
