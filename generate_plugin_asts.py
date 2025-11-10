#!/usr/bin/env python3
"""
Generate ASTs for all files in the latest releases of WordPress plugins.

This script:
1. Reads a list of plugin slugs
2. Finds the latest release tag for each plugin
3. Generates ASTs for all PHP files in that release
4. Stores them in: ast_signatures/{plugin-slug}-{version}/

Usage:
    python generate_plugin_asts.py [--plugins-file FILE] [--limit N] [--plugin SLUG]
"""

import argparse
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional
import sys
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from wordpress_vulnerability_analyzer.config import Config
from wordpress_vulnerability_analyzer.ast_parser import PHPASTParser
from wordpress_vulnerability_analyzer.svn_extractor import SVNDiffExtractor
from data_paths import (
    PROJECT_ROOT,
    OUTPUT_AST_SIGNATURES_DIR,
    INPUT_PLUGIN_LIST,
    ensure_data_directories
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PluginASTGenerator:
    """Generate and store ASTs for all files in plugin releases."""

    def __init__(self, output_base_dir: Optional[Path] = None):
        """
        Initialize the generator.

        Args:
            output_base_dir: Base directory for storing ASTs.
                           Defaults to data/output/ast_signatures/
        """
        self.config = Config()
        self.svn_extractor = SVNDiffExtractor(self.config.svn_repos_dir)
        self.ast_parser = PHPASTParser()
        self.output_base_dir = output_base_dir or OUTPUT_AST_SIGNATURES_DIR

        # Create output directory if it doesn't exist
        self.output_base_dir.mkdir(parents=True, exist_ok=True)

        # Statistics
        self.stats = {
            'plugins_processed': 0,
            'plugins_failed': 0,
            'files_processed': 0,
            'files_failed': 0,
            'asts_generated': 0
        }

    def get_latest_version(self, plugin_slug: str) -> Optional[str]:
        """
        Get the latest version tag for a plugin.

        Args:
            plugin_slug: WordPress plugin slug

        Returns:
            Latest version string or None if not found
        """
        try:
            available_tags = self.svn_extractor.get_available_tags(plugin_slug)

            if not available_tags:
                logger.warning(f"No tags found for plugin: {plugin_slug}")
                return None

            # Sort versions (simple lexicographic sort, should work for most cases)
            # For more complex version sorting, we could use packaging.version
            sorted_tags = sorted(available_tags, reverse=True)
            latest = sorted_tags[0]

            logger.info(f"Latest version for {plugin_slug}: {latest}")
            return latest

        except Exception as e:
            logger.error(f"Error getting latest version for {plugin_slug}: {e}")
            return None

    def get_plugin_files(self, plugin_slug: str, version: str, extensions: List[str] = None) -> List[Path]:
        """
        Get all files in a plugin release.

        Args:
            plugin_slug: WordPress plugin slug
            version: Version tag
            extensions: List of file extensions to include (e.g., ['.php']).
                       If None, includes all files.

        Returns:
            List of file paths
        """
        if extensions is None:
            extensions = ['.php']  # Default to PHP files only

        plugin_path = self.svn_extractor.get_local_repo_path(plugin_slug) / 'tags' / version

        if not plugin_path.exists():
            logger.error(f"Plugin path does not exist: {plugin_path}")
            return []

        files = []
        for ext in extensions:
            # Find all files with the given extension recursively
            files.extend(plugin_path.rglob(f'*{ext}'))

        logger.info(f"Found {len(files)} files in {plugin_slug} {version}")
        return files

    def generate_ast_for_file(self, file_path: Path) -> Optional[Dict]:
        """
        Generate AST for a single file.

        Args:
            file_path: Path to the PHP file

        Returns:
            Dict containing AST data or None if parsing failed
        """
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()

            # Parse into AST
            ast = self.ast_parser.parse(code)

            if not ast:
                logger.warning(f"Failed to parse: {file_path}")
                return None

            # Simplify AST to reduce size (max depth 10)
            simplified_ast = self.ast_parser.simplify_ast(ast, max_depth=10)

            # Get function definitions
            functions = self.ast_parser.get_changed_functions(ast)

            return {
                'ast': simplified_ast,
                'functions': functions,
                'file_size': len(code),
                'parse_timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
            return None

    def generate_asts_for_plugin(self, plugin_slug: str, version: str) -> bool:
        """
        Generate ASTs for all files in a plugin release.

        Args:
            plugin_slug: WordPress plugin slug
            version: Version tag

        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Processing {plugin_slug} version {version}")

            # Create output directory: ast_signatures/{plugin-slug}-{version}/
            output_dir = self.output_base_dir / f"{plugin_slug}-{version}"
            output_dir.mkdir(parents=True, exist_ok=True)

            # Get all PHP files
            files = self.get_plugin_files(plugin_slug, version, extensions=['.php'])

            if not files:
                logger.warning(f"No PHP files found for {plugin_slug} {version}")
                return False

            # Generate ASTs for each file
            plugin_path = self.svn_extractor.get_local_repo_path(plugin_slug) / 'tags' / version

            for file_path in files:
                # Get relative path from plugin root
                try:
                    relative_path = file_path.relative_to(plugin_path)
                except ValueError:
                    logger.error(f"Cannot compute relative path for {file_path}")
                    continue

                # Generate AST
                ast_data = self.generate_ast_for_file(file_path)

                if ast_data:
                    # Add metadata
                    ast_data['plugin_slug'] = plugin_slug
                    ast_data['version'] = version
                    ast_data['file_path'] = str(relative_path)
                    ast_data['absolute_path'] = str(file_path)

                    # Create output file: convert path separators to underscores
                    # e.g., includes/admin.php -> includes_admin.php.json
                    safe_filename = str(relative_path).replace('/', '_').replace('\\', '_')
                    output_file = output_dir / f"{safe_filename}.json"

                    # Save AST
                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump(ast_data, f, indent=2)

                    self.stats['asts_generated'] += 1
                    self.stats['files_processed'] += 1
                    logger.debug(f"Saved AST: {output_file}")
                else:
                    self.stats['files_failed'] += 1

            # Create summary file
            summary = {
                'plugin_slug': plugin_slug,
                'version': version,
                'total_files': len(files),
                'asts_generated': self.stats['asts_generated'],
                'generation_timestamp': datetime.now().isoformat(),
                'output_directory': str(output_dir)
            }

            summary_file = output_dir / '_summary.json'
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2)

            logger.info(f"Successfully processed {plugin_slug} {version}")
            self.stats['plugins_processed'] += 1
            return True

        except Exception as e:
            logger.error(f"Error processing {plugin_slug} {version}: {e}")
            self.stats['plugins_failed'] += 1
            return False

    def process_plugin(self, plugin_slug: str) -> bool:
        """
        Process a single plugin (find latest version and generate ASTs).

        Args:
            plugin_slug: WordPress plugin slug

        Returns:
            True if successful, False otherwise
        """
        # Get latest version
        version = self.get_latest_version(plugin_slug)

        if not version:
            logger.error(f"Cannot find latest version for {plugin_slug}")
            self.stats['plugins_failed'] += 1
            return False

        # Generate ASTs
        return self.generate_asts_for_plugin(plugin_slug, version)

    def process_plugins_from_file(self, file_path: Path, limit: Optional[int] = None) -> None:
        """
        Process multiple plugins from a file.

        Args:
            file_path: Path to file containing plugin slugs (one per line)
            limit: Maximum number of plugins to process (None for all)
        """
        try:
            with open(file_path, 'r') as f:
                plugin_slugs = [line.strip() for line in f if line.strip()]

            logger.info(f"Loaded {len(plugin_slugs)} plugin slugs from {file_path}")

            if limit:
                plugin_slugs = plugin_slugs[:limit]
                logger.info(f"Processing first {limit} plugins")

            for i, plugin_slug in enumerate(plugin_slugs, 1):
                logger.info(f"[{i}/{len(plugin_slugs)}] Processing {plugin_slug}")
                self.process_plugin(plugin_slug)

        except FileNotFoundError:
            logger.error(f"Plugin list file not found: {file_path}")
        except Exception as e:
            logger.error(f"Error processing plugins from file: {e}")

    def print_statistics(self) -> None:
        """Print processing statistics."""
        logger.info("=" * 60)
        logger.info("STATISTICS")
        logger.info("=" * 60)
        logger.info(f"Plugins processed successfully: {self.stats['plugins_processed']}")
        logger.info(f"Plugins failed: {self.stats['plugins_failed']}")
        logger.info(f"Files processed: {self.stats['files_processed']}")
        logger.info(f"Files failed: {self.stats['files_failed']}")
        logger.info(f"ASTs generated: {self.stats['asts_generated']}")
        logger.info(f"Output directory: {self.output_base_dir}")
        logger.info("=" * 60)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Generate ASTs for all files in latest WordPress plugin releases'
    )
    parser.add_argument(
        '--plugins-file',
        type=Path,
        default=INPUT_PLUGIN_LIST,
        help='File containing plugin slugs (one per line)'
    )
    parser.add_argument(
        '--plugin',
        type=str,
        help='Process a single plugin by slug'
    )
    parser.add_argument(
        '--limit',
        type=int,
        help='Limit number of plugins to process'
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        help='Custom output directory (default: data/output/ast_signatures/)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Ensure data directories exist
    ensure_data_directories()

    # Create generator
    generator = PluginASTGenerator(output_base_dir=args.output_dir)

    # Process plugins
    if args.plugin:
        # Process single plugin
        logger.info(f"Processing single plugin: {args.plugin}")
        generator.process_plugin(args.plugin)
    else:
        # Process from file
        if not args.plugins_file.exists():
            logger.error(f"Plugins file not found: {args.plugins_file}")
            logger.info("You can generate it by running: python utils/fetch_plugins.py")
            sys.exit(1)

        generator.process_plugins_from_file(args.plugins_file, limit=args.limit)

    # Print statistics
    generator.print_statistics()


if __name__ == '__main__':
    main()
