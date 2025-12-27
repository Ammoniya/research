#!/usr/bin/env python3
"""
Helper script to prepare the diff_results directory for analysis.

This script can:
1. Create the diff_results directory structure
2. Verify the directory exists and list its contents
3. Provide guidance on populating the directory

Usage:
    python3 prepare_diff_results.py --create
    python3 prepare_diff_results.py --scan
"""

import argparse
import sys
from pathlib import Path


def create_directory_structure(base_dir: Path) -> bool:
    """
    Create the diff_results directory structure.
    
    Returns:
        True if directory was created, False if it already exists
    """
    if base_dir.exists():
        print(f"[!] Directory already exists: {base_dir}")
        return False
    
    base_dir.mkdir(parents=True, exist_ok=True)
    print(f"[+] Created directory: {base_dir}")
    
    # Create a README
    readme_content = """# diff_results Directory

This directory should contain JavaScript files extracted from vulnerability diffs
or other sources for malicious code analysis.

## Structure

You can organize the files in any subdirectory structure. The malicious JS detection
tool will recursively scan all .js files found in this directory.

Example structure:
```
diff_results/
├── plugin1/
│   ├── file1.js
│   └── file2.js
├── plugin2/
│   └── vulnerable.js
└── other/
    └── script.js
```

## Populating this Directory

1. Extract JavaScript files from vulnerability diffs
2. Copy WordPress plugin JavaScript files
3. Place any JavaScript files you want to analyze for malicious patterns

## Scanning

Once populated, run:
```bash
python3 detect_malicious_js.py --dir diff_results
```
"""
    
    readme_file = base_dir / "README.md"
    readme_file.write_text(readme_content)
    print(f"[+] Created README: {readme_file}")
    
    return True


def scan_directory(base_dir: Path):
    """Scan and report on the directory structure."""
    if not base_dir.exists():
        print(f"[!] Directory does not exist: {base_dir}")
        print(f"[*] Run with --create to create it")
        return
    
    print(f"[*] Scanning directory: {base_dir}")
    print()
    
    # Count files
    js_files = list(base_dir.rglob('*.js'))
    all_files = [f for f in base_dir.rglob('*') if f.is_file()]
    subdirs = [d for d in base_dir.rglob('*') if d.is_dir()]
    
    print(f"Statistics:")
    print(f"  Subdirectories: {len(subdirs)}")
    print(f"  Total files:    {len(all_files)}")
    print(f"  JavaScript files: {len(js_files)}")
    print()
    
    if js_files:
        print(f"JavaScript files found:")
        for js_file in sorted(js_files)[:20]:  # Show first 20
            size_kb = js_file.stat().st_size / 1024
            print(f"  - {js_file.relative_to(base_dir)} ({size_kb:.1f} KB)")
        
        if len(js_files) > 20:
            print(f"  ... and {len(js_files) - 20} more files")
    else:
        print(f"[!] No JavaScript files found in {base_dir}")
        print()
        print("To add files:")
        print(f"  1. Copy .js files to: {base_dir}")
        print(f"  2. Organize in subdirectories as needed")
        print(f"  3. Run: python3 detect_malicious_js.py")
    
    print()
    
    # Show directory tree (limited depth)
    print("Directory structure (first 2 levels):")
    show_tree(base_dir, base_dir, max_depth=2)


def show_tree(path: Path, root: Path, prefix: str = "", max_depth: int = 2, current_depth: int = 0):
    """Display directory tree."""
    if current_depth >= max_depth:
        return
    
    items = sorted(path.iterdir(), key=lambda x: (not x.is_dir(), x.name))
    
    for i, item in enumerate(items):
        is_last = i == len(items) - 1
        current_prefix = "└── " if is_last else "├── "
        print(f"{prefix}{current_prefix}{item.name}")
        
        if item.is_dir() and current_depth < max_depth - 1:
            extension_prefix = "    " if is_last else "│   "
            show_tree(item, root, prefix + extension_prefix, max_depth, current_depth + 1)


def main():
    parser = argparse.ArgumentParser(
        description='Prepare and manage the diff_results directory'
    )
    parser.add_argument(
        '--dir',
        type=str,
        default='diff_results',
        help='Directory path (default: diff_results)'
    )
    parser.add_argument(
        '--create',
        action='store_true',
        help='Create the directory structure'
    )
    parser.add_argument(
        '--scan',
        action='store_true',
        help='Scan and report on directory contents'
    )
    
    args = parser.parse_args()
    
    base_dir = Path(args.dir)
    
    if args.create:
        create_directory_structure(base_dir)
        print()
        print(f"Next steps:")
        print(f"  1. Add .js files to: {base_dir}")
        print(f"  2. Run: python3 detect_malicious_js.py --dir {base_dir}")
    elif args.scan:
        scan_directory(base_dir)
    else:
        # Default: scan if exists, otherwise prompt to create
        if base_dir.exists():
            scan_directory(base_dir)
        else:
            print(f"[!] Directory does not exist: {base_dir}")
            print()
            print(f"To create it:")
            print(f"  python3 prepare_diff_results.py --create")
            print()
            print(f"Or create manually:")
            print(f"  mkdir -p {base_dir}")
            print(f"  # Add .js files to the directory")
            print(f"  python3 detect_malicious_js.py --dir {base_dir}")


if __name__ == '__main__':
    main()
