#!/usr/bin/env python3
"""
Quick diagnostic script to check if your setup is ready for pattern extraction.

Usage:
    python check_setup.py
"""

import sys
import json
from pathlib import Path
import glob


def check_dependencies():
    """Check if required dependencies are installed."""
    print("=" * 70)
    print("1. CHECKING DEPENDENCIES")
    print("=" * 70)

    try:
        import tree_sitter
        print(f"✓ tree-sitter installed (version {tree_sitter.__version__ if hasattr(tree_sitter, '__version__') else 'unknown'})")
    except ImportError:
        print("✗ tree-sitter NOT installed")
        print("  Install: pip install tree-sitter")
        return False

    try:
        import tree_sitter_php
        print(f"✓ tree-sitter-php installed")
    except ImportError:
        print("✗ tree-sitter-php NOT installed")
        print("  Install: pip install tree-sitter-php")
        return False

    return True


def check_directories():
    """Check if data directories exist."""
    print("\n" + "=" * 70)
    print("2. CHECKING DIRECTORIES")
    print("=" * 70)

    base_dir = Path.cwd()

    # Check for signature directory
    sig_dirs = [
        base_dir / "data" / "output" / "signatures",
        base_dir / "signatures",
    ]

    found_sig_dir = None
    for sig_dir in sig_dirs:
        if sig_dir.exists():
            found_sig_dir = sig_dir
            break

    if found_sig_dir:
        print(f"✓ Signature directory found: {found_sig_dir}")

        # Count signature files
        json_files = list(found_sig_dir.rglob("*.json"))
        md_files = list(found_sig_dir.rglob("*.md"))

        # Filter out markdown files
        json_only = [f for f in json_files if f.suffix == '.json']

        print(f"  → Found {len(json_only)} JSON files")
        print(f"  → Found {len(md_files)} markdown files")

        return found_sig_dir, json_only
    else:
        print("✗ No signature directory found")
        print("  Looked in:")
        for sig_dir in sig_dirs:
            print(f"    - {sig_dir}")
        return None, []


def check_signature_format(signature_files):
    """Check signature file format."""
    print("\n" + "=" * 70)
    print("3. CHECKING SIGNATURE FORMAT")
    print("=" * 70)

    if not signature_files:
        print("✗ No signature files to check")
        return False

    # Check first 5 files
    files_to_check = signature_files[:5]

    valid_count = 0
    invalid_count = 0

    for sig_file in files_to_check:
        try:
            with open(sig_file, 'r') as f:
                sig = json.load(f)

            has_pre = 'pre_patch_code' in sig
            has_post = 'post_patch_code' in sig

            if has_pre and has_post:
                print(f"✓ {sig_file.name}")
                print(f"  → pre_patch_code: {len(sig['pre_patch_code'])} chars")
                print(f"  → post_patch_code: {len(sig['post_patch_code'])} chars")
                print(f"  → CVE: {sig.get('cve', 'N/A')}")
                print(f"  → Plugin: {sig.get('plugin_slug', 'N/A')}")
                print(f"  → Type: {sig.get('vuln_type', 'N/A')}")
                valid_count += 1
            else:
                print(f"✗ {sig_file.name}")
                print(f"  → pre_patch_code: {'✓' if has_pre else '✗'}")
                print(f"  → post_patch_code: {'✓' if has_post else '✗'}")
                invalid_count += 1

        except Exception as e:
            print(f"✗ {sig_file.name} - Error: {e}")
            invalid_count += 1

    print(f"\nSummary:")
    print(f"  Valid: {valid_count}/{len(files_to_check)}")
    print(f"  Invalid: {invalid_count}/{len(files_to_check)}")

    if invalid_count > 0:
        print(f"\n⚠️  Some signatures are missing required fields!")
        print(f"   You may need to regenerate signatures with updated code.")

    return valid_count > 0


def check_scripts():
    """Check if required scripts exist."""
    print("\n" + "=" * 70)
    print("4. CHECKING SCRIPTS")
    print("=" * 70)

    base_dir = Path.cwd()

    scripts = [
        "demo_ast_diff.py",
        "extract_vulnerability_patterns.py",
    ]

    all_exist = True
    for script in scripts:
        script_path = base_dir / script
        if script_path.exists():
            print(f"✓ {script}")
        else:
            print(f"✗ {script} NOT FOUND")
            all_exist = False

    return all_exist


def provide_recommendations(sig_dir, has_valid_sigs):
    """Provide recommendations based on checks."""
    print("\n" + "=" * 70)
    print("5. RECOMMENDATIONS")
    print("=" * 70)

    if not sig_dir:
        print("❌ Cannot proceed: No signature directory found")
        print("\nNext steps:")
        print("1. Run generate_signatures.py to create signatures")
        print("2. Or ensure you're in the correct directory")
        return

    if not has_valid_sigs:
        print("❌ Cannot proceed: No valid signature files")
        print("\nNext steps:")
        print("1. Check signature file format")
        print("2. Regenerate signatures if needed")
        return

    print("✅ Setup looks good!")
    print("\nNext steps:")
    print("\n1. Test with demo script:")
    print("   python demo_ast_diff.py")

    print("\n2. Test extraction with 5 signatures:")
    print(f"   python extract_vulnerability_patterns.py \\")
    print(f"       --input-dir {sig_dir} \\")
    print(f"       --output-dir {sig_dir.parent}/vulnerability_patterns \\")
    print(f"       --limit 5")

    print("\n3. If test works, extract all patterns:")
    print(f"   python extract_vulnerability_patterns.py \\")
    print(f"       --input-dir {sig_dir} \\")
    print(f"       --output-dir {sig_dir.parent}/vulnerability_patterns")

    print("\n4. Check results:")
    print(f"   cat {sig_dir.parent}/vulnerability_patterns/extraction_summary.json")


def main():
    """Run all checks."""
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║              PATTERN EXTRACTION SETUP CHECK                          ║
║                                                                      ║
║  This script checks if your environment is ready for extracting      ║
║  vulnerability patterns from CVE signatures.                         ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """)

    # Run checks
    deps_ok = check_dependencies()
    sig_dir, sig_files = check_directories()
    sigs_valid = check_signature_format(sig_files) if sig_files else False
    scripts_ok = check_scripts()

    # Provide recommendations
    provide_recommendations(sig_dir, sigs_valid)

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    checks = [
        ("Dependencies", deps_ok),
        ("Directories", sig_dir is not None),
        ("Signatures", sigs_valid),
        ("Scripts", scripts_ok),
    ]

    all_passed = all(result for _, result in checks)

    for check_name, result in checks:
        status = "✓" if result else "✗"
        print(f"{status} {check_name}")

    if all_passed:
        print("\n✅ All checks passed! You're ready to extract patterns.")
        return 0
    else:
        print("\n❌ Some checks failed. See recommendations above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
