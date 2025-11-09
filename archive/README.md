# Archive - v1.0 and Proof-of-Concept Files

This directory contains old versions and experimental code that have been superseded by the v2.0 implementation.

## Files

### `generate_signatures.py` (v1.0 - 780 lines)
**Original monolithic implementation**

- Single file with all functionality
- Basic regex pattern matching
- No validation or quality metrics
- ~20% false positive rate

**Status:** Superseded by v2.0 modular package

**When to use:**
- Reference for comparison
- Rollback if critical issues in v2.0
- Understanding evolution of the codebase

### `enhanced_pattern_detection.py`
**Proof-of-concept for improved pattern detection**

Demonstrates:
- Context-aware analysis
- Confidence scoring
- Primary vs incidental categorization

**Status:** Concepts fully integrated into `wordpress_vulnerability_analyzer/pattern_detector.py`

**When to use:**
- Understanding the enhancement concepts
- Demo for presentations
- Reference implementation

## v1.0 vs v2.0 Comparison

| Feature | v1.0 (archived) | v2.0 (current) |
|---------|----------------|----------------|
| **Architecture** | Monolithic (780 lines) | Modular (1,520 lines, 10 modules) |
| **Pattern Detection** | Basic regex | Context-aware with confidence |
| **Validation** | None | Comprehensive quality scoring |
| **Primary/Incidental** | All mixed | Clearly separated |
| **Diff Analysis** | String storage | Structured blocks with stats |
| **False Positives** | ~20% | ~5% |
| **Documentation** | Minimal | Comprehensive |
| **Testability** | Hard to test | Easy unit testing |

## Migration from v1.0

If you need to run v1.0 temporarily:

```bash
# Copy to main directory
cp archive/generate_signatures.py .

# Run
python generate_signatures.py
```

## When to Delete

These files can be safely deleted when:
- ✅ v2.0 has been in production for 6+ months
- ✅ No compatibility issues reported
- ✅ Results validated and accepted
- ✅ Git history preserved (tag v1.0)

Before deletion:
```bash
# Create archive tag
git tag -a v1.0-archive -m "Archive v1.0 before deletion"

# Document any unique features not in v2.0
```

## Historical Context

The v1.0 implementation served as the foundation for understanding:
1. WordPress vulnerability patterns
2. SVN diff extraction challenges
3. Pattern detection requirements
4. Need for validation and quality metrics

These insights led to the v2.0 architectural redesign with:
- Modular, testable components
- Enhanced accuracy through context awareness
- Validation and quality scoring
- Clear separation of concerns

## Questions?

If you need to understand why certain decisions were made in v2.0, reviewing these archived files alongside the documentation in `docs/` provides the full context.
