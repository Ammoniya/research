# WordPress Vulnerability Signature Analyzer - Project Structure

Clean, organized structure for the v2.0 implementation.

## Directory Layout

```
research/
├── README.md                               # Main documentation
├── generate_signatures_v2.py               # CLI entry point (executable)
│
├── wordpress_vulnerability_analyzer/       # Main package (8 modules)
│   ├── __init__.py                        # Package exports
│   ├── config.py                          # Configuration management
│   ├── models.py                          # Data models
│   ├── svn_extractor.py                   # SVN operations
│   ├── pattern_detector.py                # Pattern detection
│   ├── validators.py                      # Validation logic
│   ├── progress_manager.py                # Progress tracking
│   └── signature_generator.py             # Main orchestrator
│
├── docs/                                   # Documentation (5 files)
│   ├── PATTERN_DETECTION_EXPLAINED.md     # Pattern detection deep dive
│   ├── WORKING_WITH_SIGNATURES.md         # Usage guide
│   ├── SIGNATURE_GENERATOR_ENHANCEMENTS.md # V1 enhancements doc
│   ├── V2_IMPLEMENTATION_SUMMARY.md       # Implementation details
│   └── detection_flow.txt                 # Visual flow diagram
│
├── archive/                                # Old versions (3 files)
│   ├── README.md                          # Archive guide
│   ├── generate_signatures.py             # v1.0 (780 lines)
│   └── enhanced_pattern_detection.py      # POC implementation
│
├── signatures/                             # Output directory
│   └── [plugin-name]/                     # One dir per plugin
│       └── CVE-*.json                     # Individual signatures
│
├── tests/                                  # Unit tests (future)
│
├── download_wordfence_db.py               # Utility: Download vulnerabilities
├── fetch_plugins.py                       # Utility: Fetch plugin list
├── process_vulnerabilities.py             # Utility: Process data
├── plugin_vulnerabilities.json            # Data: 17k+ vulnerabilities
└── top_10k_plugin_slugs.txt              # Data: Plugin list
```

## File Counts

- **Python files**: 14
  - Package modules: 8
  - Utility scripts: 3
  - Main script: 1
  - Archived: 2

- **Documentation**: 6
  - Main README: 1
  - Detailed docs: 5

- **Data files**: 2

## Quick Navigation

### For Users
- **Start here**: `README.md`
- **Run the tool**: `./generate_signatures_v2.py`
- **Understand patterns**: `docs/PATTERN_DETECTION_EXPLAINED.md`
- **Use signatures**: `docs/WORKING_WITH_SIGNATURES.md`

### For Developers
- **Package code**: `wordpress_vulnerability_analyzer/`
- **Architecture**: `docs/V2_IMPLEMENTATION_SUMMARY.md`
- **Add features**: Modify appropriate module in package
- **Run tests**: `pytest tests/` (when tests added)

### For Researchers
- **Implementation**: `docs/V2_IMPLEMENTATION_SUMMARY.md`
- **Pattern detection**: `docs/PATTERN_DETECTION_EXPLAINED.md`
- **Flow diagrams**: `docs/detection_flow.txt`
- **Old version**: `archive/generate_signatures.py` (reference)

## Module Responsibilities

### Production Code

| Module | Lines | Responsibility |
|--------|-------|----------------|
| `config.py` | 80 | Configuration management |
| `models.py` | 280 | Data structures (dataclasses) |
| `svn_extractor.py` | 270 | SVN operations & diff parsing |
| `pattern_detector.py` | 340 | Pattern detection with context |
| `validators.py` | 180 | Signature validation & quality |
| `progress_manager.py` | 150 | Progress & storage |
| `signature_generator.py` | 220 | Main orchestration |
| `generate_signatures_v2.py` | 160 | CLI interface |

**Total**: ~1,680 lines (vs 780 in v1.0)

### Documentation

| File | Lines | Purpose |
|------|-------|---------|
| `README.md` | 420 | Main documentation |
| `PATTERN_DETECTION_EXPLAINED.md` | 1,460 | Deep dive on patterns |
| `WORKING_WITH_SIGNATURES.md` | 360 | Usage guide |
| `V2_IMPLEMENTATION_SUMMARY.md` | 544 | Implementation details |
| `SIGNATURE_GENERATOR_ENHANCEMENTS.md` | 360 | V1 enhancements |
| `detection_flow.txt` | 280 | Visual diagrams |

**Total**: ~3,424 lines

## Output Structure

```
signatures/
├── plugin-1/
│   ├── CVE-2023-0001.json
│   ├── CVE-2023-0002.json
│   └── vuln_abc123.json
├── plugin-2/
│   └── CVE-2023-1234.json
└── ...

processing_progress.json           # Resume tracking
vulnerability_signatures.json      # Consolidated output
```

## Dependencies

### Required
- Python 3.8+
- Standard library only for core functionality

### For Development
- pytest (testing)
- black (formatting)
- mypy (type checking)

### External Tools
- `svn` command (for remote checkout fallback)
- `diff` command (for local diffs)

## Maintenance

### Adding a New Pattern Category

1. Add to `PatternCategory` enum in `models.py`
2. Add patterns to `PATTERNS` dict in `pattern_detector.py`
3. Add severity assessment in `signature_generator.py`
4. Update documentation

### Adding a New Validation Rule

1. Add method in `validators.py`
2. Add to `validation_rules` list
3. Update quality scoring if needed
4. Add tests

### Modifying Configuration

1. Update `config.py` with new parameter
2. Add validation if needed
3. Update documentation
4. Update CLI if exposing to user

## Testing Strategy (Future)

```
tests/
├── test_config.py
├── test_models.py
├── test_svn_extractor.py
├── test_pattern_detector.py
├── test_validators.py
├── test_signature_generator.py
└── fixtures/
    ├── sample_diffs/
    └── sample_signatures/
```

## Git Workflow

### Branches
- `main`: Stable releases
- `develop`: Integration branch
- `feature/*`: New features
- `bugfix/*`: Bug fixes

### Tags
- `v1.0-archive`: Original implementation
- `v2.0.0`: First modular release
- `v2.x.x`: Future releases

## Clean Structure Benefits

1. **Easy Navigation**: Everything in logical place
2. **Clear Purpose**: Each directory has specific role
3. **Scalability**: Easy to add new modules
4. **Maintenance**: Know exactly where to look
5. **Onboarding**: New developers find things quickly
6. **Testing**: Clean separation aids testing
7. **Documentation**: Centralized in docs/
8. **History**: Archived but accessible

## Comparison: Before vs After

### Before Cleanup
```
research/
├── 9 .md files (mixed purposes)
├── 4 .py scripts (v1 + v2 + POC)
├── Various docs scattered
└── No clear organization
```

### After Cleanup
```
research/
├── README.md (single entry point)
├── generate_signatures_v2.py (single active script)
├── wordpress_vulnerability_analyzer/ (organized package)
├── docs/ (all documentation)
├── archive/ (old versions)
└── Clear purpose for everything
```

## Questions?

- **General usage**: See `README.md`
- **Pattern detection**: See `docs/PATTERN_DETECTION_EXPLAINED.md`
- **Implementation**: See `docs/V2_IMPLEMENTATION_SUMMARY.md`
- **Old version**: See `archive/README.md`
