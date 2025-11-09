# WordPress Vulnerability Research

Automated discovery and validation of zero-day vulnerabilities in WordPress plugins through historical vulnerability pattern mining and fuzzing-based validation.

## Quick Start: Running the 3 Phases

This project has 3 main phases that run sequentially:

### Phase 1: Generate Vulnerability Signatures

Extract patterns from known CVEs to create reusable signatures:

```bash
python generate_signatures.py
```

**Output:** `signatures/` - Generated vulnerability signatures from known CVEs

### Phase 2: Mine Vulnerability Clones

Search for zero-day candidates by matching signatures against plugin codebases:

```bash
python mine_vulnerability_clones.py
```

**Options:**
```bash
# Fast mode - scan only tagged releases (recommended for quick results)
python mine_vulnerability_clones.py --scan-mode releases --max-plugins 100

# Comprehensive mode - scan all commits (slower but thorough)
python mine_vulnerability_clones.py --scan-mode commits --max-plugins 100

# Limit number of revisions per plugin
python mine_vulnerability_clones.py --max-revisions 50
```

**Scan Modes:**
- **`releases`** (fast): Scans only tagged releases (e.g., 1.0.0, 1.1.0, 2.0.0)
  - Much faster (typically 10-50 versions vs 1000+ commits)
  - Focuses on official published versions
  - Recommended for initial research

- **`commits`** (comprehensive): Scans all SVN commits
  - Very slow but thorough (scans every code change)
  - Better temporal analysis of when vulnerabilities appeared
  - Use when you need complete historical analysis

**Output:** `mining_results/zero_days/` - Detected zero-day candidates

### Phase 3: Validate with Fuzzing

Validate zero-day candidates using automated fuzzing to prune false positives:

```bash
python validate_zero_days.py
```

**Options:**
```bash
# Custom timeout (2 hours per target)
python validate_zero_days.py --timeout 7200

# Parallel fuzzing (8 concurrent jobs)
python validate_zero_days.py --parallel 8

# Validate specific plugin
python validate_zero_days.py --plugin vulnerable-plugin
```

**Output:**
- `fuzz_results/validated/` - Validated vulnerabilities with crash evidence
- `fuzz_results/crashes/` - Crashing inputs
- `fuzz_results/exploits/` - Generated PoC exploits

## Documentation

For detailed documentation, see:
- `docs/PHASE2_MINING.md` - Phase 2 mining documentation
- `docs/PHASE3_FUZZING.md` - Phase 3 fuzzing documentation
- `docs/QUICKSTART.md` - Full project quickstart guide
- `docs/PROJECT_STRUCTURE.md` - Project architecture

## Project Structure

```
├── generate_signatures.py             # Phase 1: Signature generation
├── mine_vulnerability_clones.py       # Phase 2: Clone mining
├── validate_zero_days.py              # Phase 3: Fuzzing validation
├── utils/                             # Utility scripts
├── fuzzing_validator/                 # Fuzzing validation system
├── vulnerability_miner/               # Mining system
├── wordpress_vulnerability_analyzer/  # Analysis system
├── signatures/                        # Generated signatures (Phase 1 output)
├── mining_results/                    # Mining results (Phase 2 output)
└── fuzz_results/                      # Fuzzing results (Phase 3 output)
```

## Requirements

- Python 3.8+
- WordPress test environment (optional, for live fuzzing)
- Dependencies: `pip install -r requirements.txt`

## Complete Research Pipeline

1. **Phase 1**: Generate signatures from known CVEs (`generate_signatures.py`)
2. **Phase 2**: Mine for vulnerability clones (`mine_vulnerability_clones.py`)
3. **Phase 3**: Validate with fuzzing (`validate_zero_days.py`)

---

**This project demonstrates automated, large-scale fuzzing validation of historical vulnerability clones - a novel approach to zero-day discovery in plugin ecosystems.**
