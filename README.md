# WordPress Vulnerability Research

Automated discovery and validation of zero-day vulnerabilities in WordPress plugins through historical vulnerability pattern mining and fuzzing-based validation.

## Quick Start: Running Phase 3

Phase 3 validates zero-day candidates from Phase 2 using automated fuzzing to prune false positives and generate proof-of-concept exploits.

### Basic Usage

Validate all Phase 2 zero-day candidates:

```bash
python validate_zero_days.py
```

### Custom Configuration

```bash
# Fuzz with custom timeout (2 hours per target)
python validate_zero_days.py --timeout 7200

# Limit fuzzing scope
python validate_zero_days.py --max-candidates 50

# Use parallel fuzzing (8 concurrent jobs)
python validate_zero_days.py --parallel 8

# Validate specific plugin
python validate_zero_days.py --plugin vulnerable-plugin

# Validate specific vulnerability type
python validate_zero_days.py --vuln-type CSRF
```

### What Phase 3 Does

1. Loads zero-day candidates from Phase 2
2. Generates fuzzing harnesses for each vulnerability type
3. Runs automated fuzzing campaigns
4. Collects crashing inputs as proof of exploitability
5. Prunes false positives (no crash = not vulnerable)
6. Generates validated zero-days with PoC exploits

### Output

Results are saved in:
- `fuzz_results/validated/` - Validated vulnerabilities with crash evidence
- `fuzz_results/crashes/` - Crashing inputs
- `fuzz_results/exploits/` - Generated PoC exploits
- `fuzz_results/false_positives/` - Pruned candidates

## Documentation

For detailed documentation, see:
- `docs/PHASE3_FUZZING.md` - Complete Phase 3 documentation
- `docs/QUICKSTART.md` - Full project quickstart guide
- `docs/PROJECT_STRUCTURE.md` - Project architecture

## Project Structure

```
├── validate_zero_days.py              # Phase 3 CLI entry point
├── fuzzing_validator/                 # Fuzzing validation system
├── vulnerability_miner/               # Phase 2 mining system
├── wordpress_vulnerability_analyzer/  # Phase 1 analysis
├── fuzz_targets/                      # Generated fuzzing targets
└── fuzz_results/                      # Fuzzing results
```

## Requirements

- Python 3.8+
- WordPress test environment (optional, for live fuzzing)
- Dependencies: `pip install -r requirements.txt`

## Research Pipeline

1. **Phase 1**: Signature generation from known CVEs
2. **Phase 2**: Historical vulnerability clone mining
3. **Phase 3**: Fuzzing-based validation (you are here)

---

**This project demonstrates automated, large-scale fuzzing validation of historical vulnerability clones - a novel approach to zero-day discovery in plugin ecosystems.**
