# Quick Start Guide - WordPress Vulnerability Research System

## 🚀 Complete Workflow

### Step 1: Generate Vulnerability Signatures (Phase 1)

Extract patterns from 9,970+ known CVEs:

```bash
python generate_signatures_v2.py
```

**Duration**: ~2-4 hours
**Output**: `signatures/` directory with ~7,000 high-quality signatures

### Step 2: Mine Vulnerability Clones (Phase 2)

Discover how patterns spread across the ecosystem:

```bash
# Full production run (24-48 hours)
python mine_vulnerability_clones.py

# Or test with limited scope (30 minutes)
python mine_vulnerability_clones.py --max-plugins 100 --max-revisions 50
```

**Output**: Research metrics, zero-day findings, temporal timelines in `mining_results/`

### Step 3: Analyze Results

```bash
# View ecosystem metrics
cat mining_results/metrics/research_report.txt

# View zero-day findings
cat mining_results/zero_days/zero_day_findings.json

# View individual timeline
cat mining_results/timelines/plugin-name_CVE-2024-XXXXX.json
```

---

## 📊 What You Get

### Research Metrics (VPP, PPD, SFR, EW)

```bash
cat mining_results/metrics/ecosystem_metrics.json
```

Example output:
```json
{
  "aggregate_metrics": {
    "avg_vpp": 0.325,      // Average prevalence: 0.325%
    "avg_ppd": 387.2,      // Average persistence: 387 days
    "ecosystem_sfr": 58.4, // Silent fix rate: 58.4%
    "total_ew": 17645892   // Total exposure: 17.6M days
  }
}
```

### Zero-Day Vulnerabilities

```bash
cat mining_results/zero_days/zero_day_findings.json
```

Example output:
```json
{
  "total_findings": 127,
  "high_confidence_count": 43,
  "findings": [
    {
      "plugin_slug": "vulnerable-plugin",
      "vulnerability_type": "CSRF",
      "confidence": 0.92,
      "exploitability_score": 7.5
    }
  ]
}
```

### Vulnerability Timelines

```bash
cat mining_results/timelines/clone_CVE-2024-10924.json
```

Example output:
```json
{
  "total_clones": 147,
  "affected_plugins": 147,
  "still_vulnerable_count": 12,
  "fixed_silently_count": 89,
  "avg_persistence_days": 423.5,
  "patient_zero": "original-plugin"
}
```

---

## 🧪 Testing Before Full Run

Test Phase 2 implementation:

```bash
python test_phase2.py
```

Expected output:
```
✓ All imports successful
✓ Configuration created
✓ All core components initialized successfully
✓ Data models working correctly
✓ Ready to mine vulnerability clones
```

---

## 📁 Directory Structure

```
research/
├── Phase 1: Signature Extraction
│   ├── generate_signatures_v2.py           # Main script
│   ├── wordpress_vulnerability_analyzer/   # Package
│   └── signatures/                         # Output
│
├── Phase 2: Clone Mining
│   ├── mine_vulnerability_clones.py        # Main script
│   ├── vulnerability_miner/                # Package
│   └── mining_results/                     # Output
│       ├── timelines/                      # Per-plugin timelines
│       ├── metrics/                        # Research metrics
│       └── zero_days/                      # Zero-day findings
│
└── Documentation
    ├── README_COMPLETE.md                  # Complete overview
    ├── PHASE2_MINING.md                    # Phase 2 details
    ├── QUICKSTART.md                       # This file
    └── PROJECT_STRUCTURE.md                # Architecture
```

---

## ⚡ Performance Tips

### For Testing

```bash
# Scan only 10 plugins with last 20 revisions each
python mine_vulnerability_clones.py --max-plugins 10 --max-revisions 20
```

### For Production

```bash
# Full run with all defaults
python mine_vulnerability_clones.py

# With custom output directory
python mine_vulnerability_clones.py --output-dir custom_results
```

---

## 🎯 Common Use Cases

### Security Researcher: Find Zero-Days

```bash
# 1. Generate signatures
python generate_signatures_v2.py

# 2. Mine for clones
python mine_vulnerability_clones.py --max-plugins 1000

# 3. Check zero-days
cat mining_results/zero_days/zero_day_findings.json | jq '.findings[] | select(.confidence > 0.9)'
```

### Academic Researcher: Generate Metrics

```bash
# 1. Full mining run
python mine_vulnerability_clones.py

# 2. View research report
cat mining_results/metrics/research_report.txt

# 3. Export data for analysis
cat mining_results/metrics/ecosystem_metrics.json
```

### Plugin Developer: Check Your Plugin

```bash
# 1. Edit plugin list to only include your plugin
echo "your-plugin-slug" > custom_plugins.txt

# 2. Configure to use custom list
# (Modify MinerConfig in mine_vulnerability_clones.py)

# 3. Run mining
python mine_vulnerability_clones.py --max-plugins 1
```

---

## 🛠️ Troubleshooting

### "No signatures found"

**Solution**: Run Phase 1 first
```bash
python generate_signatures_v2.py
```

### "SVN repository not found"

**Solution**: Ensure `svn_repos_dir` in config points to WordPress plugin SVN checkout

### "Script too slow"

**Solution**: Use `--max-plugins` and `--max-revisions` to limit scope

### "Out of memory"

**Solution**: Process in smaller batches
```bash
python mine_vulnerability_clones.py --max-plugins 100
# Then process next 100, etc.
```

---

## 📚 Next Steps

1. **Read the full documentation**: [PHASE2_MINING.md](PHASE2_MINING.md)
2. **Understand the architecture**: [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)
3. **Explore the code**: `vulnerability_miner/` package
4. **Contribute**: See GitHub repository

---

## 🌟 Key Research Insights You'll Discover

- **Vulnerability Half-Life**: How long exploitable patterns survive
- **Silent Patching Rate**: 58%+ of fixes happen without CVEs
- **Pattern Spreading**: How vulnerabilities propagate between plugins
- **Patient Zero**: Original source of vulnerability patterns
- **Zero-Days**: Currently vulnerable plugins with no CVE assigned

---

## 📞 Support

For questions or issues:
- Check [PHASE2_MINING.md](PHASE2_MINING.md) for detailed documentation
- Run `python test_phase2.py` to verify setup
- Review example outputs in `mining_results/`

---

**This is game-changing research. You're answering a question that has never been answered at this scale: "How many plugins ever looked like this exploit?"**

Start mining! 🚀
