# Aggressive Parallelization Guide

## TL;DR - Make It Fast!

```bash
# Just run it - auto-detects optimal workers
python mine_vulnerability_clones.py --scan-mode releases --max-plugins 100

# See what's happening in real-time
python mine_vulnerability_clones.py --scan-mode releases --max-plugins 100 --verbose

# Go even more aggressive
python mine_vulnerability_clones.py --scan-mode releases --max-plugins 100 --workers 64
```

## Why Low CPU Usage is Normal

**The Problem**: "My CPU is barely used - only 5-10%!"

**The Answer**: This is **I/O-bound work**, not CPU-bound work.

### What's Actually Happening

When mining vulnerability clones, 95% of time is spent:
- ⏳ Waiting for SVN operations (`svn list`, `svn cat`, `svn log`)
- ⏳ Waiting for disk I/O (reading cached files)
- ⏳ Waiting for network I/O (if SVN is remote)

Only 5% of time is actual CPU work:
- ✅ Regex pattern matching
- ✅ Building timelines
- ✅ Writing JSON outputs

**CPU timeline**:
```
Worker 1: [SVN wait...................][CPU 1ms][SVN wait.................][CPU 1ms]
Worker 2: [SVN wait...................][CPU 1ms][SVN wait.................][CPU 1ms]
Worker 3: [SVN wait...................][CPU 1ms][SVN wait.................][CPU 1ms]
Worker 4: [SVN wait...................][CPU 1ms][SVN wait.................][CPU 1ms]
```

**Solution**: Use MANY more workers so while most wait, some are processing.

## Auto-Detected Workers (Default)

**Formula**: `Workers = CPU_count × 4`

### Examples

| CPU Cores | Auto Workers | Why                              |
|-----------|--------------|----------------------------------|
| 4         | 16           | While 12 wait for I/O, 4 process |
| 8         | 32           | While 24 wait for I/O, 8 process |
| 16        | 64           | While 48 wait for I/O, 16 process|
| 32        | 128          | While 96 wait for I/O, 32 process|

### How to Check

```bash
# See auto-detection
python mine_vulnerability_clones.py --scan-mode releases --max-plugins 100

# Output shows:
# Auto-detected 8 CPUs, using 32 workers (4x for I/O-bound)
```

## Verbose Mode - See What Workers Are Doing

```bash
python mine_vulnerability_clones.py \
  --scan-mode releases \
  --max-plugins 100 \
  --verbose
```

### Output Examples

```
[Worker-12345] START: contact-form-7
[Worker-12346] Getting plugin path for woocommerce
[Worker-12347] Getting revisions for akismet (mode: releases)
[Worker-12348] Scanning 15 revisions for jetpack
[Worker-12345]   Rev 1/12 (r2547890) for contact-form-7
[Worker-12345]     Found 143 PHP files
[Worker-12349] START: elementor
[Worker-12346]   Rev 3/25 (r2598123) for woocommerce
[Worker-12347]     MATCH in includes/class-akismet.php! (2 matches)
[Worker-12345] DONE: contact-form-7 - 0 total matches
[Worker-12348] DONE: jetpack - 5 total matches
```

**What You See**:
- Each worker has unique PID
- Real-time progress per plugin
- SVN operations being performed
- Matches found immediately
- When workers finish

**Filter by worker**:
```bash
# See only one worker
python mine_vulnerability_clones.py ... --verbose | grep "Worker-12345"

# Count active workers
python mine_vulnerability_clones.py ... --verbose | grep "START:" | wc -l
```

## Manual Worker Tuning

### Start Conservative
```bash
--workers 16  # 2x your CPU count
```

### Go Aggressive
```bash
--workers 32  # 4x CPU count (default)
--workers 64  # 8x CPU count (very aggressive)
--workers 128 # 16x CPU count (maximum)
```

### When to Increase Workers

**Increase workers if**:
1. ✅ CPU usage is very low (<20%)
2. ✅ Workers finish quickly, system not busy
3. ✅ You have plenty of RAM (>16GB)
4. ✅ SVN operations are slow

**Don't increase if**:
1. ❌ Already hitting 80%+ CPU
2. ❌ Out of memory errors
3. ❌ SVN timeout errors
4. ❌ System becomes unresponsive

### Finding Your Optimal Count

**Step 1**: Start with auto (CPU × 4)
```bash
python mine_vulnerability_clones.py --scan-mode releases --max-plugins 20
# Note the time: e.g., 2 minutes
```

**Step 2**: Double the workers
```bash
python mine_vulnerability_clones.py --scan-mode releases --max-plugins 20 --workers 64
# Note the time: e.g., 1 minute
```

**Step 3**: Keep doubling until diminishing returns
```bash
--workers 128  # e.g., 45 seconds (not much better)
```

**Optimal**: Use the count before diminishing returns kick in.

## Monitoring Performance

### Real-Time Progress

```bash
python mine_vulnerability_clones.py --scan-mode releases --max-plugins 100
```

Output shows:
```
Progress: 50/100 (50.0%) | ETA: 2.5min | Speed: 3.2s/plugin
```

### Watch System Resources

**Terminal 1**: Run mining
```bash
python mine_vulnerability_clones.py --scan-mode releases --max-plugins 100 --verbose
```

**Terminal 2**: Monitor
```bash
# Watch process count
watch -n 1 'ps aux | grep python | wc -l'

# Watch CPU and memory
htop

# Watch I/O
iotop
```

### Expected Metrics

**Good parallelization**:
- Process count: ~num_workers + 1
- CPU per core: 10-30% (I/O bound)
- I/O wait: High (red in htop)
- Memory: Moderate increase

**Bad parallelization**:
- Process count: 2-3 (not parallel)
- CPU: Single core at 100%
- I/O wait: Low

## Common Scenarios

### Scenario 1: "It's too slow!"

**Check**:
```bash
# How many workers?
python mine_vulnerability_clones.py ... --verbose | grep "Auto-detected"
```

**Fix**:
```bash
# Double the workers
--workers 64
```

### Scenario 2: "I see workers start but nothing happens"

**This is normal!** Workers are waiting for SVN operations.

**Verify with verbose**:
```bash
--verbose
```

You'll see:
```
[Worker-123] Getting revisions for plugin-name (mode: releases)
# ^ This can take 10-30 seconds for SVN
```

### Scenario 3: "I want maximum speed"

**Use all optimizations**:
```bash
python mine_vulnerability_clones.py \
  --scan-mode releases \        # Faster than commits
  --max-plugins 100 \           # Limit scope
  --max-revisions 20 \          # Limit revisions
  --workers 64                  # Aggressive workers
```

**First run**: Builds cache (~5 min)
**Second run**: Uses cache (~30 sec)

### Scenario 4: "Out of memory / file descriptor errors"

**Reduce workers**:
```bash
--workers 16  # More conservative
```

**Or increase system limits**:
```bash
# Increase file descriptors
ulimit -n 4096

# Check memory
free -h
```

## Performance Targets

### Expected Times (100 plugins, releases mode)

| Workers | First Run | Cached Run |
|---------|-----------|------------|
| 0 (auto)| 2-3 min   | 20-30 sec  |
| 16      | 3-4 min   | 25-35 sec  |
| 32      | 2-3 min   | 20-30 sec  |
| 64      | 1.5-2 min | 15-20 sec  |
| 128     | 1-1.5 min | 10-15 sec  |

### Speedup Calculation

**Baseline (sequential)**: 60 minutes
**With 32 workers**: 2-3 minutes
**Speedup**: 20-30x faster

**Why not 32x?**
- Overhead from worker coordination
- SVN is the bottleneck (can't parallelize within plugin)
- Some plugins finish faster than others

## Best Practices

### ✅ Do This

1. **Start with auto-detect**
   ```bash
   python mine_vulnerability_clones.py --scan-mode releases --max-plugins 100
   ```

2. **Use verbose to understand what's happening**
   ```bash
   --verbose
   ```

3. **Tune workers based on observation**
   ```bash
   --workers 64  # If system not busy
   ```

4. **Let it build cache on first run**
   - First run: Slow (builds cache)
   - Future runs: Fast (uses cache)

### ❌ Don't Do This

1. **Don't use CPU count as worker count**
   ```bash
   --workers 8  # Too few for I/O-bound work
   ```

2. **Don't panic about low CPU**
   - This is normal for I/O-bound work
   - More workers won't increase CPU much

3. **Don't clear cache between runs**
   ```bash
   rm -rf data/cache/  # DON'T DO THIS
   ```
   - Cache makes future runs 100x faster

4. **Don't use too many workers on small RAM**
   - Each worker uses ~50-100MB
   - 128 workers = ~6-12GB RAM

## Troubleshooting

### Issue: "Nothing happening, no output"

**Solution**: Enable verbose
```bash
--verbose
```

### Issue: "Workers keep timing out"

**Solution**: Increase timeouts in config
```python
MinerConfig(
    svn_log_timeout=600,  # 10 minutes
    svn_cat_timeout=240,  # 4 minutes
)
```

### Issue: "System becomes unresponsive"

**Solution**: Reduce workers
```bash
--workers 16
```

### Issue: "Slow progress, low CPU"

**Solution**: This is expected! Increase workers instead
```bash
--workers 64
```

## Summary

**Key Takeaways**:
1. ⚡ Use auto-detect: `--workers 0` (default)
2. 🔍 Use verbose to see what's happening: `--verbose`
3. 📈 I/O-bound = many workers, low CPU is normal
4. 🚀 More workers = more parallelism (up to a point)
5. 💾 Cache makes repeat runs 100x faster

**Quick Commands**:
```bash
# Fastest (auto workers + verbose)
python mine_vulnerability_clones.py --scan-mode releases --max-plugins 100 --verbose

# Ultra aggressive (64 workers)
python mine_vulnerability_clones.py --scan-mode releases --max-plugins 100 --workers 64

# Monitor in real-time
watch -n 1 'ps aux | grep python | wc -l'
```

---

**Now go make those CPUs work (by waiting efficiently)!** 🚀
