# Phase 1 Testing Guide

## Overview
This guide helps you validate the Phase 1 workflow improvements before merging to main.

**Branch**: `fix/workflow-reliability`
**Status**: Ready for testing

## Changes Made

### 1. Enhanced Git Push (CRITICAL)
- ✅ 5 retry attempts with exponential backoff
- ✅ Extended timeout to 300 seconds
- ✅ Better error messages

### 2. Database Optimization
- ✅ VACUUM before each commit
- ✅ Size reduction reporting
- ✅ Expected: 20-30% smaller commits

### 3. CVE Data Caching
- ✅ Cache nvd.json and cvelistV5
- ✅ Reduces re-downloads
- ✅ Expected: 80%+ cache hit rate

### 4. Workflow Monitoring
- ✅ Health metrics in step summary
- ✅ Database statistics
- ✅ Automatic alerts

---

## Testing Steps

### Option 1: Test with Workflow Dispatch (Recommended)

1. **Push the branch to GitHub**:
   ```bash
   git push -u origin fix/workflow-reliability
   ```

2. **Trigger workflow manually**:
   - Go to: https://github.com/RogoLabs/GhostCVEs/actions
   - Click "Ghost Hunter - Automated CVE Hunt"
   - Click "Run workflow"
   - Select branch: `fix/workflow-reliability`
   - Click "Run workflow"

3. **Monitor the run**:
   - Watch for "Optimizing database..." message
   - Check retry logic (should see "Push attempt X of 5")
   - Verify cache usage ("Using cached data")
   - Review step summary for health metrics

4. **Verify success**:
   - [ ] Workflow completes successfully
   - [ ] Database is optimized (check logs for size reduction)
   - [ ] Push succeeds (may take 1-5 attempts depending on network)
   - [ ] Health metrics appear in summary
   - [ ] No errors or warnings

### Option 2: Test Locally First

1. **Test database optimization**:
   ```bash
   python -c "
   import sqlite3
   from pathlib import Path

   db_path = 'ghost_log.db'
   if Path(db_path).exists():
       size_before = Path(db_path).stat().st_size / (1024 * 1024)

       conn = sqlite3.connect(db_path)
       conn.execute('VACUUM')
       conn.execute('ANALYZE')
       conn.close()

       size_after = Path(db_path).stat().st_size / (1024 * 1024)
       saved = ((size_before - size_after) / size_before * 100) if size_before > 0 else 0

       print(f'Database: {size_before:.2f}MB -> {size_after:.2f}MB (saved {saved:.1f}%)')
   "
   ```

2. **Test the hunt locally**:
   ```bash
   python main.py --hunt --report --no-banner
   ```

3. **Check database size**:
   ```bash
   ls -lh ghost_log.db
   ```

4. **Push to test branch**:
   ```bash
   git push -u origin fix/workflow-reliability
   ```

---

## Success Criteria

### Must Pass (Critical)
- [ ] Workflow completes without errors
- [ ] Git push succeeds (within 5 retries)
- [ ] Database optimization runs
- [ ] No data loss or corruption

### Should Pass (Important)
- [ ] Database size reduces by 15%+ after VACUUM
- [ ] Cache hit rate > 70% on second run
- [ ] Push succeeds on first attempt (if network stable)
- [ ] Health metrics show in summary

### Nice to Have
- [ ] Workflow completes in < 15 minutes
- [ ] Cache hit rate > 80%
- [ ] Database size reduces by 25%+
- [ ] No warnings in logs

---

## Monitoring After Merge

Once merged to main, monitor for:

1. **First 3 Runs** (18 hours):
   - All pushes succeed
   - No timeouts
   - Database stays optimized
   - Cache working properly

2. **First Week**:
   - Success rate > 95%
   - Average workflow time < 15 min
   - Database growth controlled
   - No critical alerts

3. **Metrics to Track**:
   ```bash
   # Check recent runs
   gh run list --limit 10

   # View specific run
   gh run view RUN_ID

   # Check database size trend
   git log --all --oneline | grep "Ghost Hunt" | head -20
   ```

---

## Troubleshooting

### If push still fails after 5 retries:

1. **Check network status**:
   ```bash
   curl -I https://github.com
   ```

2. **Check database size**:
   ```bash
   ls -lh ghost_log.db
   # If > 20MB, may need additional optimization
   ```

3. **Manual recovery**:
   ```bash
   git pull origin main
   git push origin main
   ```

### If database optimization fails:

1. **Check database integrity**:
   ```bash
   sqlite3 ghost_log.db "PRAGMA integrity_check"
   ```

2. **Backup and retry**:
   ```bash
   cp ghost_log.db ghost_log.backup.db
   sqlite3 ghost_log.db "VACUUM"
   ```

### If cache not working:

1. **Check cache key**:
   - Verify `data/nvd.json` exists
   - Check file hash: `sha256sum data/nvd.json`

2. **Clear cache manually**:
   - Go to: Settings → Actions → Caches
   - Delete `cve-data-*` caches
   - Re-run workflow

---

## Rolling Back

If critical issues occur:

1. **Revert the workflow**:
   ```bash
   git checkout main
   git checkout main -- .github/workflows/hunt.yml
   git commit -m "Revert workflow changes"
   git push origin main
   ```

2. **Or merge revert PR**:
   ```bash
   git revert HEAD
   git push
   ```

3. **Report issues**:
   - Create GitHub issue with logs
   - Include workflow run ID
   - Attach hunt.log if available

---

## Next Steps After Successful Testing

1. **Create Pull Request**:
   ```bash
   gh pr create \
     --title "Phase 1: Critical Workflow Reliability Fixes" \
     --body "$(cat <<'EOF'
   ## Summary
   Implements Phase 1 improvements for workflow reliability.

   ## Changes
   - Enhanced git push with retry logic
   - Database optimization before commits
   - Improved CVE data caching
   - Workflow health monitoring

   ## Testing
   ✅ Tested with workflow_dispatch
   ✅ All tests passed
   ✅ No errors or warnings

   ## Expected Impact
   - 95%+ push success rate
   - 20-30% database size reduction
   - 2-5 minute faster workflows

   ## Checklist
   - [x] Tested in feature branch
   - [x] No breaking changes
   - [x] Documentation updated
   - [ ] Ready to merge
   EOF
   )"
   ```

2. **Review and merge**:
   - Review changes in PR
   - Merge when ready
   - Monitor first few runs

3. **Move to Phase 2**:
   - After 1 week of stable runs
   - Implement database maintenance
   - Setup GitHub Releases archiving

---

## Support

If you need help:
- Review logs in GitHub Actions
- Check `hunt.log` artifact
- Create issue with details
- Tag: `workflow`, `phase-1`, `testing`

---

**Last Updated**: 2026-03-10
**Status**: Ready for Testing
