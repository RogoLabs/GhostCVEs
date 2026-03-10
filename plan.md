# GhostCVEs Improvement Plan (GitHub-Native)

**Generated**: 2026-03-10
**Version**: 2.0 - GitHub-Native Edition
**Status**: Ready for Implementation

## Executive Summary

This plan addresses the critical workflow failures in GhostCVEs using **only GitHub-native features**. No external APIs, cloud services, or paid infrastructure required.

**Last Failure**: Run #22902091249 - Network timeout pushing 12MB database after 135+ seconds

**GitHub-Native Stack**:
- ✅ GitHub Actions (automation)
- ✅ GitHub Pages (dashboard)
- ✅ GitHub Releases (archiving)
- ✅ GitHub Issues/Discussions (community)
- ✅ Cost: $0.00/month

---

## Phase 1: Critical Fixes (Week 1) - IMPLEMENT NOW

### 1.1 Fix Git Push with Retry Logic
**Priority**: CRITICAL | **Effort**: 2 hours

Update `.github/workflows/hunt.yml`:

```yaml
- name: 📤 Commit Database Updates
  run: |
    git config --local user.email "github-actions[bot]@users.noreply.github.com"
    git config --local user.name "github-actions[bot]"

    # Optimize database before commit (reduces size 20-30%)
    python -c "
    import sqlite3
    conn = sqlite3.connect('ghost_log.db')
    conn.execute('VACUUM')
    conn.execute('ANALYZE')
    conn.close()
    "

    git add ghost_log.db reports/ghost_report*.{json,csv,md} || true

    if git diff --staged --quiet; then
      echo "No changes to commit"
      exit 0
    fi

    TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M UTC")
    GHOST_COUNT=$(python -c "
    from src.storage import DatabaseManager
    print(DatabaseManager().get_statistics().get('total_ghosts', 0))
    " 2>/dev/null || echo "0")

    git commit -m "🔍 Ghost Hunt: ${TIMESTAMP} | ${GHOST_COUNT} Ghosts [via ${{ github.event_name }}]"

    # Enhanced retry with exponential backoff
    MAX_RETRIES=5
    RETRY_DELAY=10

    for i in $(seq 1 $MAX_RETRIES); do
      echo "Push attempt $i of $MAX_RETRIES"

      # Pull with rebase
      git pull --rebase origin ${{ github.ref_name }} || {
        git rebase --abort
        git pull --no-rebase origin ${{ github.ref_name }}
      }

      # Push with timeout
      if timeout 300 git push; then
        echo "✓ Push successful"
        exit 0
      fi

      if [ $i -lt $MAX_RETRIES ]; then
        echo "Waiting ${RETRY_DELAY}s..."
        sleep $RETRY_DELAY
        RETRY_DELAY=$((RETRY_DELAY * 2))  # 10s → 20s → 40s → 80s → 160s
      fi
    done

    echo "::error::Push failed after $MAX_RETRIES attempts"
    exit 1
```

**Expected**: 95%+ push success rate

### 1.2 Improve Caching
**Priority**: HIGH | **Effort**: 1 hour

```yaml
- name: 🗄️ Cache CVE Data
  uses: actions/cache@v4
  with:
    path: |
      data/nvd.json
      data/cvelistV5
    key: cve-data-${{ hashFiles('data/nvd.json') }}
    restore-keys: cve-data-

- name: 📦 Update CVE Data
  run: |
    if [ -f data/nvd.json ]; then
      AGE=$(( $(date +%s) - $(stat -c%Y data/nvd.json 2>/dev/null || stat -f%m data/nvd.json) ))
      if [ $AGE -lt 86400 ]; then
        echo "✓ Using cached data (age: ${AGE}s)"
        exit 0
      fi
    fi
    echo "Updating CVE data..."
```

**Expected**: 80%+ cache hit rate, saves 2-5 minutes/run

### 1.3 Workflow Monitoring
**Priority**: MEDIUM | **Effort**: 30 min

```yaml
- name: 📊 Health Check
  if: always()
  run: |
    echo "## Workflow Metrics" >> $GITHUB_STEP_SUMMARY
    echo "- **DB Size**: $(du -h ghost_log.db | cut -f1)" >> $GITHUB_STEP_SUMMARY
    echo "- **Ghosts**: $(sqlite3 ghost_log.db 'SELECT COUNT(*) FROM ghost_cves WHERE is_ghost=1')" >> $GITHUB_STEP_SUMMARY
    echo "- **Status**: ${{ job.status }}" >> $GITHUB_STEP_SUMMARY
```

---

## Phase 2: Database Optimization (Weeks 2-3)

### 2.1 Database Maintenance
**Priority**: HIGH | **Effort**: 4 hours

Create `src/storage/maintenance.py`:

```python
"""Database maintenance utilities."""
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

class DatabaseMaintenance:
    def __init__(self, db_path: str = "ghost_log.db"):
        self.db_path = db_path

    def vacuum(self) -> dict:
        """Optimize database."""
        conn = sqlite3.connect(self.db_path)
        size_before = Path(self.db_path).stat().st_size

        conn.execute("VACUUM")
        conn.execute("ANALYZE")
        conn.close()

        size_after = Path(self.db_path).stat().st_size

        return {
            "size_before": size_before,
            "size_after": size_after,
            "saved_percent": (1 - size_after/size_before) * 100 if size_before > 0 else 0
        }

    def archive_old_sources(self, days: int = 90) -> int:
        """Archive sources older than N days."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cutoff = datetime.utcnow() - timedelta(days=days)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS discovery_sources_archive AS
            SELECT * FROM discovery_sources WHERE 1=0
        """)

        cursor.execute("""
            INSERT INTO discovery_sources_archive
            SELECT * FROM discovery_sources WHERE discovered_at < ?
        """, (cutoff,))

        archived = cursor.rowcount

        cursor.execute("DELETE FROM discovery_sources WHERE discovered_at < ?", (cutoff,))

        conn.commit()
        conn.close()
        return archived
```

Add to workflow:

```yaml
- name: 🧹 Database Maintenance
  run: |
    python -c "
    from datetime import datetime
    from src.storage.maintenance import DatabaseMaintenance

    maint = DatabaseMaintenance()

    # Weekly VACUUM (Mondays)
    if datetime.now().weekday() == 0:
        result = maint.vacuum()
        print(f'VACUUM saved {result[\"saved_percent\"]:.1f}%')

    # Monthly archive (1st of month)
    if datetime.now().day == 1:
        archived = maint.archive_old_sources(90)
        print(f'Archived {archived} old sources')
    "
```

**Expected**: 20-30% database size reduction

### 2.2 Archive to GitHub Releases
**Priority**: MEDIUM | **Effort**: 3 hours

```yaml
- name: 📦 Monthly Archive to Releases
  if: github.event_name == 'schedule'
  run: |
    # Archive on 1st of month
    if [ $(date +%d) == "01" ]; then
      MONTH=$(date +%Y-%m)

      # Compress database
      gzip -c ghost_log.db > ghost_log_${MONTH}.db.gz

      # Get stats
      GHOSTS=$(python -c "from src.storage import DatabaseManager; print(DatabaseManager().get_statistics()['total_ghosts'])")

      # Create release
      gh release create "data-${MONTH}" \
        ghost_log_${MONTH}.db.gz \
        --title "Ghost CVE Archive - ${MONTH}" \
        --notes "Monthly database snapshot

**Ghosts**: ${GHOSTS}
**Size**: $(du -h ghost_log_${MONTH}.db.gz | cut -f1)

Download and gunzip to explore data."

      rm ghost_log_${MONTH}.db.gz
    fi

    # Archive old reports
    find reports/archive -mtime +30 -name "*.md" -delete
```

**Expected**: Repo stays < 50MB, historical data preserved

---

## Phase 3: GitHub Pages Dashboard (Weeks 4-6)

### 3.1 Static Dashboard
**Priority**: HIGH | **Effort**: 16 hours

Create `.github/workflows/pages.yml`:

```yaml
name: Deploy Dashboard

on:
  workflow_run:
    workflows: ["Ghost Hunter - Automated CVE Hunt"]
    types: [completed]

permissions:
  pages: write
  id-token: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Generate Dashboard Data
        run: |
          pip install -r requirements.txt
          mkdir -p docs/_data
          cp reports/ghost_report_*.json docs/_data/latest.json || echo "{}" > docs/_data/latest.json
          python scripts/generate_dashboard_data.py

      - uses: actions/configure-pages@v4
      - uses: actions/jekyll-build-pages@v1
        with:
          source: ./docs
      - uses: actions/upload-pages-artifact@v3
      - uses: actions/deploy-pages@v4
```

Create `docs/index.html`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Ghost CVE Tracker</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
    <style>
        body { font-family: system-ui; max-width: 1200px; margin: 0 auto; padding: 20px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .stat-card { background: #f5f5f5; padding: 20px; border-radius: 8px; text-align: center; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .critical { background-color: #fee; }
    </style>
</head>
<body>
    <h1>👻 Ghost CVE Tracker</h1>

    <div class="stats">
        <div class="stat-card">
            <h2 id="ghostCount">-</h2>
            <p>Active Ghosts</p>
        </div>
        <div class="stat-card">
            <h2 id="criticalCount">-</h2>
            <p>Critical (30+ days)</p>
        </div>
    </div>

    <canvas id="trendChart" height="80"></canvas>

    <table id="ghostTable">
        <thead>
            <tr>
                <th>CVE ID</th>
                <th>First Seen</th>
                <th>Days in Limbo</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>

    <script>
        fetch('_data/latest.json')
            .then(r => r.json())
            .then(data => {
                // Update stats safely (no innerHTML)
                document.getElementById('ghostCount').textContent = data.summary?.active_ghosts || 0;
                document.getElementById('criticalCount').textContent =
                    (data.ghosts || []).filter(g => g.days_in_limbo >= 30).length;

                // Build table using DOM methods (secure)
                const tbody = document.querySelector('#ghostTable tbody');
                (data.ghosts || []).forEach(ghost => {
                    const row = tbody.insertRow();
                    if (ghost.days_in_limbo >= 30) row.className = 'critical';

                    const cveCell = row.insertCell();
                    const link = document.createElement('a');
                    link.href = `https://nvd.nist.gov/vuln/detail/${ghost.cve_id}`;
                    link.textContent = ghost.cve_id;
                    cveCell.appendChild(link);

                    row.insertCell().textContent = new Date(ghost.first_seen).toLocaleDateString();
                    row.insertCell().textContent = ghost.days_in_limbo;
                    row.insertCell().textContent = ghost.registry_status;
                });

                // Chart
                if (data.timeline) {
                    new Chart(document.getElementById('trendChart'), {
                        type: 'line',
                        data: {
                            labels: data.timeline.map(t => t.date),
                            datasets: [{
                                label: 'Ghosts',
                                data: data.timeline.map(t => t.count),
                                borderColor: '#6366f1'
                            }]
                        }
                    });
                }
            });
    </script>
</body>
</html>
```

Create `scripts/generate_dashboard_data.py`:

```python
"""Generate dashboard data."""
import json
from datetime import datetime, timedelta
from pathlib import Path
from src.storage import DatabaseManager

def main():
    db = DatabaseManager()
    docs_data = Path("docs/_data")
    docs_data.mkdir(parents=True, exist_ok=True)

    # Get ghosts
    ghosts = db.get_ghost_cves(only_ghosts=True, limit=100)

    # Generate trends (last 30 days)
    trends = []
    for i in range(30):
        date = datetime.utcnow() - timedelta(days=29-i)
        count = len([g for g in ghosts if g.first_seen <= date])
        trends.append({"date": date.strftime("%Y-%m-%d"), "count": count})

    # Export
    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": db.get_statistics(),
        "ghosts": [
            {
                "cve_id": g.cve_id,
                "first_seen": g.first_seen.isoformat() + "Z",
                "registry_status": g.registry_status,
                "days_in_limbo": g.days_in_limbo
            }
            for g in ghosts
        ],
        "timeline": trends
    }

    with open(docs_data / "latest.json", "w") as f:
        json.dump(data, f, indent=2)

if __name__ == "__main__":
    main()
```

**Expected**: Public dashboard at `https://rogolabs.github.io/GhostCVEs`

---

## Phase 4: GitHub Integration (Month 3)

### 4.1 Automated Issues for Critical Ghosts
**Priority**: MEDIUM | **Effort**: 4 hours

Create `scripts/create_ghost_issues.py`:

```python
"""Create issues for critical ghosts."""
import subprocess
from src.storage import DatabaseManager
from src.config import APP_SETTINGS

def issue_exists(cve_id):
    result = subprocess.run(
        ["gh", "issue", "list", "--search", f"CVE: {cve_id}", "--json", "number"],
        capture_output=True, text=True
    )
    return "number" in result.stdout

def main():
    db = DatabaseManager()
    ghosts = db.get_ghost_cves(only_ghosts=True)

    for ghost in ghosts:
        if ghost.days_in_limbo >= 30 and not issue_exists(ghost.cve_id):
            sources = db.get_sources_for_cve(ghost.cve_id)
            body = f"""## Critical Ghost CVE

**{ghost.cve_id}** - {ghost.days_in_limbo} days in limbo

**Sources**: {len(sources)}
**Status**: {ghost.registry_status}

[View Dashboard](https://rogolabs.github.io/GhostCVEs)
"""
            subprocess.run([
                "gh", "issue", "create",
                "--title", f"Critical Ghost: {ghost.cve_id}",
                "--body", body,
                "--label", "critical-ghost"
            ])

if __name__ == "__main__":
    main()
```

Add to workflow:

```yaml
- name: 🚨 Create Issues
  if: github.event_name == 'schedule'
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: python scripts/create_ghost_issues.py
```

---

## Success Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Workflow Success Rate | > 95% | ~90% |
| Push Success Rate | > 98% | ~85% |
| Database Size | < 15MB | 12MB |
| Workflow Duration | < 15 min | ~14 min |
| Repo Size | < 50MB | Growing |
| Dashboard Load Time | < 2s | N/A |

---

## Implementation Checklist

### Week 1 (CRITICAL)
- [ ] Implement retry logic with exponential backoff
- [ ] Add database VACUUM before commits
- [ ] Improve caching for CVE data
- [ ] Add workflow monitoring
- [ ] Test in feature branch
- [ ] Merge when 95%+ success rate achieved

### Weeks 2-3
- [ ] Create database maintenance module
- [ ] Setup monthly GitHub Releases archiving
- [ ] Implement report cleanup
- [ ] Add error handling and backups
- [ ] Performance testing

### Weeks 4-6
- [ ] Build GitHub Pages dashboard
- [ ] Create data generation scripts
- [ ] Design responsive UI
- [ ] Test dashboard functionality
- [ ] Deploy to Pages

### Month 3
- [ ] Implement GitHub Issues integration
- [ ] Add weekly discussion summaries (optional)
- [ ] Complete documentation
- [ ] Final testing and validation

---

## Rollback Procedures

**If git push fails**:
```bash
# Manual recovery
git pull origin main
git push origin main
```

**If database corrupted**:
```bash
# Restore from backup
cp backups/ghost_log_LATEST.db ghost_log.db
```

**If workflow broken**:
```bash
# Revert workflow file
git checkout origin/main -- .github/workflows/hunt.yml
git commit -m "Revert workflow changes"
git push
```

---

## Cost Analysis

| Component | Solution | Cost |
|-----------|----------|------|
| Automation | GitHub Actions | $0 (free tier) |
| Storage (database) | GitHub Releases | $0 (unlimited) |
| Web hosting | GitHub Pages | $0 |
| CDN/SSL | GitHub Pages | $0 |
| Issue tracking | GitHub Issues | $0 |
| Community | GitHub Discussions | $0 |
| Caching | Actions Cache (10GB) | $0 |
| **TOTAL** | **All GitHub-Native** | **$0/month** |

---

## Next Steps

1. **Review this plan** - Validate approach
2. **Create feature branch** - `git checkout -b fix/workflow-reliability`
3. **Implement Phase 1** - Critical fixes first
4. **Test thoroughly** - Run 10+ times, verify 95%+ success
5. **Merge to main** - After validation
6. **Monitor for 1 week** - Ensure stable
7. **Proceed to Phase 2** - Build on success

---

**Status**: Ready to implement
**Dependencies**: None (100% GitHub-native)
**Risk**: Low (all changes are reversible)
**Timeline**: 3 months to full implementation
**Cost**: $0.00

