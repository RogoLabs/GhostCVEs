/**
 * Ghost CVE Tracker Dashboard
 * Securely loads and displays ghost CVE data
 */

let allGhosts = [];
let filteredGhosts = [];

/**
 * Load dashboard data and initialize
 */
async function loadDashboard() {
    try {
        const response = await fetch('_data/latest.json');
        const data = await response.json();

        allGhosts = data.ghosts || [];
        filteredGhosts = [...allGhosts];

        // Update statistics
        updateStatistics(data);

        // Render table
        renderGhostTable(filteredGhosts);

        // Load and render chart
        await loadAndRenderChart();

        // Setup filters
        setupFilters();

        // Update last updated time
        updateLastUpdated(data.generated_at);

    } catch (error) {
        console.error('Failed to load dashboard data:', error);
        showError('Failed to load data. Please try again later.');
    }
}

/**
 * Update statistics cards
 */
function updateStatistics(data) {
    const summary = data.summary || {};

    // Active ghosts
    const ghostCount = summary.total_ghosts || allGhosts.length;
    document.getElementById('ghostCount').textContent = ghostCount;

    // Critical count (30+ days)
    const criticalCount = allGhosts.filter(g => g.days_in_limbo >= 30).length;
    document.getElementById('criticalCount').textContent = criticalCount;

    // New today
    const oneDayAgo = new Date(Date.now() - 86400000);
    const newToday = allGhosts.filter(g => {
        const firstSeen = new Date(g.first_seen);
        return firstSeen > oneDayAgo;
    }).length;
    document.getElementById('newToday').textContent = newToday;

    // Sources count
    const sourcesCount = summary.total_sources || '-';
    document.getElementById('sourcesCount').textContent = sourcesCount;
}

/**
 * Render ghost table using secure DOM methods
 */
function renderGhostTable(ghosts) {
    const tbody = document.getElementById('ghostsBody');
    tbody.textContent = ''; // Clear existing content

    if (ghosts.length === 0) {
        const row = tbody.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 5;
        cell.className = 'loading';
        cell.textContent = 'No ghost CVEs found matching your filters.';
        return;
    }

    // Sort by days in limbo (descending)
    const sortedGhosts = [...ghosts].sort((a, b) => b.days_in_limbo - a.days_in_limbo);

    sortedGhosts.forEach(ghost => {
        const row = tbody.insertRow();

        // Apply severity class
        if (ghost.days_in_limbo >= 30) {
            row.className = 'critical';
        } else if (ghost.days_in_limbo >= 7) {
            row.className = 'warning';
        }

        // CVE ID (with link)
        const cveCell = row.insertCell();
        const cveLink = document.createElement('a');
        cveLink.href = `https://nvd.nist.gov/vuln/detail/${ghost.cve_id}`;
        cveLink.target = '_blank';
        cveLink.rel = 'noopener noreferrer';
        cveLink.textContent = ghost.cve_id;
        cveCell.appendChild(cveLink);

        // Status (with badge)
        const statusCell = row.insertCell();
        const statusBadge = document.createElement('span');
        statusBadge.className = `status-badge status-${ghost.registry_status.toLowerCase()}`;
        statusBadge.textContent = ghost.registry_status;
        statusCell.appendChild(statusBadge);

        // First Seen
        const firstSeenCell = row.insertCell();
        firstSeenCell.textContent = formatDate(ghost.first_seen);

        // Days in Limbo
        const daysCell = row.insertCell();
        daysCell.textContent = `${ghost.days_in_limbo} days`;

        // Primary Source (with link)
        const sourceCell = row.insertCell();
        if (ghost.sources && ghost.sources.length > 0) {
            const source = ghost.sources[0];
            const sourceLink = document.createElement('a');
            sourceLink.href = source.url;
            sourceLink.target = '_blank';
            sourceLink.rel = 'noopener noreferrer';
            sourceLink.textContent = source.name;
            sourceCell.appendChild(sourceLink);
        } else {
            sourceCell.textContent = 'Unknown';
        }
    });
}

/**
 * Load and render trend chart
 */
async function loadAndRenderChart() {
    try {
        const response = await fetch('_data/trends.json');
        const data = await response.json();

        const canvas = document.getElementById('trendChart');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');

        new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.timeline.map(t => t.date),
                datasets: [{
                    label: 'Active Ghosts',
                    data: data.timeline.map(t => t.count),
                    borderColor: '#6366f1',
                    backgroundColor: 'rgba(99, 102, 241, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                aspectRatio: 3,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Number of Ghosts'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Date'
                        }
                    }
                }
            }
        });
    } catch (error) {
        console.error('Failed to load chart data:', error);
    }
}

/**
 * Setup filter controls
 */
function setupFilters() {
    const searchInput = document.getElementById('searchInput');
    const statusFilter = document.getElementById('statusFilter');
    const ageFilter = document.getElementById('ageFilter');

    searchInput.addEventListener('input', applyFilters);
    statusFilter.addEventListener('change', applyFilters);
    ageFilter.addEventListener('change', applyFilters);
}

/**
 * Apply all active filters
 */
function applyFilters() {
    const searchQuery = document.getElementById('searchInput').value.toLowerCase();
    const statusFilter = document.getElementById('statusFilter').value;
    const ageFilter = document.getElementById('ageFilter').value;

    filteredGhosts = allGhosts.filter(ghost => {
        // Search filter
        if (searchQuery && !ghost.cve_id.toLowerCase().includes(searchQuery)) {
            return false;
        }

        // Status filter
        if (statusFilter && ghost.registry_status !== statusFilter) {
            return false;
        }

        // Age filter
        if (ageFilter) {
            const days = parseInt(ageFilter);
            const cutoff = new Date(Date.now() - days * 86400000);
            const firstSeen = new Date(ghost.first_seen);
            if (firstSeen < cutoff) {
                return false;
            }
        }

        return true;
    });

    renderGhostTable(filteredGhosts);
}

/**
 * Format date for display
 */
function formatDate(dateString) {
    if (!dateString) return '-';

    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

/**
 * Update last updated timestamp
 */
function updateLastUpdated(timestamp) {
    const elem = document.getElementById('lastUpdated');
    if (elem && timestamp) {
        elem.textContent = formatDate(timestamp);
    }
}

/**
 * Show error message
 */
function showError(message) {
    const tbody = document.getElementById('ghostsBody');
    tbody.textContent = '';

    const row = tbody.insertRow();
    const cell = row.insertCell();
    cell.colSpan = 5;
    cell.className = 'loading';
    cell.textContent = message;
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', loadDashboard);
