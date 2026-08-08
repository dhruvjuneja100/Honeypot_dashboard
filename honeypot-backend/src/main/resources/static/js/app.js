// ─── Auth ────────────────────────────────────────────────────────────────────
const authCredentials = localStorage.getItem('honeypot_auth');
if (!authCredentials) { window.location.href = '/index.html'; }

const fetchOpts = { headers: { 'Authorization': 'Basic ' + authCredentials } };

document.getElementById('logoutBtn').addEventListener('click', () => {
    localStorage.removeItem('honeypot_auth');
    window.location.href = '/index.html';
});

// ─── Active Sidebar Link ──────────────────────────────────────────────────────
(function highlightNav() {
    const currentPage = window.location.pathname.split('/').pop() || 'dashboard.html';
    document.querySelectorAll('.nav-link').forEach(link => {
        const linkPage = link.getAttribute('href').split('/').pop();
        if (linkPage === currentPage) {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });
})();

// ─── Helpers ─────────────────────────────────────────────────────────────────
async function fetchApi(endpoint) {
    try {
        const res = await fetch(endpoint, fetchOpts);
        if (res.status === 401) {
            localStorage.removeItem('honeypot_auth');
            window.location.href = '/index.html';
            return null;
        }
        return await res.json();
    } catch (err) {
        console.error('Error fetching ' + endpoint, err);
        return null;
    }
}

async function downloadFile(url, filename) {
    try {
        const res = await fetch(url, fetchOpts);
        if (!res.ok) throw new Error('Export failed');
        const blob = await res.blob();
        const blobUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = blobUrl;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(blobUrl);
    } catch (err) {
        console.error(err);
        alert('Failed to export file.');
    }
}

function generateColors(count) {
    const palette = ['#ef4444','#f97316','#f59e0b','#84cc16','#22c55e',
                     '#06b6d4','#3b82f6','#6366f1','#a855f7','#ec4899'];
    return Array.from({ length: count }, (_, i) => palette[i % palette.length]);
}

function getMarkerColor(attackType) {
    const map = {
        'SQL Injection':        '#ef4444',
        'Cross-Site Scripting': '#f97316',
        'Path Traversal':       '#3b82f6',
        'Brute Force':          '#a855f7',
        'Malicious Upload':     '#0f172a',
    };
    return map[attackType] || '#64748b';
}

// ─── Map ──────────────────────────────────────────────────────────────────────
const map = L.map('map').setView([20, 0], 2);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
    subdomains: 'abcd',
    maxZoom: 20
}).addTo(map);

// ─── Chart instances ──────────────────────────────────────────────────────────
let attackTypesChartInstance = null;
let topIpsChartInstance      = null;

// ─── Main load ────────────────────────────────────────────────────────────────
async function loadDashboardData() {

    // 1. Attack-types doughnut
    const attackTypes = await fetchApi('/api/dashboard/attacksByType');
    if (attackTypes) {
        const labels = attackTypes.map(d => d.type || 'Unknown');
        const data   = attackTypes.map(d => d.count);
        const ctx    = document.getElementById('attackTypesChart').getContext('2d');
        if (attackTypesChartInstance) attackTypesChartInstance.destroy();
        attackTypesChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: { labels, datasets: [{ data, backgroundColor: generateColors(labels.length), borderWidth: 0 }] },
            options: { responsive: true, plugins: { legend: { position: 'right', labels: { color: '#cbd5e1' } } } }
        });
    }

    // 2. Top-IPs bar chart
    const topIps = await fetchApi('/api/dashboard/topIPs');
    if (topIps) {
        const labels = topIps.map(d => d.ip);
        const data   = topIps.map(d => d.count);
        const ctx    = document.getElementById('topIpsChart').getContext('2d');
        if (topIpsChartInstance) topIpsChartInstance.destroy();
        topIpsChartInstance = new Chart(ctx, {
            type: 'bar',
            data: { labels, datasets: [{ label: 'Attack Count', data, backgroundColor: '#3b82f6', borderRadius: 4 }] },
            options: {
                responsive: true, maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true, grid: { color: '#334155' }, ticks: { color: '#94a3b8' } },
                    x: { grid: { display: false }, ticks: { color: '#94a3b8' } }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    // 3. Map markers from log data
    const logsData = await fetchApi('/api/dashboard/logs?size=200');
    if (logsData && logsData.content) {
        map.eachLayer(layer => {
            if (layer instanceof L.Marker || layer instanceof L.CircleMarker) map.removeLayer(layer);
        });

        logsData.content.forEach(log => {
            if (log.latitude && log.longitude) {
                const radius = 5 + Math.min(Math.round((log.threatScore || 0) / 20), 5);
                L.circleMarker([log.latitude, log.longitude], {
                    radius,
                    fillColor: getMarkerColor(log.attackType),
                    color: '#000', weight: 1, opacity: 1, fillOpacity: 0.75
                }).addTo(map).bindPopup(
                    `<b>IP:</b> ${log.ipAddress}<br>` +
                    `<b>Type:</b> ${log.attackType || 'Unknown'}<br>` +
                    `<b>Location:</b> ${log.city || 'Unknown'}, ${log.country || 'Unknown'}<br>` +
                    `<b>Threat Score:</b> ${log.threatScore ?? 0}`
                );
            }
        });
    }
}

loadDashboardData();
setInterval(loadDashboardData, 15000);
