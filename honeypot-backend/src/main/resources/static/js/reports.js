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
        link.classList.toggle('active', linkPage === currentPage);
    });
})();

// ─── Helpers ─────────────────────────────────────────────────────────────────
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

function formatAttackLabel(raw) {
    const map = {
        'SQL_INJECTION':    'SQL Injection',
        'XSS':              'Cross-Site Scripting',
        'PATH_TRAVERSAL':   'Path Traversal',
        'BRUTE_FORCE':      'Brute Force',
        'MALICIOUS_UPLOAD': 'Malicious Upload',
        'UNKNOWN':          'Unknown'
    };
    return map[(raw || '').toUpperCase()] || raw || 'Unknown';
}

// ─── Summary ──────────────────────────────────────────────────────────────────
async function loadSummary() {
    try {
        const res  = await fetch('/api/reports/summary', fetchOpts);
        if (!res.ok) return;
        const data = await res.json();

        const totalEl = document.getElementById('totalAttacksCount');
        if (totalEl) totalEl.textContent = data.totalAttacks ?? 0;

        const topTypeEl = document.getElementById('topAttackType');
        if (topTypeEl && data.topAttackTypes && data.topAttackTypes.length > 0) {
            topTypeEl.textContent = formatAttackLabel(data.topAttackTypes[0].type);
        }

        const topIpEl = document.getElementById('topAttackerIp');
        if (topIpEl && data.topIps && data.topIps.length > 0) {
            topIpEl.textContent = data.topIps[0].ip || 'Unknown';
        }
    } catch (e) {
        console.error('Failed to load summary:', e);
    }
}

// ─── Alerts Table ─────────────────────────────────────────────────────────────
async function loadAlerts() {
    const tbody = document.getElementById('alertsTableBody');
    tbody.innerHTML = `<tr><td colspan="4" class="px-6 py-8 text-center text-slate-500 animate-pulse">Loading…</td></tr>`;

    try {
        const res    = await fetch('/api/reports/alerts', fetchOpts);
        const alerts = await res.json();

        if (!alerts || alerts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="px-6 py-8 text-center text-slate-500">No high-severity alerts found.</td></tr>`;
            return;
        }

        tbody.innerHTML = '';
        alerts.forEach(alert => {
            const date  = new Date(alert.timestamp).toLocaleString();
            const ip    = alert.attackLog?.ipAddress || 'Unknown';
            const score = alert.threatScore ?? 0;
            const tr    = document.createElement('tr');
            tr.className = 'hover:bg-slate-700/20 transition-colors';
            tr.innerHTML = `
                <td class="px-6 py-4 whitespace-nowrap text-slate-300 text-sm">${date}</td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="bg-slate-700 text-slate-300 py-1 px-2 rounded text-xs border border-slate-600 font-bold">
                        ${formatAttackLabel(alert.alertType)}
                    </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-blue-400 font-mono text-sm">${ip}</td>
                <td class="px-6 py-4 whitespace-nowrap text-center">
                    <span class="bg-red-500/20 text-red-400 border border-red-500/30 py-1 px-2 rounded text-xs font-bold">${score} High</span>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error('Failed to load alerts:', e);
        tbody.innerHTML = `<tr><td colspan="4" class="px-6 py-8 text-center text-red-500">Error loading alerts.</td></tr>`;
    }
}

// ─── Export Buttons ───────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('exportAlertsCsvBtn')?.addEventListener('click', () =>
        downloadFile('/api/reports/export?format=csv', 'alerts_report.csv'));

    document.getElementById('exportAlertsPdfBtn')?.addEventListener('click', () =>
        downloadFile('/api/reports/export?format=pdf', 'alerts_report.pdf'));
});

// ─── Boot ─────────────────────────────────────────────────────────────────────
loadSummary();
loadAlerts();
setInterval(() => { loadSummary(); loadAlerts(); }, 15000);
