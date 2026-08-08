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

function formatDate(isoString) {
    return isoString ? new Date(isoString).toLocaleString() : '-';
}

function threatBadgeHtml(score) {
    if (score == null) return `<span class="badge-unknown">—</span>`;
    if (score > 60)  return `<span class="badge-high">${score} High</span>`;
    if (score > 20)  return `<span class="badge-medium">${score} Medium</span>`;
    return               `<span class="badge-safe">${score} Safe</span>`;
}

// ─── Load Logs ────────────────────────────────────────────────────────────────
async function loadLogs() {
    const tbody = document.getElementById('logsTableBody');
    tbody.innerHTML = `<tr><td colspan="6" class="px-6 py-8 text-center text-slate-500 animate-pulse">Loading…</td></tr>`;

    const data = await fetchApi('/api/dashboard/logs?size=200');
    if (!data || !data.content) {
        tbody.innerHTML = `<tr><td colspan="6" class="px-6 py-8 text-center text-red-400">Failed to load logs.</td></tr>`;
        return;
    }

    if (data.content.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="px-6 py-8 text-center text-slate-500">No attack logs yet.</td></tr>`;
        return;
    }

    tbody.innerHTML = '';
    data.content.forEach(log => {
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-slate-700/50 transition-colors';
        tr.innerHTML = `
            <td class="px-6 py-4 whitespace-nowrap text-slate-300 text-sm">${formatDate(log.timestamp)}</td>
            <td class="px-6 py-4 whitespace-nowrap text-blue-400 font-mono text-sm">${log.ipAddress || '-'}</td>
            <td class="px-6 py-4 whitespace-nowrap">
                <span class="bg-slate-700 text-slate-300 py-1 px-2 rounded text-xs border border-slate-600">${log.attackType || 'Unknown'}</span>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-slate-400 font-mono text-sm">${log.endpoint || '-'}</td>
            <td class="px-6 py-4 whitespace-nowrap text-slate-400 text-sm">${log.country || '-'}${log.city ? ' (' + log.city + ')' : ''}</td>
            <td class="px-6 py-4 whitespace-nowrap text-center">${threatBadgeHtml(log.threatScore)}</td>
        `;
        tbody.appendChild(tr);
    });
}

// ─── Export Buttons ───────────────────────────────────────────────────────────
document.getElementById('exportCsvBtn').addEventListener('click', () =>
    downloadFile('/api/dashboard/export/csv', 'honeypot-logs.csv'));

document.getElementById('exportPdfBtn').addEventListener('click', () =>
    downloadFile('/api/dashboard/export/pdf', 'honeypot-logs.pdf'));

// ─── Boot ─────────────────────────────────────────────────────────────────────
loadLogs();
setInterval(loadLogs, 15000);
