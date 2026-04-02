// Configuration
const API_URL = 'http://127.0.0.1:5000/api/admin';

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    fetchDashboardData();
});

async function fetchDashboardData() {
    fetchStats();
    fetchScans();
}

/**
 * Fetches High Level Stats for the Top Output Cards
 */
async function fetchStats() {
    const container = document.getElementById('stats-container');
    
    // Inject loading cards temporarily
    container.innerHTML = `
        <div class="glass-card p-6 animate-pulse"><div class="h-4 bg-white/10 rounded w-1/3 mb-4"></div><div class="h-10 bg-white/10 rounded w-1/2"></div></div>
        <div class="glass-card p-6 animate-pulse"><div class="h-4 bg-white/10 rounded w-1/3 mb-4"></div><div class="h-10 bg-white/10 rounded w-1/2"></div></div>
        <div class="glass-card p-6 animate-pulse"><div class="h-4 bg-white/10 rounded w-1/3 mb-4"></div><div class="h-10 bg-white/10 rounded w-1/2"></div></div>
    `;

    try {
        const response = await fetch(`${API_URL}/stats`);
        if (!response.ok) {
            const errBody = await response.json().catch(()=>({}));
            throw new Error(errBody.error || "Failed to fetch stats");
        }
        const data = await response.json();

        // Calculate threat ratio purely for aesthetics
        const threatRatio = data.total > 0 ? Math.round((data.fake / data.total) * 100) : 0;

        container.innerHTML = `
            <div class="glass-card p-6 relative overflow-hidden group">
                <div class="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity"><svg class="w-16 h-16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg></div>
                <h3 class="text-sm font-medium text-gray-400">Total Scans Processed</h3>
                <div class="mt-2 flex items-baseline gap-2">
                    <span class="text-4xl font-extrabold text-white tracking-tight">${data.total}</span>
                </div>
            </div>

            <div class="glass-card p-6 relative overflow-hidden group border-t-4 border-t-danger/50">
                <h3 class="text-sm font-medium text-danger/80">Identified Scams</h3>
                <div class="mt-2 flex items-baseline gap-2">
                    <span class="text-4xl font-extrabold text-white tracking-tight">${data.fake}</span>
                    <span class="text-sm font-medium text-gray-500">(${threatRatio}% Threat Rate)</span>
                </div>
            </div>

            <div class="glass-card p-6 relative overflow-hidden group border-t-4 border-t-success/50">
                <h3 class="text-sm font-medium text-success/80">Genuine Jobs Checked</h3>
                <div class="mt-2 flex items-baseline gap-2">
                    <span class="text-4xl font-extrabold text-white tracking-tight">${data.genuine}</span>
                </div>
            </div>
        `;
    } catch (error) {
        console.error(error);
        container.innerHTML = `<div class="col-span-3 font-mono text-xs text-red-400 glass-card p-4 truncate" title="${error.message}"><b>Stats Error:</b> ${error.message} <br>Make sure MySQL Server (XAMPP etc) is running and Python terminal has no errors.</div>`;
    }
}

/**
 * Fetches the raw MySQL Database log rows
 */
async function fetchScans() {
    const tableBody = document.getElementById('table-body');
    tableBody.innerHTML = `<tr><td colspan="5" class="px-6 py-8 text-center"><div class="inline-block animate-spin rounded-full h-6 w-6 border-b-2 border-primary"></div></td></tr>`;

    try {
        const response = await fetch(`${API_URL}/scans`);
        if (!response.ok) {
            const errBody = await response.json().catch(()=>({}));
            throw new Error(errBody.error || "Failed to fetch scan logs");
        }
        const scans = await response.json();

        if (scans.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="6" class="px-6 py-12 text-center text-gray-500">No scans exist in the database yet.</td></tr>`;
            return;
        }

        tableBody.innerHTML = scans.map(scan => {
            
            // Format Risk Label
            let riskBadge = '';
            if(scan.result === 'fake' || scan.risk_score > 50) {
                riskBadge = `<span class="px-2.5 py-1 text-xs font-semibold rounded-full bg-danger/10 text-danger border border-danger/20">High Risk (${scan.risk_score})</span>`;
            } else {
                riskBadge = `<span class="px-2.5 py-1 text-xs font-semibold rounded-full bg-success/10 text-success border border-success/20">Low Risk (${scan.risk_score})</span>`;
            }

            // Keyword formatting
            let keywords = "[]";
            try { keywords = typeof scan.flagged_keywords === 'string' ? JSON.parse(scan.flagged_keywords) : scan.flagged_keywords; } catch(e){}
            const keywordTags = Array.isArray(keywords) && keywords.length > 0 
                ? keywords.slice(0,3).map(k => `<span class="px-2 py-0.5 rounded text-[10px] bg-white/5 text-gray-300 border border-white/10 uppercase tracking-wide mr-1">${k}</span>`).join('') + (keywords.length > 3 ? '<span class="text-xs text-gray-500">...</span>' : '')
                : '<span class="text-xs text-gray-600 italic">None</span>';

            // Clean date
            const dateObj = new Date(scan.created_at);
            const dateDisplay = isNaN(dateObj) ? scan.created_at : dateObj.toLocaleString();

            return `
                <tr class="hover:bg-white/[0.02] transition-colors">
                    <td class="px-6 py-4 whitespace-nowrap">
                        <div class="text-sm font-bold text-gray-300">#${scan.id}</div>
                        <div class="text-xs text-gray-500 mt-0.5">${dateDisplay}</div>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap">
                        ${riskBadge}
                    </td>
                    <td class="px-6 py-4">
                        <div class="text-xs font-mono text-gray-400 bg-black/30 px-2 py-1 rounded inline-block">IP: ${scan.ip_address || 'Unknown'}</div>
                    </td>
                    <td class="px-6 py-4 text-sm text-gray-400">
                        <div class="truncate max-w-xs group-hover:text-gray-300 transition-colors" title="${scan.job_text_excerpt}">
                            ${scan.job_text_excerpt ? scan.job_text_excerpt.substring(0, 80) + '...' : '<i>Empty Payload</i>'}
                        </div>
                    </td>
                    <td class="px-6 py-4">
                        <div class="flex flex-wrap gap-y-1">${keywordTags}</div>
                    </td>
                    <td class="px-6 py-4">
                        <button onclick="deleteScan(${scan.id})" class="text-danger hover:text-red-300 transition-colors bg-danger/10 hover:bg-danger/20 p-2 rounded-lg" title="Delete Log">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

    } catch (error) {
        console.error(error);
        tableBody.innerHTML = `<tr><td colspan="6" class="px-6 py-8 text-center text-red-400 font-mono text-xs"><b>MySQL Fetch Error:</b> ${error.message}<br><span class="text-gray-500 mt-2 block">If this says 'Database not connected', your local MySQL instance is rejecting the connection (check passwords/XAMPP).</span></td></tr>`;
    }
}

/**
 * Deletes a specific scan record from MySQL
 */
async function deleteScan(id) {
    if (!confirm('Are you sure you want to delete this specific log? This cannot be undone.')) return;
    
    try {
        const response = await fetch(`${API_URL}/delete/${id}`, { method: 'DELETE' });
        const result = await response.json();
        
        if (response.ok) {
            fetchDashboardData(); // Refresh everything
        } else {
            alert("Error: " + result.error);
        }
    } catch (error) {
        alert("Failed to connect to backend for deletion.");
    }
}
