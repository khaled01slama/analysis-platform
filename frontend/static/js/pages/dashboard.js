// ── Dashboard Page ──────────────────────────────────────────────────────
const DashboardPage = {
  async render() {
    let data;
    try {
      data = await API.dashboardSummary();
    } catch {
      data = { total_analyses: 0, total_vulnerabilities: 0, severity_breakdown: {}, recent_analyses: [], risk_distribution: {} };
    }

    const sev = data.severity_breakdown || {};
    const risk = data.risk_distribution || {};
    const critHigh = (sev.Critical || 0) + (sev.High || 0);

    const recentRows = (data.recent_analyses || []).map(a => `
      <tr class="border-b last:border-0 hover:bg-gray-50">
        <td class="py-2 pr-4 font-mono text-gray-400">${a.id}</td>
        <td class="py-2 pr-4 whitespace-nowrap">${new Date(a.timestamp).toLocaleString()}</td>
        <td class="py-2 pr-4 font-mono text-xs max-w-[200px] truncate">${a.repo_path}</td>
        <td class="py-2 pr-4"><span class="px-2 py-0.5 rounded-full text-xs font-medium bg-brand-100 text-brand-700">${a.analysis_type}</span></td>
        <td class="py-2 pr-4"><span class="px-2 py-0.5 rounded-full text-xs font-medium ${a.status==='completed'?'bg-green-100 text-green-700':a.status==='failed'?'bg-red-100 text-red-700':'bg-yellow-100 text-yellow-700'}">${a.status}</span></td>
        <td class="py-2">${a.duration ? a.duration + 's' : '—'}</td>
      </tr>
    `).join('');

    // SVG mini bar charts for severity
    const sevEntries = Object.entries(sev);
    const maxSev = Math.max(...sevEntries.map(([,v])=>v), 1);
    const sevBars = sevEntries.map(([name, val]) => {
      const colors = {Critical:'#ef4444',High:'#f97316',Medium:'#eab308',Low:'#22c55e'};
      const h = Math.round((val / maxSev) * 140);
      return `<div class="flex flex-col items-center gap-1">
        <div class="w-12 bg-gray-100 rounded-t relative" style="height:160px">
          <div class="absolute bottom-0 w-full rounded-t" style="height:${h}px;background:${colors[name]||'#94a3b8'}"></div>
        </div>
        <span class="text-xs font-medium text-gray-600">${name}</span>
        <span class="text-sm font-bold">${val}</span>
      </div>`;
    }).join('');

    const riskEntries = Object.entries(risk);
    const totalRisk = riskEntries.reduce((s,[,v])=>s+v,0) || 1;
    const riskBars = riskEntries.map(([name, val]) => {
      const colors = {High:'#ef4444',Medium:'#f97316',Low:'#22c55e'};
      const pct = Math.round((val/totalRisk)*100);
      return `<div class="flex items-center gap-3">
        <span class="w-20 text-sm font-medium text-gray-600">${name}</span>
        <div class="flex-1 bg-gray-100 rounded-full h-5">
          <div class="h-5 rounded-full flex items-center justify-end pr-2 text-xs text-white font-bold" style="width:${Math.max(pct,8)}%;background:${colors[name]||'#94a3b8'}">${val}</div>
        </div>
        <span class="text-sm text-gray-500">${pct}%</span>
      </div>`;
    }).join('');

    return `
      <h1 class="text-2xl font-bold mb-6">Dashboard</h1>

      <!-- Stat cards -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        ${statCard('Total Analyses', data.total_analyses, 'bg-brand-600', iconActivity)}
        ${statCard('Vulnerabilities', data.total_vulnerabilities, 'bg-red-500', iconBug)}
        ${statCard('Critical + High', critHigh, 'bg-orange-500', iconShield)}
        ${statCard('Low Risk', risk.Low || 0, 'bg-green-600', iconTrend)}
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <!-- Severity chart -->
        <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          <h2 class="text-lg font-semibold mb-4">Vulnerability Severity</h2>
          ${sevEntries.length > 0 ? `<div class="flex items-end justify-center gap-6">${sevBars}</div>` : '<p class="text-gray-400 text-center py-16">No data yet</p>'}
        </div>

        <!-- Risk distribution -->
        <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          <h2 class="text-lg font-semibold mb-4">Risk Distribution</h2>
          ${riskEntries.length > 0 ? `<div class="space-y-3 pt-4">${riskBars}</div>` : '<p class="text-gray-400 text-center py-16">No data yet</p>'}
        </div>
      </div>

      <!-- Recent analyses table -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
        <h2 class="text-lg font-semibold mb-4">Recent Analyses</h2>
        ${recentRows ? `
          <div class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead><tr class="border-b text-left text-gray-500">
                <th class="pb-2 pr-4">#</th><th class="pb-2 pr-4">Date</th><th class="pb-2 pr-4">Repository</th>
                <th class="pb-2 pr-4">Type</th><th class="pb-2 pr-4">Status</th><th class="pb-2">Duration</th>
              </tr></thead>
              <tbody>${recentRows}</tbody>
            </table>
          </div>
        ` : '<p class="text-gray-400 text-center py-8">No analyses yet. Start by uploading an SBOM or running a correlation.</p>'}
      </div>
    `;
  }
};

// ── Helpers ─────────────────────────────────────────────────────────────
function statCard(label, value, color, iconSvg) {
  return `
    <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6 flex items-center gap-4">
      <div class="p-3 rounded-xl ${color}">${iconSvg}</div>
      <div>
        <p class="text-sm text-gray-500">${label}</p>
        <p class="text-2xl font-bold">${value}</p>
      </div>
    </div>`;
}

const iconActivity = '<svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>';
const iconBug = '<svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8V4m0 4a4 4 0 014 4v1a2 2 0 01-2 2h-4a2 2 0 01-2-2v-1a4 4 0 014-4zm-6 4H3m3 0v4m12-4h3m-3 0v4m-6 4v2m-4-2h8"/></svg>';
const iconShield = '<svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>';
const iconTrend = '<svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/></svg>';
