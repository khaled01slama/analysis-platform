// ── History Page ────────────────────────────────────────────────────────
const HistoryPage = {
  _page: 0,
  _limit: 15,
  _typeFilter: '',

  async render() {
    return `
      <div class="flex items-center justify-between flex-wrap gap-3 mb-6">
        <h1 class="text-2xl font-bold">Analysis History</h1>
        <div class="flex items-center gap-2">
          <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z"/></svg>
          <select id="hist-filter" onchange="HistoryPage.onFilter(this.value)"
                  class="border rounded-lg px-3 py-1.5 text-sm focus:ring-2 focus:ring-brand-400 focus:outline-none">
            <option value="">All Types</option>
            <option value="sbom_only">SBOM</option>
            <option value="correlation">Correlation</option>
            <option value="vanir_only">Vanir</option>
            <option value="joern_only">Joern</option>
            <option value="integrated">Integrated</option>
          </select>
        </div>
      </div>

      <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
        <div id="hist-table">
          <p class="text-gray-400 text-center py-8">Loading…</p>
        </div>
      </div>

      <!-- Detail modal -->
      <div id="hist-modal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 hidden" onclick="HistoryPage.closeModal()">
        <div class="bg-white rounded-2xl shadow-xl max-w-2xl w-full max-h-[80vh] overflow-auto p-6 m-4" onclick="event.stopPropagation()">
          <div id="hist-modal-content"></div>
        </div>
      </div>
    `;
  },

  init() {
    this._page = 0;
    this._typeFilter = '';
    this.loadData();
  },

  onFilter(val) {
    this._typeFilter = val;
    this._page = 0;
    this.loadData();
  },

  async loadData() {
    const params = { limit: this._limit, offset: this._page * this._limit };
    if (this._typeFilter) params.analysis_type = this._typeFilter;

    try {
      const data = await API.analyses(params);
      this._renderTable(data.analyses, data.total);
    } catch {
      document.getElementById('hist-table').innerHTML = '<p class="text-red-500 text-center py-8">Failed to load history</p>';
    }
  },

  _renderTable(analyses, total) {
    const el = document.getElementById('hist-table');
    if (!analyses.length) {
      el.innerHTML = '<p class="text-gray-400 text-center py-8">No analyses found</p>';
      return;
    }

    const rows = analyses.map(a => `
      <tr class="border-b last:border-0 hover:bg-gray-50">
        <td class="py-2 pr-4 font-mono text-gray-400">${a.id}</td>
        <td class="py-2 pr-4 whitespace-nowrap">${new Date(a.timestamp).toLocaleString()}</td>
        <td class="py-2 pr-4 font-mono text-xs max-w-[200px] truncate">${a.repo_path}</td>
        <td class="py-2 pr-4"><span class="px-2 py-0.5 rounded-full text-xs font-medium bg-brand-100 text-brand-700">${a.analysis_type}</span></td>
        <td class="py-2 pr-4"><span class="px-2 py-0.5 rounded-full text-xs font-medium
          ${a.status==='completed'?'bg-green-100 text-green-700':a.status==='failed'?'bg-red-100 text-red-700':'bg-yellow-100 text-yellow-700'}">${a.status}</span></td>
        <td class="py-2 pr-4">${a.duration ? a.duration + 's' : '—'}</td>
        <td class="py-2"><button onclick="HistoryPage.openDetail(${a.id})" class="text-brand-600 hover:text-brand-800">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
        </button></td>
      </tr>
    `).join('');

    const totalPages = Math.ceil(total / this._limit);
    const paginationHtml = totalPages > 1 ? `
      <div class="flex items-center justify-between mt-4 text-sm">
        <span class="text-gray-500">Showing ${this._page * this._limit + 1}–${Math.min((this._page+1)*this._limit, total)} of ${total}</span>
        <div class="flex gap-1">
          <button ${this._page===0?'disabled':''} onclick="HistoryPage.prevPage()" class="px-3 py-1 rounded border disabled:opacity-40 hover:bg-gray-100">Prev</button>
          <button ${this._page>=totalPages-1?'disabled':''} onclick="HistoryPage.nextPage()" class="px-3 py-1 rounded border disabled:opacity-40 hover:bg-gray-100">Next</button>
        </div>
      </div>` : '';

    el.innerHTML = `
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead><tr class="border-b text-left text-gray-500">
            <th class="pb-2 pr-4">#</th><th class="pb-2 pr-4">Date</th><th class="pb-2 pr-4">Repository</th>
            <th class="pb-2 pr-4">Type</th><th class="pb-2 pr-4">Status</th><th class="pb-2 pr-4">Duration</th><th class="pb-2"></th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      ${paginationHtml}
    `;
  },

  prevPage() { this._page = Math.max(0, this._page - 1); this.loadData(); },
  nextPage() { this._page++; this.loadData(); },

  async openDetail(id) {
    document.getElementById('hist-modal').classList.remove('hidden');
    document.getElementById('hist-modal-content').innerHTML = '<div class="flex justify-center py-8"><div class="w-6 h-6 border-3 border-brand-600 border-t-transparent rounded-full animate-spin"></div></div>';

    try {
      const d = await API.analysisDetail(id);
      let sections = '';

      if (d.vanir) {
        sections += `<h3 class="font-semibold text-gray-700 mt-4 mb-2">Vanir Results</h3>
          <div class="pl-4">${row('Vulnerabilities',d.vanir.vulnerability_count)}${row('Critical',d.vanir.critical)}${row('High',d.vanir.high)}${row('Medium',d.vanir.medium)}${row('Low',d.vanir.low)}
          ${d.vanir.cve_ids?.length ? row('CVEs', d.vanir.cve_ids.join(', ')) : ''}</div>`;
      }
      if (d.joern) {
        sections += `<h3 class="font-semibold text-gray-700 mt-4 mb-2">Joern Results</h3>
          <div class="pl-4">${row('Unused Functions',d.joern.unused_functions_count)}</div>`;
      }
      if (d.correlation) {
        sections += `<h3 class="font-semibold text-gray-700 mt-4 mb-2">Correlation</h3>
          <div class="pl-4">${row('High Risk',d.correlation.high_risk)}${row('Medium Risk',d.correlation.medium_risk)}${row('Low Risk',d.correlation.low_risk)}</div>`;
      }
      if (d.sbom) {
        sections += `<h3 class="font-semibold text-gray-700 mt-4 mb-2">SBOM Results</h3>
          <div class="pl-4">${row('Packages',d.sbom.package_count)}${row('Vulnerabilities',d.sbom.vulnerability_count)}${row('Critical',d.sbom.critical)}</div>`;
      }

      document.getElementById('hist-modal-content').innerHTML = `
        <div class="flex items-center justify-between mb-4">
          <h2 class="text-lg font-bold">Analysis #${d.id}</h2>
          <button onclick="HistoryPage.closeModal()" class="text-gray-400 hover:text-gray-600 text-xl">&times;</button>
        </div>
        <div class="space-y-1 text-sm">
          ${row('Date', new Date(d.timestamp).toLocaleString())}
          ${row('Repository', d.repo_path)}
          ${row('Type', d.analysis_type)}
          ${row('Status', d.status)}
          ${row('Duration', d.duration ? d.duration + 's' : '—')}
          ${sections}
        </div>
      `;
    } catch {
      document.getElementById('hist-modal-content').innerHTML = '<p class="text-red-500 py-4">Failed to load details</p>';
    }
  },

  closeModal() {
    document.getElementById('hist-modal').classList.add('hidden');
  },
};

function row(label, value) {
  return `<div class="flex justify-between py-1 border-b border-gray-100"><span class="text-gray-500">${label}</span><span class="font-medium">${value}</span></div>`;
}
