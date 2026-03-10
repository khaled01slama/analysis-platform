// ── SBOM Analysis Page ──────────────────────────────────────────────────
const SBOMPage = {
  _jobId: null,
  _pollTimer: null,

  async render() {
    return `
      <h1 class="text-2xl font-bold mb-1">SBOM Analysis</h1>
      <p class="text-gray-500 mb-6">Upload an SBOM file (SPDX or JSON) to scan for vulnerabilities using Grype.</p>

      <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6 max-w-3xl space-y-4">
        <div id="sbom-dropzone"
             class="border-2 border-dashed border-gray-300 rounded-xl p-10 flex flex-col items-center justify-center cursor-pointer hover:border-brand-400 transition"
             onclick="document.getElementById('sbom-file').click()">
          <svg class="w-9 h-9 text-gray-400 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/></svg>
          <p id="sbom-filename" class="text-sm text-gray-500">Click to select SBOM file (.spdx, .json)</p>
          <input id="sbom-file" type="file" class="hidden" accept=".spdx,.json" onchange="SBOMPage.onFileSelect(this)" />
        </div>

        <button id="sbom-btn" onclick="SBOMPage.startAnalysis()" disabled
                class="w-full py-2.5 rounded-lg bg-brand-600 text-white font-medium hover:bg-brand-700 disabled:opacity-50 disabled:cursor-not-allowed transition">
          Analyze SBOM
        </button>

        <div id="sbom-error" class="text-red-600 text-sm hidden"></div>
      </div>

      <div id="sbom-progress" class="max-w-3xl mt-6 hidden">
        <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6 space-y-3">
          <div class="flex items-center gap-2">
            <div class="w-5 h-5 border-3 border-brand-600 border-t-transparent rounded-full animate-spin"></div>
            <span class="font-medium">Analysis in progress…</span>
          </div>
          <div class="w-full bg-gray-200 rounded-full h-3">
            <div id="sbom-bar" class="bg-brand-600 h-3 rounded-full progress-bar" style="width:0%"></div>
          </div>
          <p id="sbom-msg" class="text-sm text-gray-500"></p>
        </div>
      </div>

      <div id="sbom-result" class="max-w-3xl mt-6 space-y-4 hidden"></div>
    `;
  },

  init() {
    this._jobId = null;
    if (this._pollTimer) clearInterval(this._pollTimer);
  },

  _selectedFile: null,

  onFileSelect(input) {
    this._selectedFile = input.files[0];
    document.getElementById('sbom-filename').textContent = this._selectedFile ? this._selectedFile.name : 'Click to select SBOM file';
    document.getElementById('sbom-btn').disabled = !this._selectedFile;
    document.getElementById('sbom-result').classList.add('hidden');
    document.getElementById('sbom-error').classList.add('hidden');
  },

  async startAnalysis() {
    if (!this._selectedFile) return;
    const btn = document.getElementById('sbom-btn');
    btn.disabled = true;
    btn.textContent = 'Uploading…';
    document.getElementById('sbom-error').classList.add('hidden');

    try {
      const res = await API.uploadSBOM(this._selectedFile);
      this._jobId = res.job_id;
      document.getElementById('sbom-progress').classList.remove('hidden');
      this._startPolling();
    } catch (e) {
      const errEl = document.getElementById('sbom-error');
      errEl.textContent = e.message;
      errEl.classList.remove('hidden');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Analyze SBOM';
    }
  },

  _startPolling() {
    this._pollTimer = setInterval(async () => {
      try {
        const st = await API.sbomStatus(this._jobId);
        const pct = Math.round(st.progress * 100);
        document.getElementById('sbom-bar').style.width = pct + '%';
        document.getElementById('sbom-msg').textContent = st.message;

        if (st.status === 'completed') {
          clearInterval(this._pollTimer);
          document.getElementById('sbom-progress').classList.add('hidden');
          this._renderResult(st.result);
        } else if (st.status === 'failed') {
          clearInterval(this._pollTimer);
          document.getElementById('sbom-progress').classList.add('hidden');
          const errEl = document.getElementById('sbom-error');
          errEl.textContent = 'Analysis failed: ' + st.message;
          errEl.classList.remove('hidden');
        }
      } catch {}
    }, 2000);
  },

  _renderResult(result) {
    const el = document.getElementById('sbom-result');
    el.classList.remove('hidden');

    const s = result.summary || {};
    const vulns = result.vulnerabilities || [];

    const vulnRows = vulns.slice(0, 50).map(v => `
      <tr class="border-b last:border-0 hover:bg-gray-50">
        <td class="py-2 pr-4 font-mono text-xs">${v.id}</td>
        <td class="py-2 pr-4"><span class="px-2 py-0.5 rounded-full text-xs font-medium
          ${v.severity==='Critical'?'bg-red-100 text-red-800':v.severity==='High'?'bg-orange-100 text-orange-800':v.severity==='Medium'?'bg-yellow-100 text-yellow-800':'bg-green-100 text-green-800'}">${v.severity}</span></td>
        <td class="py-2 pr-4">${v.package}</td>
        <td class="py-2 pr-4 font-mono text-xs">${v.version}</td>
        <td class="py-2 pr-4">${v.cvss_score ? v.cvss_score.toFixed(1) : '—'}</td>
        <td class="py-2 text-xs">${v.fix_versions?.length ? v.fix_versions.join(', ') : '—'}</td>
      </tr>
    `).join('');

    el.innerHTML = `
      <div class="bg-green-50 border border-green-200 rounded-xl p-4 flex items-center gap-3">
        <svg class="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
        <span class="font-medium text-green-700">Analysis Complete</span>
      </div>

      <div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
        ${tile('Packages', result.total_packages, 'bg-blue-100 text-blue-700')}
        ${tile('Critical', s.Critical || 0, 'bg-red-100 text-red-700')}
        ${tile('High', s.High || 0, 'bg-orange-100 text-orange-700')}
        ${tile('Medium', s.Medium || 0, 'bg-yellow-100 text-yellow-700')}
      </div>

      ${vulns.length > 0 ? `
        <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6 overflow-x-auto">
          <h2 class="text-lg font-semibold mb-3">Vulnerabilities (${vulns.length})</h2>
          <table class="w-full text-sm">
            <thead><tr class="border-b text-left text-gray-500">
              <th class="pb-2 pr-4">ID</th><th class="pb-2 pr-4">Severity</th><th class="pb-2 pr-4">Package</th>
              <th class="pb-2 pr-4">Version</th><th class="pb-2 pr-4">CVSS</th><th class="pb-2">Fix</th>
            </tr></thead>
            <tbody>${vulnRows}</tbody>
          </table>
          ${vulns.length > 50 ? `<p class="text-sm text-gray-400 mt-2">Showing 50 of ${vulns.length}</p>` : ''}
        </div>
      ` : ''}
    `;
  }
};

function tile(label, value, cls) {
  return `<div class="rounded-xl p-4 text-center ${cls}"><p class="text-2xl font-bold">${value}</p><p class="text-xs font-medium mt-1">${label}</p></div>`;
}
