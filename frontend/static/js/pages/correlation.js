// ── Correlation Page ────────────────────────────────────────────────────
const CorrelationPage = {
  _mode: 'upload', // upload | json

  async render() {
    return `
      <h1 class="text-2xl font-bold mb-1">Vulnerability Correlation</h1>
      <p class="text-gray-500 mb-6">Correlate Vanir vulnerability reports with Joern unused-function analysis to prioritize fixes.</p>

      <!-- Mode toggle -->
      <div class="flex gap-2 mb-4">
        <button id="corr-mode-upload" onclick="CorrelationPage.setMode('upload')"
                class="px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white">Upload Files</button>
        <button id="corr-mode-json" onclick="CorrelationPage.setMode('json')"
                class="px-4 py-2 rounded-lg text-sm font-medium bg-gray-100 text-gray-600 hover:bg-gray-200">Paste JSON</button>
      </div>

      <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6 max-w-5xl space-y-4">
        <!-- File upload mode -->
        <div id="corr-upload-area" class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div class="border-2 border-dashed border-gray-300 rounded-xl p-6 flex flex-col items-center justify-center cursor-pointer hover:border-brand-400 transition"
               onclick="document.getElementById('corr-vanir-file').click()">
            <svg class="w-7 h-7 text-gray-400 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/></svg>
            <p id="corr-vanir-name" class="text-sm text-gray-500">Vanir Results (.json)</p>
            <input id="corr-vanir-file" type="file" class="hidden" accept=".json" onchange="CorrelationPage.onVanirFile(this)" />
          </div>
          <div class="border-2 border-dashed border-gray-300 rounded-xl p-6 flex flex-col items-center justify-center cursor-pointer hover:border-brand-400 transition"
               onclick="document.getElementById('corr-joern-file').click()">
            <svg class="w-7 h-7 text-gray-400 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/></svg>
            <p id="corr-joern-name" class="text-sm text-gray-500">Joern Results (.json)</p>
            <input id="corr-joern-file" type="file" class="hidden" accept=".json" onchange="CorrelationPage.onJoernFile(this)" />
          </div>
        </div>

        <!-- JSON paste mode -->
        <div id="corr-json-area" class="grid grid-cols-1 sm:grid-cols-2 gap-4 hidden">
          <div>
            <label class="text-sm font-medium text-gray-600 mb-1 block">Vanir JSON</label>
            <textarea id="corr-vanir-json" rows="8"
                      class="w-full border rounded-lg p-3 text-xs font-mono focus:ring-2 focus:ring-brand-400 focus:outline-none"
                      placeholder='{"vulnerabilities": [...]}'></textarea>
          </div>
          <div>
            <label class="text-sm font-medium text-gray-600 mb-1 block">Joern JSON</label>
            <textarea id="corr-joern-json" rows="8"
                      class="w-full border rounded-lg p-3 text-xs font-mono focus:ring-2 focus:ring-brand-400 focus:outline-none"
                      placeholder='[{"name":"func","file":"path.c","line":1}]'></textarea>
          </div>
        </div>

        <button id="corr-btn" onclick="CorrelationPage.runAnalysis()"
                class="w-full py-2.5 rounded-lg bg-brand-600 text-white font-medium hover:bg-brand-700 disabled:opacity-50 transition flex items-center justify-center gap-2">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"/></svg>
          Run Correlation
        </button>
        <div id="corr-error" class="text-red-600 text-sm hidden"></div>
      </div>

      <div id="corr-result" class="max-w-5xl mt-6 space-y-6 hidden"></div>
    `;
  },

  init() { this._mode = 'upload'; },

  _vanirFile: null,
  _joernFile: null,

  setMode(mode) {
    this._mode = mode;
    document.getElementById('corr-upload-area').classList.toggle('hidden', mode !== 'upload');
    document.getElementById('corr-json-area').classList.toggle('hidden', mode !== 'json');
    document.getElementById('corr-mode-upload').className = `px-4 py-2 rounded-lg text-sm font-medium ${mode==='upload'?'bg-brand-600 text-white':'bg-gray-100 text-gray-600 hover:bg-gray-200'}`;
    document.getElementById('corr-mode-json').className = `px-4 py-2 rounded-lg text-sm font-medium ${mode==='json'?'bg-brand-600 text-white':'bg-gray-100 text-gray-600 hover:bg-gray-200'}`;
  },

  onVanirFile(input) {
    this._vanirFile = input.files[0];
    document.getElementById('corr-vanir-name').textContent = this._vanirFile?.name || 'Vanir Results (.json)';
  },
  onJoernFile(input) {
    this._joernFile = input.files[0];
    document.getElementById('corr-joern-name').textContent = this._joernFile?.name || 'Joern Results (.json)';
  },

  async runAnalysis() {
    const btn = document.getElementById('corr-btn');
    btn.disabled = true;
    btn.innerHTML = '<div class="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div> Analyzing…';
    document.getElementById('corr-error').classList.add('hidden');
    document.getElementById('corr-result').classList.add('hidden');

    try {
      let result;
      if (this._mode === 'upload') {
        result = await API.correlationUpload(this._vanirFile, this._joernFile);
      } else {
        const vanirJson = document.getElementById('corr-vanir-json').value.trim();
        const joernJson = document.getElementById('corr-joern-json').value.trim();
        result = await API.correlationAnalyze({
          vanir_data: vanirJson ? JSON.parse(vanirJson) : undefined,
          joern_data: joernJson ? JSON.parse(joernJson) : undefined,
        });
      }
      this._renderResult(result);
    } catch (e) {
      const errEl = document.getElementById('corr-error');
      errEl.textContent = e.message || 'Analysis failed';
      errEl.classList.remove('hidden');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"/></svg> Run Correlation';
    }
  },

  _renderResult(result) {
    const el = document.getElementById('corr-result');
    el.classList.remove('hidden');

    const s = result.summary;
    const corrs = result.correlations || [];
    const recs = result.recommendations || [];

    // Risk bars
    const riskData = [
      { name: 'High Risk', value: s.high_risk_count, color: '#ef4444' },
      { name: 'Medium Risk', value: s.medium_risk_count, color: '#f97316' },
      { name: 'Low Risk', value: s.low_risk_count, color: '#22c55e' },
    ];
    const maxR = Math.max(...riskData.map(d => d.value), 1);
    const riskBars = riskData.map(d => `
      <div class="flex items-center gap-3">
        <span class="w-24 text-sm font-medium">${d.name}</span>
        <div class="flex-1 bg-gray-100 rounded-full h-6">
          <div class="h-6 rounded-full flex items-center justify-end pr-3 text-xs text-white font-bold"
               style="width:${Math.max((d.value/maxR)*100,8)}%;background:${d.color}">${d.value}</div>
        </div>
      </div>
    `).join('');

    // Correlation rows
    const corrRows = corrs.map((c, i) => {
      const v = c.vulnerability;
      const riskCls = c.risk_level==='HIGH'?'bg-red-100 text-red-700':c.risk_level==='MEDIUM'?'bg-orange-100 text-orange-700':'bg-green-100 text-green-700';
      return `
        <div class="border rounded-lg">
          <button onclick="this.nextElementSibling.classList.toggle('hidden')"
                  class="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-gray-50 transition">
            <span class="font-mono text-xs flex-1">${v.id || 'N/A'}</span>
            <span class="px-2 py-0.5 rounded-full text-xs font-bold ${riskCls}">${c.risk_level}</span>
            <span class="text-xs text-gray-400">${c.is_function_unused ? 'Unused' : 'Active'}</span>
            <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
          </button>
          <div class="hidden px-4 pb-3 text-sm space-y-1 border-t pt-3">
            <p><strong>Severity:</strong> ${v.severity}</p>
            <p><strong>File:</strong> ${v.file_path || '—'}</p>
            <p><strong>Function:</strong> ${v.function_name || '—'}</p>
            <p><strong>Risk:</strong> ${c.risk_explanation}</p>
            <p><strong>Reachable:</strong> ${c.is_reachable ? 'Yes' : 'No'}</p>
            ${v.description ? `<p><strong>Description:</strong> ${v.description}</p>` : ''}
            ${v.patch_url ? `<p><strong>Patch:</strong> <a href="${v.patch_url}" target="_blank" class="text-brand-600 underline">${v.patch_url}</a></p>` : ''}
          </div>
        </div>`;
    }).join('');

    // Recommendations
    const recHtml = recs.map(r => {
      const priCls = r.priority==='CRITICAL'?'bg-red-100 text-red-700':r.priority==='HIGH'?'bg-orange-100 text-orange-700':r.priority==='MEDIUM'?'bg-yellow-100 text-yellow-700':'bg-green-100 text-green-700';
      const actions = (r.action_items||[]).map(a => `<li>${a}</li>`).join('');
      return `
        <div class="p-4 rounded-lg bg-gray-50 border">
          <div class="flex items-center gap-2 mb-1">
            <span class="px-2 py-0.5 rounded-full text-xs font-bold ${priCls}">${r.priority}</span>
            <span class="font-medium text-sm">${r.title}</span>
          </div>
          <p class="text-sm text-gray-600">${r.description}</p>
          ${actions ? `<ul class="mt-2 ml-4 list-disc text-xs text-gray-500 space-y-1">${actions}</ul>` : ''}
        </div>`;
    }).join('');

    el.innerHTML = `
      <!-- Summary tiles -->
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
        ${tile('Total Vulns', s.total_vulnerabilities, 'bg-gray-100 text-gray-700')}
        ${tile('High Risk', s.high_risk_count, 'bg-red-100 text-red-700')}
        ${tile('Medium Risk', s.medium_risk_count, 'bg-orange-100 text-orange-700')}
        ${tile('Low Risk', s.low_risk_count, 'bg-green-100 text-green-700')}
      </div>

      ${s.prioritization_effectiveness > 0 ? `
        <div class="bg-blue-50 border border-blue-200 rounded-xl p-4 flex items-center gap-3">
          <svg class="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
          <span class="text-blue-700 font-medium">Workload reduction: ${s.prioritization_effectiveness.toFixed(1)}% of vulnerabilities are in unused code</span>
        </div>` : ''}

      <!-- Risk chart -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
        <h2 class="text-lg font-semibold mb-4">Risk Distribution</h2>
        <div class="space-y-3">${riskBars}</div>
      </div>

      <!-- Correlations -->
      <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
        <h2 class="text-lg font-semibold mb-3">Correlation Details (${corrs.length})</h2>
        <div class="space-y-2">${corrRows || '<p class="text-gray-400 py-4">No correlations found</p>'}</div>
      </div>

      ${recs.length > 0 ? `
        <div class="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          <h2 class="text-lg font-semibold mb-3">Recommendations</h2>
          <div class="space-y-3">${recHtml}</div>
        </div>` : ''}
    `;
  }
};
