// ── API Client ──────────────────────────────────────────────────────────
const API = {
  async _fetch(url, opts = {}) {
    const res = await fetch('/api' + url, {
      headers: { 'Content-Type': 'application/json', ...opts.headers },
      ...opts,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || res.statusText);
    }
    return res.json();
  },

  // Health
  health()        { return this._fetch('/health'); },

  // SBOM
  async uploadSBOM(file) {
    const form = new FormData();
    form.append('file', file);
    const res = await fetch('/api/sbom/upload', { method: 'POST', body: form });
    if (!res.ok) throw new Error('Upload failed');
    return res.json();
  },
  sbomStatus(jobId) { return this._fetch(`/sbom/status/${jobId}`); },

  // Correlation
  correlationAnalyze(data) {
    return this._fetch('/correlation/analyze', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
  async correlationUpload(vanirFile, joernFile) {
    const form = new FormData();
    if (vanirFile) form.append('vanir_file', vanirFile);
    if (joernFile) form.append('joern_file', joernFile);
    const res = await fetch('/api/correlation/upload', { method: 'POST', body: form });
    if (!res.ok) throw new Error('Correlation failed');
    return res.json();
  },

  // Security
  securityQuery(query, context) {
    return this._fetch('/security/query', {
      method: 'POST',
      body: JSON.stringify({ query, context }),
    });
  },
  vulnSearch(query, limit = 10) {
    return this._fetch('/security/search', {
      method: 'POST',
      body: JSON.stringify({ query, limit }),
    });
  },

  // Dashboard
  dashboardSummary() { return this._fetch('/dashboard/summary'); },

  // History
  analyses(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this._fetch('/history/analyses' + (qs ? '?' + qs : ''));
  },
  analysisDetail(id) { return this._fetch(`/history/analysis/${id}`); },
};
