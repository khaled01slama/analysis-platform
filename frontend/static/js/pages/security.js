// ── Security Assistant Page ──────────────────────────────────────────────
const SecurityPage = {
  _messages: [],

  async render() {
    return `
      <div class="flex flex-col" style="height:calc(100vh - 8rem);max-width:48rem">
        <h1 class="text-2xl font-bold mb-1">Security Assistant</h1>
        <p class="text-gray-500 text-sm mb-4">Ask about CVEs, vulnerabilities, or security best practices. Powered by NVD, OSV, and AI.</p>

        <!-- Quick searches -->
        <div class="flex flex-wrap gap-2 mb-4">
          ${['CVE-2024-3094','CVE-2023-44487','Log4Shell vulnerability','OpenSSL latest CVEs'].map(q =>
            `<button onclick="SecurityPage.setInput('${q}')" class="px-3 py-1.5 bg-gray-100 hover:bg-gray-200 rounded-full text-xs font-medium text-gray-600 transition">
              <svg class="w-3 h-3 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>${q}
            </button>`
          ).join('')}
        </div>

        <!-- Messages -->
        <div id="sec-messages" class="flex-1 overflow-auto space-y-4 pb-4">
          <div class="flex flex-col items-center justify-center h-full text-gray-400">
            <svg class="w-12 h-12 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
            <p class="text-lg font-medium">Ask me about security</p>
            <p class="text-sm">Try searching for a CVE or asking about a vulnerability</p>
          </div>
        </div>

        <!-- Input -->
        <div class="flex gap-2 pt-3 border-t">
          <input id="sec-input" type="text"
                 onkeydown="if(event.key==='Enter')SecurityPage.send()"
                 placeholder="Search CVE, ask about a vulnerability…"
                 class="flex-1 px-4 py-2.5 border rounded-xl text-sm focus:ring-2 focus:ring-brand-400 focus:outline-none" />
          <button onclick="SecurityPage.send()"
                  class="px-4 py-2.5 bg-brand-600 text-white rounded-xl hover:bg-brand-700 transition">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"/></svg>
          </button>
        </div>
      </div>
    `;
  },

  init() { this._messages = []; },

  setInput(text) {
    document.getElementById('sec-input').value = text;
    document.getElementById('sec-input').focus();
  },

  async send() {
    const input = document.getElementById('sec-input');
    const q = input.value.trim();
    if (!q) return;

    this._messages.push({ role: 'user', content: q });
    input.value = '';
    this._renderMessages(true);

    try {
      const res = await API.securityQuery(q);
      this._messages.push({
        role: 'assistant',
        content: res.answer,
        sources: res.sources || [],
        confidence: res.confidence,
      });
    } catch (e) {
      this._messages.push({
        role: 'assistant',
        content: 'Error: Could not reach the security assistant API.',
        sources: [],
      });
    }
    this._renderMessages(false);
  },

  _renderMessages(showLoading) {
    const el = document.getElementById('sec-messages');

    const msgs = this._messages.map(m => {
      if (m.role === 'user') {
        return `<div class="flex justify-end"><div class="max-w-[85%] rounded-2xl rounded-br-md px-4 py-3 text-sm bg-brand-600 text-white whitespace-pre-wrap">${esc(m.content)}</div></div>`;
      }

      const sourcesHtml = (m.sources||[]).map(s =>
        `<a href="${s.url}" target="_blank" class="flex items-center gap-1 text-xs text-brand-600 hover:underline">
          <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
          ${esc(s.title || s.url)} ${s.source ? `<span class="text-gray-400">(${s.source})</span>` : ''}
        </a>`
      ).join('');

      return `<div class="flex justify-start"><div class="max-w-[85%] rounded-2xl rounded-bl-md px-4 py-3 text-sm bg-white border border-gray-200 shadow-sm whitespace-pre-wrap">
        ${esc(m.content)}
        ${sourcesHtml ? `<div class="mt-3 border-t pt-2 space-y-1"><p class="text-xs font-medium text-gray-400">Sources</p>${sourcesHtml}</div>` : ''}
        ${m.confidence > 0 ? `<p class="mt-2 text-xs text-gray-400">Confidence: ${(m.confidence*100).toFixed(0)}%</p>` : ''}
      </div></div>`;
    }).join('');

    const loadingHtml = showLoading ? `
      <div class="flex justify-start">
        <div class="bg-white border border-gray-200 rounded-2xl rounded-bl-md px-4 py-3 shadow-sm">
          <div class="w-5 h-5 border-2 border-brand-600 border-t-transparent rounded-full animate-spin"></div>
        </div>
      </div>` : '';

    el.innerHTML = msgs + loadingHtml;
    el.scrollTop = el.scrollHeight;
  }
};

function esc(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
