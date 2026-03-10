// ── Simple hash-based router ────────────────────────────────────────────
const Router = {
  routes: {},
  currentPage: null,

  register(hash, { label, icon, render }) {
    this.routes[hash] = { label, icon, render };
  },

  navigate(hash) {
    window.location.hash = hash;
  },

  async render() {
    const hash = window.location.hash || '#dashboard';
    const route = this.routes[hash];
    if (!route) return;

    this.currentPage = hash;
    const main = document.getElementById('main-content');
    main.innerHTML = '<div class="flex items-center justify-center py-20"><div class="w-8 h-8 border-4 border-brand-600 border-t-transparent rounded-full animate-spin"></div></div>';

    try {
      const html = await route.render();
      main.innerHTML = `<div class="fade-in">${html}</div>`;
      // Run page-specific init if defined
      if (route.init) route.init();
    } catch (e) {
      main.innerHTML = `<div class="text-center py-20 text-red-500">Error loading page: ${e.message}</div>`;
    }

    this.updateNav();
  },

  updateNav() {
    const nav = document.getElementById('nav-links');
    nav.innerHTML = '';
    for (const [hash, route] of Object.entries(this.routes)) {
      const isActive = this.currentPage === hash;
      nav.innerHTML += `
        <a href="${hash}"
           class="nav-item flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition
                  ${isActive ? 'nav-active' : 'text-brand-200'}">
          ${route.icon}
          ${route.label}
        </a>`;
    }
  },

  init() {
    window.addEventListener('hashchange', () => this.render());
    if (!window.location.hash) window.location.hash = '#dashboard';
    this.render();
  }
};
