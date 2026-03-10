// ── App Bootstrap ───────────────────────────────────────────────────────
// SVG icons for nav
const navIcons = {
  dashboard: '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>',
  sbom: '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 21h7a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v11m0 5l4.879-4.879m0 0a3 3 0 104.243-4.242 3 3 0 00-4.243 4.242z"/></svg>',
  correlation: '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"/></svg>',
  security: '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>',
  history: '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>',
};

// Register routes
Router.register('#dashboard', {
  label: 'Dashboard',
  icon: navIcons.dashboard,
  render: () => DashboardPage.render(),
  init: () => {},
});

Router.register('#sbom', {
  label: 'SBOM Analysis',
  icon: navIcons.sbom,
  render: () => SBOMPage.render(),
  init: () => SBOMPage.init(),
});

Router.register('#correlation', {
  label: 'Correlation',
  icon: navIcons.correlation,
  render: () => CorrelationPage.render(),
  init: () => CorrelationPage.init(),
});

Router.register('#security', {
  label: 'Security Assistant',
  icon: navIcons.security,
  render: () => SecurityPage.render(),
  init: () => SecurityPage.init(),
});

Router.register('#history', {
  label: 'History',
  icon: navIcons.history,
  render: () => HistoryPage.render(),
  init: () => HistoryPage.init(),
});

// Sidebar toggle for mobile
function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebar-overlay');
  const isOpen = !sidebar.classList.contains('hidden') && !sidebar.classList.contains('lg:flex');
  
  if (sidebar.classList.contains('hidden')) {
    sidebar.classList.remove('hidden');
    sidebar.classList.add('flex', 'fixed', 'inset-y-0', 'left-0', 'z-40');
    overlay.classList.remove('hidden');
  } else if (sidebar.classList.contains('fixed')) {
    sidebar.classList.add('hidden');
    sidebar.classList.remove('flex', 'fixed', 'inset-y-0', 'left-0', 'z-40');
    overlay.classList.add('hidden');
  }
}

// Start app
Router.init();
