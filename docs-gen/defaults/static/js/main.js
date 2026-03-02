// Language selector
(function () {
  var btn = document.querySelector('.lang-btn');
  var popup = document.querySelector('.lang-popup');
  if (!btn || !popup) return;

  btn.addEventListener('click', function (e) {
    e.stopPropagation();
    popup.classList.toggle('open');
  });

  document.addEventListener('click', function () {
    popup.classList.remove('open');
  });

  popup.addEventListener('click', function (e) {
    var link = e.target.closest('[data-lang]');
    if (!link) return;
    e.preventDefault();
    var lang = link.getAttribute('data-lang');
    localStorage.setItem('preferred-lang', lang);
    var basePath = document.documentElement.getAttribute('data-base-path') || '';
    var path = window.location.pathname;
    // Strip base path prefix, replace lang, then re-add base path
    var pathWithoutBase = path.slice(basePath.length);
    var newPath = basePath + pathWithoutBase.replace(/^\/[a-z]{2}\//, '/' + lang + '/');
    window.location.href = newPath;
  });
})();

// Theme toggle
(function () {
  var btn = document.querySelector('.theme-toggle');
  if (!btn) return;

  // Feather Icons: sun (light mode) and moon (dark mode)
  var sunSVG = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
  var moonSVG = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';

  function getTheme() {
    var stored = localStorage.getItem('preferred-theme');
    if (stored) return stored;
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }

  function applyTheme(theme) {
    if (theme === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
    btn.innerHTML = theme === 'light' ? sunSVG : moonSVG;
  }

  applyTheme(getTheme());

  btn.addEventListener('click', function () {
    var current = getTheme();
    var next = current === 'dark' ? 'light' : 'dark';
    localStorage.setItem('preferred-theme', next);
    applyTheme(next);
  });
})();

// Mobile sidebar toggle
(function () {
  var toggle = document.querySelector('.sidebar-toggle');
  var sidebar = document.querySelector('.sidebar');
  if (!toggle || !sidebar) return;

  toggle.addEventListener('click', function () {
    sidebar.classList.toggle('open');
  });

  document.addEventListener('click', function (e) {
    if (!sidebar.contains(e.target) && e.target !== toggle) {
      sidebar.classList.remove('open');
    }
  });
})();
