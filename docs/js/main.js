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
    btn.textContent = theme === 'light' ? '\u2600\uFE0F' : '\uD83C\uDF19';
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
