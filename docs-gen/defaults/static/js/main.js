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

// Site search (⌘K / Ctrl+K)
(function () {
  var overlay = document.getElementById('search-overlay');
  var input = document.getElementById('search-input');
  var resultsList = document.getElementById('search-results');
  if (!overlay || !input || !resultsList) return;

  var searchBtn = document.querySelector('.search-btn');
  var pagesData = null; // cached pages-data.json
  var activeIndex = -1;

  function getCurrentLang() {
    return document.documentElement.getAttribute('lang') || 'en';
  }

  function getBasePath() {
    return document.documentElement.getAttribute('data-base-path') || '';
  }

  function openSearch() {
    overlay.classList.add('open');
    input.value = '';
    resultsList.innerHTML = '';
    activeIndex = -1;
    input.focus();
    loadPagesData();
  }

  function closeSearch() {
    overlay.classList.remove('open');
    input.value = '';
    resultsList.innerHTML = '';
    activeIndex = -1;
  }

  function loadPagesData() {
    if (pagesData) return;
    var basePath = getBasePath();
    fetch(basePath + '/pages-data.json')
      .then(function (res) { return res.json(); })
      .then(function (data) { pagesData = data; })
      .catch(function () { pagesData = []; });
  }

  function escapeRegExp(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function highlightText(text, query) {
    if (!query) return text;
    var escaped = escapeRegExp(query);
    var re = new RegExp('(' + escaped + ')', 'gi');
    return text.replace(re, '<mark>$1</mark>');
  }

  function buildSnippet(body, query) {
    if (!query || !body) return '';
    var lower = body.toLowerCase();
    var idx = lower.indexOf(query.toLowerCase());
    var start, end, snippet;
    if (idx === -1) {
      snippet = body.substring(0, 120);
    } else {
      start = Math.max(0, idx - 40);
      end = Math.min(body.length, idx + query.length + 80);
      snippet = (start > 0 ? '...' : '') + body.substring(start, end) + (end < body.length ? '...' : '');
    }
    return highlightText(snippet, query);
  }

  function search(query) {
    if (!pagesData || !query) {
      resultsList.innerHTML = '';
      activeIndex = -1;
      return;
    }

    var lang = getCurrentLang();
    var q = query.toLowerCase();

    // Score and filter
    var scored = [];
    for (var i = 0; i < pagesData.length; i++) {
      var page = pagesData[i];
      if (page.lang !== lang) continue;

      var score = 0;
      var titleLower = page.title.toLowerCase();
      var bodyLower = (page.body || '').toLowerCase();

      if (titleLower.indexOf(q) !== -1) {
        score += 10;
        // Bonus for exact title match
        if (titleLower === q) score += 5;
      }
      if (bodyLower.indexOf(q) !== -1) {
        score += 3;
      }
      if (page.section.toLowerCase().indexOf(q) !== -1) {
        score += 1;
      }

      if (score > 0) {
        scored.push({ page: page, score: score });
      }
    }

    // Sort by score descending
    scored.sort(function (a, b) { return b.score - a.score; });

    // Limit results
    var results = scored.slice(0, 20);

    if (results.length === 0) {
      resultsList.innerHTML = '<li class="search-no-results">No results found.</li>';
      activeIndex = -1;
      return;
    }

    var html = '';
    for (var j = 0; j < results.length; j++) {
      var r = results[j];
      var snippet = buildSnippet(r.page.body, query);
      html += '<li data-url="' + r.page.url + '">'
        + '<div class="search-result-title">' + highlightText(r.page.title, query) + '</div>'
        + (snippet ? '<div class="search-result-snippet">' + snippet + '</div>' : '')
        + '</li>';
    }
    resultsList.innerHTML = html;
    activeIndex = -1;
  }

  function setActive(index) {
    var items = resultsList.querySelectorAll('li[data-url]');
    if (items.length === 0) return;
    // Remove previous active
    for (var i = 0; i < items.length; i++) {
      items[i].classList.remove('active');
    }
    if (index < 0) index = items.length - 1;
    if (index >= items.length) index = 0;
    activeIndex = index;
    items[activeIndex].classList.add('active');
    items[activeIndex].scrollIntoView({ block: 'nearest' });
  }

  function navigateToActive() {
    var items = resultsList.querySelectorAll('li[data-url]');
    if (activeIndex >= 0 && activeIndex < items.length) {
      var url = items[activeIndex].getAttribute('data-url');
      if (url) {
        closeSearch();
        window.location.href = url;
      }
    }
  }

  // Event: search button
  if (searchBtn) {
    searchBtn.addEventListener('click', function (e) {
      e.stopPropagation();
      openSearch();
    });
  }

  // Use capture phase to intercept keys before browser default behavior
  // (e.g. ESC clearing input text in some browsers)
  document.addEventListener('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      overlay.classList.contains('open') ? closeSearch() : openSearch();
      return;
    }
    if (!overlay.classList.contains('open')) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      closeSearch();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive(activeIndex + 1);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive(activeIndex - 1);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      navigateToActive();
    }
  }, true); // capture phase

  // Event: click overlay background to close
  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) {
      closeSearch();
    }
  });

  // Event: click result item
  resultsList.addEventListener('click', function (e) {
    var li = e.target.closest('li[data-url]');
    if (!li) return;
    var url = li.getAttribute('data-url');
    if (url) {
      closeSearch();
      window.location.href = url;
    }
  });

  // Event: input for live search
  var debounceTimer = null;
  input.addEventListener('input', function () {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(function () {
      search(input.value.trim());
    }, 150);
  });
})();
