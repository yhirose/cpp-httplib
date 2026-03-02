# docs-gen

A static site generator for multi-language documentation. Markdown content, Tera templates, and syntax highlighting — all in a single binary.

## Quick Start

```bash
# 1. Scaffold a new project
docs-gen init my-docs

# 2. Start the local dev server with live-reload
docs-gen serve my-docs --open

# 3. Build for production
docs-gen build my-docs --out docs
```

---

## Commands

### `init [DIR]`

Creates a new project scaffold in `DIR` (default: `.`).

Generated files:

```
config.toml
pages/
  en/index.md
  ja/index.md
templates/
  base.html
  page.html
  portal.html
static/
  css/main.css
  js/main.js
```

Existing files are never overwritten.

---

### `serve [SRC] [--port PORT] [--open]`

Builds the site into a temporary directory and serves it locally. Watches for changes and live-reloads the browser automatically.

| Option | Default | Description |
|--------|---------|-------------|
| `SRC` | `.` | Source directory |
| `--port` | `8080` | HTTP server port |
| `--open` | — | Open browser on startup |

---

### `build [SRC] [--out OUT]`

Generates the static site from source.

| Option | Default | Description |
|--------|---------|-------------|
| `SRC` | `.` | Source directory |
| `--out` | `docs` | Output directory |

---

## Source Directory Structure

Only `config.toml` and `pages/` are required. `templates/` and `static/` are optional — when absent, built-in defaults are used automatically.

```
my-docs/
├── config.toml          # Site configuration (required)
├── pages/               # Markdown content (required)
│   ├── en/
│   │   ├── index.md         # Portal page (homepage, no sidebar)
│   │   └── guide/
│   │       ├── index.md     # Section index
│   │       ├── 01-intro.md
│   │       └── 02-usage.md
│   └── ja/
│       └── ...
├── templates/           # Override built-in HTML templates (optional)
│   ├── base.html
│   ├── page.html
│   └── portal.html
└── static/              # Override built-in CSS/JS/assets (optional)
    ├── css/main.css
    └── js/main.js
```

---

## config.toml

```toml
[site]
title = "My Project"
version = "1.0.0"                           # Optional. Shown in header.
hostname = "https://example.github.io"      # Optional. Combined with base_path for full URLs.
base_path = "/my-project"                   # URL prefix. Use "" for local-only.

[[nav]]
label = "Guide"
path = "guide/"                             # Internal section path (resolved per language)
icon_svg = '<svg ...>...</svg>'             # Optional inline SVG icon

[[nav]]
label = "GitHub"
url = "https://github.com/your/repo"        # External URL
icon_svg = '<svg ...>...</svg>'

[i18n]
langs = ["en", "ja"]    # First entry is the default language

[highlight]
dark_theme = "base16-eighties.dark"   # Dark mode theme
light_theme = "InspiredGitHub"         # Light mode theme (optional)
```

### `[site]`

| Key | Required | Description |
|-----|----------|-------------|
| `title` | yes | Site title displayed in the header |
| `version` | no | Version string displayed in the header |
| `hostname` | no | Base hostname (e.g. `"https://user.github.io"`). Combined with `base_path` to form `site.base_url` in templates. |
| `base_path` | no | URL path prefix. Use `"/repo-name"` for GitHub Pages, `""` for local development. |

### `[[nav]]` — Toolbar Buttons

Defines buttons in the site header. Each entry supports:

| Key | Required | Description |
|-----|----------|-------------|
| `label` | yes | Button label text |
| `path` | no | Internal section path relative to `<lang>/` (e.g. `"guide/"`). Resolved using the current language. |
| `url` | no | Absolute external URL. Takes precedence over `path` if both are set. |
| `icon_svg` | no | Inline SVG markup displayed as an icon |

### `[i18n]`

| Key | Required | Description |
|-----|----------|-------------|
| `langs` | yes | List of language codes. At least one is required. The first entry is used as the default language. |

### `[highlight]`

| Key | Default | Description |
|-----|---------|-------------|
| `dark_theme` | `base16-ocean.dark` | Theme for dark mode |
| `light_theme` | _(none)_ | Theme for light mode. When set, both dark and light code blocks are emitted and toggled via CSS. |

Available themes: `base16-ocean.dark`, `base16-ocean.light`, `base16-eighties.dark`, `base16-mocha.dark`, `InspiredGitHub`, `Solarized (dark)`, `Solarized (light)`.

---

## Writing Pages

### Frontmatter

Every `.md` file must begin with YAML frontmatter:

```yaml
---
title: "Getting Started"
order: 1
---

Page content goes here...
```

| Field | Required | Description |
|-------|----------|-------------|
| `title` | yes | Page title shown in the heading and browser tab |
| `order` | no | Sort order within the section (default: `0`) |
| `status` | no | Set to `"draft"` to display a DRAFT banner |

### URL Routing

Files are mapped to URLs as follows:

| File | URL |
|------|-----|
| `en/index.md` | `<base_path>/en/` |
| `en/guide/index.md` | `<base_path>/en/guide/` |
| `en/guide/01-intro.md` | `<base_path>/en/guide/01-intro/` |

The root `index.html` is generated automatically and redirects to the default language, respecting the user's `localStorage` language preference.

### Sidebar Navigation

Sidebar navigation is generated automatically:

- Each subdirectory under a language becomes a **section**
- The section's `index.md` title is used as the section heading
- Pages within a section are sorted by `order`, then by filename
- `index.md` at the language root uses `portal.html` (no sidebar)
- All other pages use `page.html` (with sidebar)

---

## Customizing Templates and Assets

When `templates/` or `static/` directories exist in the source, files there override the built-in defaults. Use `docs-gen init` to generate the defaults as a starting point.

Three templates are available:

| Template | Used for |
|----------|----------|
| `base.html` | Shared layout: `<head>`, header, footer, scripts |
| `page.html` | Content pages with sidebar |
| `portal.html` | Homepage (`index.md` at language root), no sidebar |

---

## Template Variables

Templates use [Tera](https://keats.github.io/tera/) syntax. Available variables:

### All templates

| Variable | Type | Description |
|----------|------|-------------|
| `page.title` | string | Page title from frontmatter |
| `page.url` | string | Page URL path |
| `page.status` | string? | `"draft"` or null |
| `content` | string | Rendered HTML (use `{{ content \| safe }}`) |
| `lang` | string | Current language code |
| `site.title` | string | Site title |
| `site.version` | string? | Site version |
| `site.base_url` | string | Full base URL (`hostname` + `base_path`) |
| `site.base_path` | string | URL path prefix |
| `site.langs` | list | All language codes |
| `site.nav` | list | Toolbar button entries |
| `site.nav[].label` | string | Button label |
| `site.nav[].url` | string? | External URL (if set) |
| `site.nav[].path` | string? | Internal section path (if set) |
| `site.nav[].icon_svg` | string? | Inline SVG icon (if set) |

### `page.html` only

| Variable | Type | Description |
|----------|------|-------------|
| `nav` | list | Sidebar sections |
| `nav[].title` | string | Section title |
| `nav[].url` | string | Section index URL |
| `nav[].active` | bool | True if this section contains the current page |
| `nav[].children` | list | Pages within this section |
| `nav[].children[].title` | string | Page title |
| `nav[].children[].url` | string | Page URL |
| `nav[].children[].active` | bool | True if this is the current page |
