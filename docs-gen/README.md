# docs-gen

A simple static site generator written in Rust. Designed for multi-language documentation sites with Markdown content, Tera templates, and syntax highlighting.

## Build

```
cargo build --release --manifest-path docs-gen/Cargo.toml
```

## Usage

```
docs-gen [SRC] [--out OUT]
```

- `SRC` — Source directory containing `config.toml` (default: `.`)
- `--out OUT` — Output directory (default: `docs`)

Example:

```
./docs-gen/target/release/docs-gen docs-src --out docs
```

## Source Directory Structure

```
docs-src/
├── config.toml          # Site configuration
├── pages/               # Markdown content (one subdirectory per language)
│   ├── en/
│   │   ├── index.md     # Portal page (no sidebar)
│   │   ├── tour/
│   │   │   ├── index.md # Section index
│   │   │   ├── 01-getting-started.md
│   │   │   └── ...
│   │   └── cookbook/
│   │       └── index.md
│   └── ja/
│       └── ...          # Same structure as en/
├── templates/           # Tera HTML templates
│   ├── base.html        # Base layout (header, scripts)
│   ├── page.html        # Content page with sidebar navigation
│   └── portal.html      # Portal page without sidebar
└── static/              # Static assets (copied as-is to output root)
    ├── css/
    └── js/
```

## config.toml

```toml
[site]
title = "My Project"
base_url = "https://example.github.io/my-project"
base_path = "/my-project"

[i18n]
default_lang = "en"
langs = ["en", "ja"]

[highlight]
theme = "base16-eighties.dark"        # Dark mode syntax theme (syntect built-in)
theme_light = "base16-ocean.light"    # Light mode syntax theme (optional)
```

### `base_path`

`base_path` controls the URL prefix prepended to all generated links, CSS/JS paths, and redirects.

| Value | Use case |
|---|---|
| `"/my-project"` | GitHub Pages (`https://user.github.io/my-project/`) |
| `""` | Local development at `http://localhost:8000/` |

Leave empty for local-only use; set to `"/<repo-name>"` before deploying to GitHub Pages.

### `highlight`

When `theme_light` is set, code blocks are rendered twice (dark and light) and toggled via CSS classes `.code-dark` / `.code-light`.

Available themes: `base16-ocean.dark`, `base16-ocean.light`, `base16-eighties.dark`, `base16-mocha.dark`, `InspiredGitHub`, `Solarized (dark)`, `Solarized (light)`.

## Markdown Frontmatter

Every `.md` file requires YAML frontmatter:

```yaml
---
title: "Page Title"
order: 1
---
```

| Field    | Required | Description |
|----------|----------|-------------|
| `title`  | yes      | Page title shown in heading and browser tab |
| `order`  | no       | Sort order within the section (default: `0`) |
| `status` | no       | Set to `"draft"` to show a DRAFT banner |

## URL Routing

Markdown files are mapped to URLs as follows:

| File path             | URL                         | Output file                         |
|-----------------------|-----------------------------|-------------------------------------|
| `en/index.md`         | `<base_path>/en/`           | `en/index.html`                     |
| `en/tour/index.md`    | `<base_path>/en/tour/`      | `en/tour/index.html`                |
| `en/tour/01-foo.md`   | `<base_path>/en/tour/01-foo/` | `en/tour/01-foo/index.html`       |

A root `index.html` is generated automatically, redirecting `<base_path>/` to `<base_path>/<default_lang>/` (respecting `localStorage` preference).

## Local Debugging vs GitHub Pages

To preview locally with the same URL structure as GitHub Pages, set `base_path = "/cpp-httplib"` in `config.toml`, then:

```bash
./docs-gen/target/release/docs-gen docs-src --out /tmp/test/cpp-httplib
cd /tmp/test && python3 -m http.server
# Open http://localhost:8000/cpp-httplib/
```

For a plain local preview (no prefix), set `base_path = ""` and open `http://localhost:8000/`.

## Navigation

Navigation is generated automatically from the directory structure:

- Each subdirectory under a language becomes a **section**
- The section's `index.md` title is used as the section heading
- Pages within a section are sorted by `order`, then by filename
- `portal.html` template is used for root `index.md` (no sidebar)
- `page.html` template is used for all other pages (with sidebar)

## Template Variables

Templates use [Tera](https://keats.github.io/tera/) syntax. Available variables:

### All templates

| Variable      | Type   | Description |
|---------------|--------|-------------|
| `page.title`  | string | Page title from frontmatter |
| `page.url`    | string | Page URL path |
| `page.status` | string? | `"draft"` or null |
| `content`     | string | Rendered HTML content (use `{{ content \| safe }}`) |
| `lang`        | string | Current language code |
| `site.title`  | string | Site title from config |
| `site.base_url` | string | Base URL from config |
| `site.base_path` | string | Base path prefix (e.g. `"/cpp-httplib"` or `""`) |
| `site.langs`  | list   | Available language codes |

### page.html only

| Variable           | Type   | Description |
|--------------------|--------|-------------|
| `nav`              | list   | Navigation sections |
| `nav[].title`      | string | Section title |
| `nav[].url`        | string | Section URL |
| `nav[].active`     | bool   | Whether this section contains the current page |
| `nav[].children`   | list   | Child pages |
| `nav[].children[].title` | string | Page title |
| `nav[].children[].url`   | string | Page URL |
| `nav[].children[].active` | bool  | Whether this is the current page |

## Dependencies

- [pulldown-cmark](https://crates.io/crates/pulldown-cmark) — Markdown parsing
- [tera](https://crates.io/crates/tera) — Template engine
- [syntect](https://crates.io/crates/syntect) — Syntax highlighting
- [walkdir](https://crates.io/crates/walkdir) — Directory traversal
- [serde](https://crates.io/crates/serde) / [serde_yml](https://crates.io/crates/serde_yml) / [toml](https://crates.io/crates/toml) — Serialization
- [clap](https://crates.io/crates/clap) — CLI argument parsing
- [anyhow](https://crates.io/crates/anyhow) — Error handling
