use crate::config::SiteConfig;
use crate::markdown::{Frontmatter, MarkdownRenderer};
use anyhow::{Context, Result};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use tera::Tera;
use walkdir::WalkDir;

#[derive(Debug, Serialize)]
struct PageContext {
    title: String,
    url: String,
    status: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct NavItem {
    title: String,
    url: String,
    children: Vec<NavItem>,
    active: bool,
}

#[derive(Debug, Serialize)]
struct SiteContext {
    title: String,
    base_url: String,
    langs: Vec<String>,
}

struct Page {
    frontmatter: Frontmatter,
    html_content: String,
    url: String,
    out_path: PathBuf,
    rel_path: String,
    section: String,
}

pub fn build(src: &Path, out: &Path) -> Result<()> {
    let config = SiteConfig::load(src)?;
    let renderer = MarkdownRenderer::new(config.highlight_theme(), config.highlight_theme_light());

    let templates_dir = src.join("templates");
    let template_glob = format!("{}/**/*.html", templates_dir.display());
    let tera = Tera::new(&template_glob).context("Failed to load templates")?;

    // Clean output directory
    if out.exists() {
        fs::remove_dir_all(out).context("Failed to clean output directory")?;
    }
    fs::create_dir_all(out)?;

    // Copy static files
    let static_dir = src.join("static");
    if static_dir.exists() {
        copy_dir_recursive(&static_dir, out)?;
    }

    // Build each language
    for lang in &config.i18n.langs {
        let pages_dir = src.join("pages").join(lang);
        if !pages_dir.exists() {
            eprintln!("Warning: pages directory not found for lang '{}', skipping", lang);
            continue;
        }

        let pages = collect_pages(&pages_dir, lang, out, &renderer)?;
        let nav = build_nav(&pages);

        for page in &pages {
            let template_name = if page.section.is_empty() {
                "portal.html"
            } else {
                "page.html"
            };

            // Filter nav to only the current section
            let section_nav: Vec<&NavItem> = nav
                .iter()
                .filter(|item| {
                    let item_section = extract_section(&item.url);
                    item_section == page.section
                })
                .collect();

            let mut ctx = tera::Context::new();
            ctx.insert("page", &PageContext {
                title: page.frontmatter.title.clone(),
                url: page.url.clone(),
                status: page.frontmatter.status.clone(),
            });
            ctx.insert("content", &page.html_content);
            ctx.insert("lang", lang);
            ctx.insert("site", &SiteContext {
                title: config.site.title.clone(),
                base_url: config.site.base_url.clone(),
                langs: config.i18n.langs.clone(),
            });

            // Set active state and pass nav
            let mut nav_with_active: Vec<NavItem> = section_nav
                .into_iter()
                .cloned()
                .map(|mut item| {
                    set_active(&mut item, &page.url);
                    item
                })
                .collect();

            // If we're on a section index page, expand its children
            if let Some(item) = nav_with_active.first_mut() {
                if item.url == page.url {
                    item.active = true;
                }
            }

            ctx.insert("nav", &nav_with_active);

            let html = tera
                .render(template_name, &ctx)
                .with_context(|| format!("Failed to render template for {}", page.url))?;

            if let Some(parent) = page.out_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&page.out_path, html)?;
        }
    }

    // Generate root redirect
    generate_root_redirect(out, &config)?;

    println!(
        "Site generated: {} languages, output at {}",
        config.i18n.langs.len(),
        out.display()
    );

    Ok(())
}

fn collect_pages(
    pages_dir: &Path,
    lang: &str,
    out: &Path,
    renderer: &MarkdownRenderer,
) -> Result<Vec<Page>> {
    let mut pages = Vec::new();

    for entry in WalkDir::new(pages_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension().map_or(false, |ext| ext == "md")
        })
    {
        let path = entry.path();
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;

        let (frontmatter, body) = MarkdownRenderer::parse_frontmatter(&content)
            .with_context(|| format!("Failed to parse frontmatter in {}", path.display()))?;

        let html_content = renderer.render(body);

        let rel = path.strip_prefix(pages_dir)?;
        let rel_str = rel.to_string_lossy().to_string();

        // Compute URL and output path
        let (url, out_path) = if rel.file_name().map_or(false, |f| f == "index.md") {
            // index.md -> /<lang>/dir/
            let parent = rel.parent().unwrap_or(Path::new(""));
            if parent.as_os_str().is_empty() {
                // Root index.md
                (
                    format!("/{}/", lang),
                    out.join(lang).join("index.html"),
                )
            } else {
                (
                    format!("/{}/{}/", lang, parent.display()),
                    out.join(lang).join(parent).join("index.html"),
                )
            }
        } else {
            // foo.md -> /<lang>/foo/
            let stem = rel.with_extension("");
            (
                format!("/{}/{}/", lang, stem.display()),
                out.join(lang).join(&stem).join("index.html"),
            )
        };

        let section = extract_section(&url);

        pages.push(Page {
            frontmatter,
            html_content,
            url,
            out_path,
            rel_path: rel_str,
            section,
        });
    }

    Ok(pages)
}

fn extract_section(url: &str) -> String {
    // URL format: /<lang>/ or /<lang>/section/...
    let parts: Vec<&str> = url.trim_matches('/').split('/').collect();
    if parts.len() >= 2 {
        parts[1].to_string()
    } else {
        String::new()
    }
}

fn build_nav(pages: &[Page]) -> Vec<NavItem> {
    // Group pages by section (top-level directory)
    let mut sections: std::collections::BTreeMap<String, Vec<&Page>> =
        std::collections::BTreeMap::new();

    for page in pages {
        if page.section.is_empty() {
            continue; // Skip root index (portal)
        }
        sections
            .entry(page.section.clone())
            .or_default()
            .push(page);
    }

    let mut nav = Vec::new();

    for (section, mut section_pages) in sections {
        // Sort by order, then by filename
        section_pages.sort_by(|a, b| {
            a.frontmatter
                .order
                .cmp(&b.frontmatter.order)
                .then_with(|| a.rel_path.cmp(&b.rel_path))
        });

        // Find the section index page
        let index_page = section_pages
            .iter()
            .find(|p| p.rel_path.ends_with("index.md") && extract_section(&p.url) == section);

        let section_title = index_page
            .map(|p| p.frontmatter.title.clone())
            .unwrap_or_else(|| section.clone());
        let section_url = index_page
            .map(|p| p.url.clone())
            .unwrap_or_default();

        let children: Vec<NavItem> = section_pages
            .iter()
            .filter(|p| !p.rel_path.ends_with("index.md") || extract_section(&p.url) != section)
            .map(|p| NavItem {
                title: p.frontmatter.title.clone(),
                url: p.url.clone(),
                children: Vec::new(),
                active: false,
            })
            .collect();

        nav.push(NavItem {
            title: section_title,
            url: section_url,
            children,
            active: false,
        });
    }

    // Sort nav sections by order of their index pages
    nav
}

fn set_active(item: &mut NavItem, current_url: &str) {
    if item.url == current_url {
        item.active = true;
    }
    for child in &mut item.children {
        set_active(child, current_url);
        if child.active {
            item.active = true;
        }
    }
}

fn generate_root_redirect(out: &Path, config: &SiteConfig) -> Result<()> {
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<script>
(function() {{
  var lang = localStorage.getItem('preferred-lang') || '{}';
  window.location.replace('/' + lang + '/');
}})();
</script>
<meta http-equiv="refresh" content="0;url=/{default_lang}/">
<title>Redirecting...</title>
</head>
<body>
<p>Redirecting to <a href="/{default_lang}/">/{default_lang}/</a>...</p>
</body>
</html>"#,
        config.i18n.default_lang,
        default_lang = config.i18n.default_lang,
    );

    fs::write(out.join("index.html"), html)?;
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    for entry in WalkDir::new(src).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        let rel = path.strip_prefix(src)?;
        let target = dst.join(rel);

        if path.is_dir() {
            fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(path, &target)?;
        }
    }
    Ok(())
}
