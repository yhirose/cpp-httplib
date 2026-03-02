use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct SiteConfig {
    pub site: Site,
    pub i18n: I18n,
    pub highlight: Option<Highlight>,
    #[serde(default)]
    pub nav: Vec<NavLink>,
}

/// A navigation link entry defined in config.toml under [[nav]].
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NavLink {
    pub label: String,
    /// Absolute or external URL (e.g. GitHub link).
    pub url: Option<String>,
    /// Path relative to /<base_path>/<lang>/ (e.g. "tour/").
    pub path: Option<String>,
    /// Optional inline SVG string to display as an icon.
    pub icon_svg: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Site {
    pub title: String,
    pub version: Option<String>,
    /// Optional hostname (e.g. "https://example.github.io"). Combined with
    /// base_path to form the full base URL.
    pub hostname: Option<String>,
    #[serde(default)]
    pub base_path: String,
}

impl Site {
    /// Returns the full base URL derived from hostname + base_path.
    /// Falls back to base_path alone if hostname is not set.
    pub fn base_url(&self) -> String {
        match &self.hostname {
            Some(h) => format!("{}{}", h.trim_end_matches('/'), self.base_path),
            None => self.base_path.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct I18n {
    pub langs: Vec<String>,
}

impl I18n {
    /// Returns the default language, which is the first entry in langs.
    pub fn default_lang(&self) -> &str {
        self.langs.first().map(|s| s.as_str()).unwrap_or("en")
    }
}

#[derive(Debug, Deserialize)]
pub struct Highlight {
    pub theme: Option<String>,
}

impl SiteConfig {
    pub fn load(src_dir: &Path) -> Result<Self> {
        let path = src_dir.join("config.toml");
        let content =
            std::fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path.display()))?;
        let mut config: SiteConfig =
            toml::from_str(&content).with_context(|| format!("Failed to parse {}", path.display()))?;

        // Validate required fields
        if config.i18n.langs.is_empty() {
            anyhow::bail!("[i18n] langs must not be empty. Please specify at least one language.");
        }

        // Normalize base_path: strip trailing slash (but keep empty for root)
        let bp = config.site.base_path.trim_end_matches('/').to_string();
        config.site.base_path = bp;
        Ok(config)
    }

    pub fn highlight_theme(&self) -> &str {
        self.highlight
            .as_ref()
            .and_then(|h| h.theme.as_deref())
            .unwrap_or("base16-ocean.dark")
    }
}
