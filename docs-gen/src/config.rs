use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct SiteConfig {
    pub site: Site,
    pub i18n: I18n,
    pub highlight: Option<Highlight>,
}

#[derive(Debug, Deserialize)]
pub struct Site {
    pub title: String,
    pub version: Option<String>,
    pub base_url: String,
}

#[derive(Debug, Deserialize)]
pub struct I18n {
    pub default_lang: String,
    pub langs: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Highlight {
    pub theme: Option<String>,
    pub theme_light: Option<String>,
}

impl SiteConfig {
    pub fn load(src_dir: &Path) -> Result<Self> {
        let path = src_dir.join("config.toml");
        let content =
            std::fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path.display()))?;
        let config: SiteConfig =
            toml::from_str(&content).with_context(|| format!("Failed to parse {}", path.display()))?;
        Ok(config)
    }

    pub fn highlight_theme(&self) -> &str {
        self.highlight
            .as_ref()
            .and_then(|h| h.theme.as_deref())
            .unwrap_or("base16-ocean.dark")
    }

    pub fn highlight_theme_light(&self) -> Option<&str> {
        self.highlight
            .as_ref()
            .and_then(|h| h.theme_light.as_deref())
    }
}
