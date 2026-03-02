// Default embedded theme files. Users can override any of these by placing
// a file with the same name under their <SRC>/templates/ or <SRC>/static/.

pub const TEMPLATE_BASE: &str = include_str!("../defaults/templates/base.html");
pub const TEMPLATE_PAGE: &str = include_str!("../defaults/templates/page.html");
pub const TEMPLATE_PORTAL: &str = include_str!("../defaults/templates/portal.html");

pub const STATIC_CSS_MAIN: &str = include_str!("../defaults/static/css/main.css");
pub const STATIC_JS_MAIN: &str = include_str!("../defaults/static/js/main.js");

// Init command templates
pub const INIT_CONFIG_TOML: &str = include_str!("../defaults/config.toml");
pub const INIT_PAGE_EN_INDEX: &str = include_str!("../defaults/pages/en/index.md");
pub const INIT_PAGE_JA_INDEX: &str = include_str!("../defaults/pages/ja/index.md");

/// Returns all default templates as (name, source) pairs for Tera registration.
pub fn default_templates() -> Vec<(&'static str, &'static str)> {
    vec![
        ("base.html", TEMPLATE_BASE),
        ("page.html", TEMPLATE_PAGE),
        ("portal.html", TEMPLATE_PORTAL),
    ]
}

/// Returns all default static files as (relative_path, content) pairs.
pub fn default_static_files() -> Vec<(&'static str, &'static str)> {
    vec![
        ("css/main.css", STATIC_CSS_MAIN),
        ("js/main.js", STATIC_JS_MAIN),
    ]
}

/// Returns all init scaffold files as (relative_path, content) pairs.
pub fn init_files() -> Vec<(&'static str, &'static str)> {
    vec![
        ("config.toml", INIT_CONFIG_TOML),
        ("templates/base.html", TEMPLATE_BASE),
        ("templates/page.html", TEMPLATE_PAGE),
        ("templates/portal.html", TEMPLATE_PORTAL),
        ("static/css/main.css", STATIC_CSS_MAIN),
        ("static/js/main.js", STATIC_JS_MAIN),
        ("pages/en/index.md", INIT_PAGE_EN_INDEX),
        ("pages/ja/index.md", INIT_PAGE_JA_INDEX),
    ]
}
