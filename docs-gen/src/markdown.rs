use anyhow::{Context, Result};
use pulldown_cmark::{CodeBlockKind, Event, Options, Parser, Tag, TagEnd};
use serde::Deserialize;
use syntect::highlighting::ThemeSet;
use syntect::html::highlighted_html_for_string;
use syntect::parsing::SyntaxSet;

#[derive(Debug, Deserialize)]
pub struct Frontmatter {
    pub title: String,
    #[serde(default)]
    pub order: i32,
    pub status: Option<String>,
}

pub struct MarkdownRenderer {
    syntax_set: SyntaxSet,
    theme_set: ThemeSet,
    theme_name: String,
    theme_light_name: Option<String>,
}

impl MarkdownRenderer {
    pub fn new(theme_name: &str, theme_light_name: Option<&str>) -> Self {
        Self {
            syntax_set: SyntaxSet::load_defaults_newlines(),
            theme_set: ThemeSet::load_defaults(),
            theme_name: theme_name.to_string(),
            theme_light_name: theme_light_name.map(|s| s.to_string()),
        }
    }

    pub fn parse_frontmatter(content: &str) -> Result<(Frontmatter, &str)> {
        let content = content.trim_start();
        if !content.starts_with("---") {
            anyhow::bail!("Missing frontmatter delimiter");
        }
        let after_first = &content[3..];
        let end = after_first
            .find("\n---")
            .context("Missing closing frontmatter delimiter")?;
        let yaml = &after_first[..end];
        let body = &after_first[end + 4..];
        let fm: Frontmatter =
            serde_yml::from_str(yaml).context("Failed to parse frontmatter YAML")?;
        Ok((fm, body))
    }

    pub fn render(&self, markdown: &str) -> String {
        let options = Options::ENABLE_TABLES
            | Options::ENABLE_STRIKETHROUGH
            | Options::ENABLE_TASKLISTS;

        let parser = Parser::new_ext(markdown, options);

        let mut in_code_block = false;
        let mut code_lang = String::new();
        let mut code_buf = String::new();
        let mut events: Vec<Event> = Vec::new();

        for event in parser {
            match event {
                Event::Start(Tag::CodeBlock(kind)) => {
                    in_code_block = true;
                    code_buf.clear();
                    code_lang = match kind {
                        CodeBlockKind::Fenced(lang) => lang.to_string(),
                        CodeBlockKind::Indented => String::new(),
                    };
                }
                Event::End(TagEnd::CodeBlock) => {
                    in_code_block = false;
                    let html = self.highlight_code(&code_buf, &code_lang);
                    events.push(Event::Html(html.into()));
                }
                Event::Text(text) if in_code_block => {
                    code_buf.push_str(&text);
                }
                other => events.push(other),
            }
        }

        let mut html_output = String::new();
        pulldown_cmark::html::push_html(&mut html_output, events.into_iter());
        html_output
    }

    fn highlight_code(&self, code: &str, lang: &str) -> String {
        if lang.is_empty() {
            return format!("<pre><code>{}</code></pre>", escape_html(code));
        }

        let syntax = self
            .syntax_set
            .find_syntax_by_token(lang)
            .unwrap_or_else(|| self.syntax_set.find_syntax_plain_text());

        let dark_html = self.highlight_with_theme(code, syntax, &self.theme_name);

        if let Some(ref light_name) = self.theme_light_name {
            let light_html = self.highlight_with_theme(code, syntax, light_name);
            format!(
                "<div class=\"code-dark\">{}</div><div class=\"code-light\">{}</div>",
                dark_html, light_html
            )
        } else {
            dark_html
        }
    }

    fn highlight_with_theme(
        &self,
        code: &str,
        syntax: &syntect::parsing::SyntaxReference,
        theme_name: &str,
    ) -> String {
        let theme = self
            .theme_set
            .themes
            .get(theme_name)
            .unwrap_or_else(|| {
                self.theme_set
                    .themes
                    .values()
                    .next()
                    .expect("No themes available")
            });

        match highlighted_html_for_string(code, &self.syntax_set, syntax, theme) {
            Ok(html) => html,
            Err(_) => format!("<pre><code>{}</code></pre>", escape_html(code)),
        }
    }
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
