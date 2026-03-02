mod builder;
mod config;
mod defaults;
mod markdown;
mod serve;
mod utils;

use anyhow::Result;
use clap::{Parser, Subcommand, CommandFactory};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(version, about = "A simple static site generator")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Source directory containing config.toml (used when no subcommand given)
    #[arg(default_value = ".")]
    src: PathBuf,

    /// Output directory (used when no subcommand given)
    #[arg(long, default_value = "docs")]
    out: PathBuf,
}

#[derive(Subcommand)]
enum Command {
    /// Build the documentation site
    Build {
        /// Source directory containing config.toml
        #[arg(default_value = ".")]
        src: PathBuf,

        /// Output directory
        #[arg(long, default_value = "docs")]
        out: PathBuf,
    },
    /// Initialize a new docs project with default scaffold files
    Init {
        /// Target directory to initialize (default: current directory)
        #[arg(default_value = ".")]
        src: PathBuf,
    },
    /// Start a local development server with live-reload
    Serve {
        /// Source directory containing config.toml
        #[arg(default_value = ".")]
        src: PathBuf,

        /// Port number for the HTTP server
        #[arg(long, default_value = "8080")]
        port: u16,

        /// Open browser automatically
        #[arg(long)]
        open: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Build { src, out }) => builder::build(&src, &out),
        Some(Command::Init { src }) => cmd_init(&src),
        Some(Command::Serve { src, port, open }) => serve::serve(&src, port, open),
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}

fn cmd_init(target: &Path) -> Result<()> {
    let mut skipped = 0usize;
    let mut created = 0usize;

    for (rel_path, content) in defaults::init_files() {
        let dest = target.join(rel_path);
        if dest.exists() {
            eprintln!("Skipping (already exists): {}", dest.display());
            skipped += 1;
            continue;
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&dest, content)?;
        println!("Created: {}", dest.display());
        created += 1;
    }

    println!("\nInit complete: {} file(s) created, {} skipped.", created, skipped);
    Ok(())
}

