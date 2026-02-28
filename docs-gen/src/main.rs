mod builder;
mod config;
mod markdown;

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about = "A simple static site generator")]
struct Cli {
    /// Source directory containing config.toml
    #[arg(default_value = ".")]
    src: PathBuf,

    /// Output directory
    #[arg(long, default_value = "docs")]
    out: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    builder::build(&cli.src, &cli.out)
}
