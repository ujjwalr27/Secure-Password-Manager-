use anyhow::Result;
use clap::Parser;
use colored::Colorize;

mod encryption;
mod password_gen;
mod credential_manager;
mod ui;
mod utils;

use ui::cli::{handle_command, Command};

/// Secure Password Manager - A Rust-based secure credential storage solution
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match handle_command(cli.command) {
        Ok(_) => {
            println!("{}", "Operation completed successfully".green());
            Ok(())
        },
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            Err(e)
        }
    }
}
