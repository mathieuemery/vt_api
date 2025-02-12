//! VT_API - A Rust program that interacts with the Virus Total API
//!
//! Allows to check url, domains, IPs and files and generates
//! either the full report or a summary.
//!
//! # Usage
//!
//! ```rust
//! // Example showing url scan usage
//! cargo run url https://www.google.com
//! ```
//!
//! ```rust
//! // Example showing ip scan usage
//! cargo run domain 8.8.8.8
//! ```
//!
//! # Features
//!
//! - url: Generates a report for a URL
//! - resolve: Generates a report for either a domain or an IP
//! - file: Generates a report for a file and its behaviour (Allows files bigger than 32 MB)
//!
//! # Configuration
//!
//! Environment variables required:
//! - `VT_API_KEY`: Your virus total API key.
//!
//! # License
//! MIT

use clap::{Parser, Subcommand};

mod resolve;
mod url;

// Manages user cli input
#[derive(Parser)]
#[command(name = "my_tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Url { url: String },
    Domain { domain: String },
    File { path: String },
}

fn main() {
    let cli = Cli::parse();

    // Matches the user input
    let result = match cli.command {
        Commands::Url { url: _ }  => url::request::request(),
        Commands::Domain { domain: _ } => resolve::request::request(),
        Commands::File { path: _ } => /*file::request::request()*/"".to_string(),
    };

    println!("{}", result);
}