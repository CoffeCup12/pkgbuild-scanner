pub mod aur;
pub mod cache;
pub mod config;
pub mod extract;
pub mod interactive;
pub mod ollama;
pub mod prompt;
pub mod routes;
pub mod scanner;
pub mod version;

mod types;

use clap::Parser;
use std::path::PathBuf;

// ─── CLI definition ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "yay",
    trailing_var_arg = true,
    about = "pkgbuild-scanner — scan PKGBUILDs for security issues before installing"
)]
struct Cli {
    /// All positional arguments are captured verbatim so they can be forwarded
    /// to the real `yay` binary.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

// ─── Real-yay discovery ───────────────────────────────────────────────────────

/// Search PATH for a `yay` binary that is not our own executable.
fn find_real_yay() -> Option<PathBuf> {
    let self_path = std::env::current_exe().ok()?;
    let path_var = std::env::var("PATH").ok()?;

    for dir in path_var.split(':') {
        let candidate = PathBuf::from(dir).join("yay");
        // Must exist and be a regular file
        if std::fs::metadata(&candidate)
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            // Exclude our own binary (compare canonical paths)
            if let Ok(canonical) = std::fs::canonicalize(&candidate) {
                if canonical == self_path {
                    continue;
                }
            }
            return Some(candidate);
        }
    }
    None
}

// ─── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let args = &cli.args;

    if args.is_empty() {
        // No arguments — print usage hint and exit cleanly.
        println!("pkgbuild-scanner — scan PKGBUILDs for security issues before installing");
        println!();
        println!("Usage: yay [options] [package...]");
        println!("For help on yay itself, run: yay --help");
        return;
    }

    use crate::routes::{route, Command};

    match route(&cli.args) {
        Command::Install(packages) => {
            // ── Install mode ──────────────────────────────────────────────────
            // 1.  Locate the real yay so we can delegate after scanning.
            let _real_yay = match find_real_yay() {
                Some(path) => path,
                None => {
                    eprintln!("error: yay not found in PATH");
                    std::process::exit(1);
                }
            };

            // 2.  Load configuration and create the scanner pipeline.
            let config = crate::config::load_or_default();
            let scanner = crate::scanner::Scanner::new(&config);

            // 3.  Scan each AUR package (names already extracted by route()).
            let package_names: Vec<&str> = packages.iter().map(|s| s.as_str()).collect();

            match scanner.scan_packages_batch(&package_names).await {
                Ok(mut results) => {
                    let decisions = crate::interactive::present_findings(&results);
                    crate::interactive::print_summary(&results, &decisions);

                    // Apply decisions back to scans
                    for (scan, decision) in results.iter_mut().zip(decisions.iter()) {
                        scan.decision = Some(decision.clone());
                    }

                    // TODO (T15): delegate to real yay
                    println!("would delegate to yay: {args:?}");
                }
                Err(e) => {
                    eprintln!("error: scan failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Command::Update => {
            // ── Update mode ────────────────────────────────────────────────────
            // TODO (T14): scan all cached packages for system upgrade
            println!("would scan all cached packages (update mode)");
            println!("would delegate to yay: {args:?}");
        }
        Command::Passthrough(_passthrough_args) => {
            // ── Passthrough mode ───────────────────────────────────────────────
            // Forward everything verbatim to the real yay.
            // TODO (T15): replace with exec::delegate_to_yay(&args)
            println!("would delegate to yay: {args:?}");
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_install_packages() {
        let cli = Cli::parse_from(&["yay", "-S", "cower"]);
        assert_eq!(
            cli.args,
            vec!["-S".to_string(), "cower".to_string()]
        );
    }

    #[test]
    fn test_parse_syu() {
        let cli = Cli::parse_from(&["yay", "-Syu"]);
        assert_eq!(cli.args, vec!["-Syu".to_string()]);
    }

    #[test]
    fn test_parse_remove() {
        let cli = Cli::parse_from(&["yay", "-R", "cower"]);
        assert_eq!(
            cli.args,
            vec!["-R".to_string(), "cower".to_string()]
        );
    }
}
