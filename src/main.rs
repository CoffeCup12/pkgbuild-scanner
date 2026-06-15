pub mod aur;
pub mod cache;
pub mod config;
pub mod exec;
pub mod extract;
pub mod interactive;
pub mod ollama;
pub mod prompt;
pub mod routes;
pub mod scanner;
pub mod version;

mod types;

use clap::Parser;
use std::process::ExitCode;

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

// ─── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let args = &cli.args;

    if args.is_empty() {
        // No arguments — print usage hint and exit cleanly.
        println!("pkgbuild-scanner — scan PKGBUILDs for security issues before installing");
        println!();
        println!("Usage: yay [options] [package...]");
        println!("For help on yay itself, run: yay --help");
        return ExitCode::SUCCESS;
    }

    use crate::routes::{route, Command};
    use crate::types::UserDecision;

    match route(&cli.args) {
        Command::Install(packages) => {
            // ── Install mode ──────────────────────────────────────────────────
            // 1.  Load configuration and create the scanner pipeline.
            let config = crate::config::load_or_default();
            let scanner = crate::scanner::Scanner::new(&config);

            // 2.  Scan each AUR package (names already extracted by route()).
            let package_names: Vec<&str> = packages.iter().map(|s| s.as_str()).collect();

            match scanner.scan_packages_batch(&package_names).await {
                Ok(mut results) => {
                    let decisions = crate::interactive::present_findings(&results);
                    crate::interactive::print_summary(&results, &decisions);

                    // Apply decisions back to scans
                    for (scan, decision) in results.iter_mut().zip(decisions.iter()) {
                        scan.decision = Some(decision.clone());
                    }

                    // Filter approved packages
                    let approved: Vec<String> = results
                        .iter()
                        .filter(|s| s.decision == Some(UserDecision::Approve))
                        .map(|s| s.name.clone())
                        .collect();

                    if approved.is_empty() {
                        println!("No packages approved. Nothing to install.");
                        return ExitCode::SUCCESS;
                    }

                    let cmd = exec::build_install_command(&approved, &cli.args);
                    return exec::delegate_to_yay(&cmd);
                }
                Err(e) => {
                    eprintln!("error: scan failed: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        Command::Update => {
            // ── Update mode ────────────────────────────────────────────────────
            // TODO (T14): scan all cached packages for system upgrade.
            // For now, delegate directly to real yay (no package filtering yet).
            return exec::delegate_to_yay(args);
        }
        Command::Passthrough(_passthrough_args) => {
            // ── Passthrough mode ───────────────────────────────────────────────
            // Forward everything verbatim to the real yay.
            return exec::delegate_to_yay(args);
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
