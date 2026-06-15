//! Interactive prompt — displays scan results and collects user decisions.
//!
//! TDD: tests written before production code.

use std::io::{BufRead, Write};

use crate::types::{PackageScan, ScanResult, UserDecision};

/// Returns `true` if any scan has a `Suspicious` or `Error` result.
pub fn has_suspicious(scans: &[PackageScan]) -> bool {
    scans.iter().any(|s| {
        matches!(
            s.result,
            ScanResult::Suspicious { .. } | ScanResult::Error(_)
        )
    })
}

/// Presents findings and collects decisions, reading from an arbitrary `BufRead`
/// source (useful for testing with a `Cursor` or similar).
///
/// Rules:
/// - `Clean` → auto-approve (no prompt)
/// - `Error` → auto-reject (no prompt)
/// - `Suspicious` → display findings, prompt [y/N] (default No)
pub fn present_findings_with_reader<R: BufRead>(
    scans: &[PackageScan],
    reader: &mut R,
) -> Vec<UserDecision> {
    let mut decisions = Vec::with_capacity(scans.len());

    for scan in scans {
        match &scan.result {
            ScanResult::Clean => {
                println!("\x1b[32m✓\x1b[0m {}: clean — auto-approved", scan.name);
                decisions.push(UserDecision::Approve);
            }
            ScanResult::Error(msg) => {
                println!("\x1b[31m✗\x1b[0m {}: error — rejected ({})", scan.name, msg);
                decisions.push(UserDecision::Reject);
            }
            ScanResult::Suspicious { findings } => {
                println!(
                    "\x1b[33m!\x1b[0m {} ({}): suspicious",
                    scan.name, scan.version
                );
                for finding in findings {
                    println!("  - {finding}");
                }
                print!("Approve? [y/N] ");
                std::io::stdout().flush().expect("flush stdout");

                let mut input = String::new();
                reader.read_line(&mut input).expect("read input");
                let approved = input.trim().eq_ignore_ascii_case("y");

                if approved {
                    println!("\x1b[32m✓\x1b[0m {}: approved by user", scan.name);
                    decisions.push(UserDecision::Approve);
                } else {
                    println!("\x1b[31m✗\x1b[0m {}: rejected by user", scan.name);
                    decisions.push(UserDecision::Reject);
                }
            }
        }
    }

    decisions
}

/// Presents findings and collects decisions from the user via stdin.
pub fn present_findings(scans: &[PackageScan]) -> Vec<UserDecision> {
    present_findings_with_reader(scans, &mut std::io::stdin().lock())
}

/// Prints a colored summary of scan results and decisions.
pub fn print_summary(scans: &[PackageScan], decisions: &[UserDecision]) {
    println!();
    println!("═══════════════════════════════════════");
    println!("          Scan Summary");
    println!("═══════════════════════════════════════");

    for (scan, decision) in scans.iter().zip(decisions.iter()) {
        let status = match decision {
            UserDecision::Approve => "\x1b[32mAPPROVE\x1b[0m",
            UserDecision::Reject => "\x1b[31mREJECT\x1b[0m",
        };
        println!("  {status}  {} {}", scan.name, scan.version);
    }

    let approved = decisions
        .iter()
        .filter(|d| **d == UserDecision::Approve)
        .count();
    let rejected = decisions.len() - approved;
    println!("───────────────────────────────────────");
    println!("  \x1b[32m{approved} approved\x1b[0m, \x1b[31m{rejected} rejected\x1b[0m");
    println!("═══════════════════════════════════════");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests  (TDD: written before production code)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ── has_suspicious ───────────────────────────────────────────────────────

    #[test]
    fn test_has_suspicious_all_clean() {
        let scans = vec![
            PackageScan {
                name: "pkg-a".into(),
                base: "pkg-a".into(),
                version: "1.0-1".into(),
                result: ScanResult::Clean,
                decision: None,
            },
            PackageScan {
                name: "pkg-b".into(),
                base: "pkg-b".into(),
                version: "2.0-1".into(),
                result: ScanResult::Clean,
                decision: None,
            },
        ];
        assert!(!has_suspicious(&scans));
    }

    #[test]
    fn test_has_suspicious_with_suspicious() {
        let scans = vec![
            PackageScan {
                name: "pkg-a".into(),
                base: "pkg-a".into(),
                version: "1.0-1".into(),
                result: ScanResult::Clean,
                decision: None,
            },
            PackageScan {
                name: "pkg-b".into(),
                base: "pkg-b".into(),
                version: "2.0-1".into(),
                result: ScanResult::Suspicious {
                    findings: vec!["uses curl | bash".into()],
                },
                decision: None,
            },
        ];
        assert!(has_suspicious(&scans));
    }

    #[test]
    fn test_has_suspicious_with_error() {
        let scans = vec![PackageScan {
            name: "broken".into(),
            base: "broken".into(),
            version: "0.1-1".into(),
            result: ScanResult::Error("network timeout".into()),
            decision: None,
        }];
        assert!(has_suspicious(&scans));
    }

    #[test]
    fn test_has_suspicious_empty() {
        let scans: Vec<PackageScan> = vec![];
        assert!(!has_suspicious(&scans));
    }

    // ── present_findings_with_reader — all clean ─────────────────────────────

    #[test]
    fn test_present_findings_all_clean() {
        let scans = vec![
            PackageScan {
                name: "safe-pkg".into(),
                base: "safe-pkg".into(),
                version: "1.0-1".into(),
                result: ScanResult::Clean,
                decision: None,
            },
            PackageScan {
                name: "also-safe".into(),
                base: "also-safe".into(),
                version: "2.0-1".into(),
                result: ScanResult::Clean,
                decision: None,
            },
        ];
        let mut reader = Cursor::new(Vec::<u8>::new());
        let decisions = present_findings_with_reader(&scans, &mut reader);

        assert_eq!(decisions.len(), 2);
        assert_eq!(decisions[0], UserDecision::Approve);
        assert_eq!(decisions[1], UserDecision::Approve);
    }

    // ── present_findings_with_reader — all error ─────────────────────────────

    #[test]
    fn test_present_findings_all_error() {
        let scans = vec![
            PackageScan {
                name: "broken-a".into(),
                base: "broken-a".into(),
                version: "0.1-1".into(),
                result: ScanResult::Error("parse failure".into()),
                decision: None,
            },
            PackageScan {
                name: "broken-b".into(),
                base: "broken-b".into(),
                version: "0.2-1".into(),
                result: ScanResult::Error("network error".into()),
                decision: None,
            },
        ];
        let mut reader = Cursor::new(Vec::<u8>::new());
        let decisions = present_findings_with_reader(&scans, &mut reader);

        assert_eq!(decisions.len(), 2);
        assert_eq!(decisions[0], UserDecision::Reject);
        assert_eq!(decisions[1], UserDecision::Reject);
    }

    // ── present_findings_with_reader — suspicious approve ────────────────────

    #[test]
    fn test_present_findings_suspicious_approve() {
        let scans = vec![PackageScan {
            name: "shady".into(),
            base: "shady".into(),
            version: "3.0-1".into(),
            result: ScanResult::Suspicious {
                findings: vec!["insecure source".into()],
            },
            decision: None,
        }];
        let mut reader = Cursor::new(b"y\n");
        let decisions = present_findings_with_reader(&scans, &mut reader);

        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0], UserDecision::Approve);
    }

    // ── present_findings_with_reader — suspicious reject (explicit n) ────────

    #[test]
    fn test_present_findings_suspicious_reject_n() {
        let scans = vec![PackageScan {
            name: "shady".into(),
            base: "shady".into(),
            version: "3.0-1".into(),
            result: ScanResult::Suspicious {
                findings: vec!["unknown source".into()],
            },
            decision: None,
        }];
        let mut reader = Cursor::new(b"n\n");
        let decisions = present_findings_with_reader(&scans, &mut reader);

        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0], UserDecision::Reject);
    }

    // ── present_findings_with_reader — suspicious default reject ─────────────

    #[test]
    fn test_present_findings_suspicious_default_reject() {
        let scans = vec![PackageScan {
            name: "shady".into(),
            base: "shady".into(),
            version: "3.0-1".into(),
            result: ScanResult::Suspicious {
                findings: vec!["precompiled binary".into()],
            },
            decision: None,
        }];
        let mut reader = Cursor::new(b"\n"); // empty input → default No
        let decisions = present_findings_with_reader(&scans, &mut reader);

        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0], UserDecision::Reject);
    }

    // ── present_findings_with_reader — mixed ────────────────────────────────

    #[test]
    fn test_present_findings_mixed() {
        let scans = vec![
            PackageScan {
                name: "clean-pkg".into(),
                base: "clean-pkg".into(),
                version: "1.0-1".into(),
                result: ScanResult::Clean,
                decision: None,
            },
            PackageScan {
                name: "shady-pkg".into(),
                base: "shady-pkg".into(),
                version: "2.0-1".into(),
                result: ScanResult::Suspicious {
                    findings: vec!["eval in PKGBUILD".into()],
                },
                decision: None,
            },
            PackageScan {
                name: "broken-pkg".into(),
                base: "broken-pkg".into(),
                version: "0.1-1".into(),
                result: ScanResult::Error("timeout".into()),
                decision: None,
            },
        ];
        let mut reader = Cursor::new(b"y\n"); // approve the suspicious one
        let decisions = present_findings_with_reader(&scans, &mut reader);

        assert_eq!(decisions.len(), 3);
        assert_eq!(decisions[0], UserDecision::Approve); // clean → auto-approve
        assert_eq!(decisions[1], UserDecision::Approve); // suspicious → user said y
        assert_eq!(decisions[2], UserDecision::Reject); // error → auto-reject
    }

    // ── print_summary ────────────────────────────────────────────────────────

    /// Verify that `print_summary` produces output without panicking.
    ///
    /// We cannot easily capture `print!`/`println!` output in tests without
    /// refactoring the function to accept a `Write` sink, so we verify the
    /// function runs without panicking and the preconditions hold.
    #[test]
    fn test_print_summary() {
        let scans = vec![
            PackageScan {
                name: "good-pkg".into(),
                base: "good-pkg".into(),
                version: "1.0-1".into(),
                result: ScanResult::Clean,
                decision: Some(UserDecision::Approve),
            },
            PackageScan {
                name: "bad-pkg".into(),
                base: "bad-pkg".into(),
                version: "2.0-1".into(),
                result: ScanResult::Suspicious {
                    findings: vec!["malicious".into()],
                },
                decision: Some(UserDecision::Reject),
            },
        ];
        let decisions = vec![UserDecision::Approve, UserDecision::Reject];

        // Must not panic
        print_summary(&scans, &decisions);

        // Preconditions hold
        assert_eq!(scans.len(), 2);
        assert_eq!(decisions.len(), 2);
    }
}
