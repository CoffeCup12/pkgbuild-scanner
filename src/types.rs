//! Shared data structures for pkgbuild-scanner.
//!
//! All types in this module are data-only — no business logic.
//! Every struct/enum derives Serialize, Deserialize, Clone, and Debug.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─── AUR RPC types ───────────────────────────────────────────────────────────

/// Response from the AUR RPC API (v5).
///
/// The real AUR returns `results` (camelCase) at the top level, but
/// individual package fields are PascalCase.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AurRpcResponse {
    /// List of packages returned by the query.
    #[serde(rename = "results")]
    pub results: Vec<AurPackage>,
}

/// An AUR package as returned by the RPC `/info` or `/search` endpoints.
///
/// Field names in the JSON are PascalCase (`Name`, `PackageBase`, …).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AurPackage {
    pub name: String,
    pub package_base: String,
    pub version: String,
    /// Note: the JSON key is `URLPath` (not `UrlPath`), hence the explicit rename.
    #[serde(rename = "URLPath")]
    pub url_path: String,
    pub description: Option<String>,
}

// ─── Scan types ──────────────────────────────────────────────────────────────

/// Outcome of a PKGBUILD scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanResult {
    /// No suspicious patterns found.
    Clean,
    /// Suspicious patterns were detected.
    Suspicious {
        /// Human-readable descriptions of each finding.
        findings: Vec<String>,
    },
    /// The scan could not complete (network error, parse failure, …).
    Error(String),
}

/// A cached scan result, keyed by `package_base`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub package_base: String,
    pub version: String,
    pub result: ScanResult,
    pub scanned_at: DateTime<Utc>,
}

// ─── Config types ────────────────────────────────────────────────────────────

/// Settings for the Ollama LLM backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaConfig {
    pub model: String,
    pub endpoint: String,
    pub prompt_override: Option<String>,
}

/// Settings for the result cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub ttl_hours: u32,
}

/// Top-level application configuration, read from a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub ollama: OllamaConfig,
    pub cache: CacheConfig,
}

// ─── Interactive-scan types ──────────────────────────────────────────────────

/// Decision made by the user during an interactive review.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum UserDecision {
    /// User approved the package.
    Approve,
    /// User rejected the package.
    Reject,
}

/// A single package together with its scan result and (optionally) a user
/// decision. Used during interactive scanning to track state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageScan {
    pub name: String,
    pub base: String,
    pub version: String,
    pub result: ScanResult,
    pub decision: Option<UserDecision>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests  (TDD: written before production code)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── AurRpcResponse ──────────────────────────────────────────────────────

    /// Deserialise a realistic AUR RPC response (single result).
    #[test]
    fn test_deserialize_aur_rpc_response() {
        let json = r#"{
            "results": [
                {
                    "Name": "visual-studio-code-bin",
                    "PackageBase": "visual-studio-code-bin",
                    "Version": "1.96.0-1",
                    "URLPath": "/cgit/aur.git/snapshot/visual-studio-code-bin/visual-studio-code-bin.tar.gz",
                    "Description": "Visual Studio Code (binary release)"
                }
            ]
        }"#;

        let response: AurRpcResponse = serde_json::from_str(json)
            .expect("AurRpcResponse should deserialize from valid JSON");

        assert_eq!(response.results.len(), 1);
        let pkg = &response.results[0];
        assert_eq!(pkg.name, "visual-studio-code-bin");
        assert_eq!(pkg.package_base, "visual-studio-code-bin");
        assert_eq!(pkg.version, "1.96.0-1");
        assert_eq!(
            pkg.url_path,
            "/cgit/aur.git/snapshot/visual-studio-code-bin/visual-studio-code-bin.tar.gz"
        );
        assert_eq!(
            pkg.description.as_deref(),
            Some("Visual Studio Code (binary release)")
        );
    }

    /// Deserialise an AurRpcResponse with an empty results array.
    #[test]
    fn test_deserialize_aur_rpc_response_empty() {
        let json = r#"{"results": []}"#;
        let response: AurRpcResponse =
            serde_json::from_str(json).expect("empty result list should work");
        assert!(response.results.is_empty());
    }

    // ── AurPackage ──────────────────────────────────────────────────────────

    /// Description is optional — some AUR packages omit it.
    #[test]
    fn test_deserialize_aur_package_no_description() {
        let json = r#"{
            "Name": "no-desc-pkg",
            "PackageBase": "no-desc-pkg-base",
            "Version": "1.0-1",
            "URLPath": "/cgit/aur.git/snapshot/no-desc-pkg.tar.gz"
        }"#;

        let pkg: AurPackage =
            serde_json::from_str(json).expect("package w/o description should deserialize");
        assert_eq!(pkg.name, "no-desc-pkg");
        assert!(pkg.description.is_none());
    }

    /// Description can be null in JSON too.
    #[test]
    fn test_deserialize_aur_package_null_description() {
        let json = r#"{
            "Name": "null-desc-pkg",
            "PackageBase": "null-desc-pkg",
            "Version": "2.0-1",
            "URLPath": "/cgit/aur.git/snapshot/null-desc-pkg.tar.gz",
            "Description": null
        }"#;

        let pkg: AurPackage =
            serde_json::from_str(json).expect("package w/ null description should deserialize");
        assert!(pkg.description.is_none());
    }

    // ── CacheEntry (critical round-trip) ────────────────────────────────────

    /// Serialise a CacheEntry to JSON and back — all fields must survive,
    /// including the DateTime<Utc> timestamp.
    #[test]
    fn test_cache_entry_roundtrip() {
        let entry = CacheEntry {
            package_base: "test-pkg".into(),
            version: "2.0-1".into(),
            result: ScanResult::Suspicious {
                findings: vec!["uses curl | bash".into(), "hardcoded path /tmp".into()],
            },
            scanned_at: Utc::now(),
        };

        let json = serde_json::to_string(&entry).expect("CacheEntry should serialise");
        let deserialized: CacheEntry =
            serde_json::from_str(&json).expect("CacheEntry should deserialise from its own JSON");

        assert_eq!(deserialized.package_base, "test-pkg");
        assert_eq!(deserialized.version, "2.0-1");

        match &deserialized.result {
            ScanResult::Suspicious { findings } => {
                assert_eq!(findings.len(), 2);
                assert_eq!(findings[0], "uses curl | bash");
                assert_eq!(findings[1], "hardcoded path /tmp");
            }
            other => panic!("expected Suspicious, got {other:?}"),
        }

        // Timestamps should be equal within 1 second (sub-second drift is OK).
        let diff = deserialized.scanned_at - entry.scanned_at;
        assert!(
            diff.num_seconds().abs() <= 1,
            "timestamp drift too large: {diff:?}"
        );
    }

    /// Round-trip with ScanResult::Clean.
    #[test]
    fn test_cache_entry_clean_roundtrip() {
        let entry = CacheEntry {
            package_base: "clean-pkg".into(),
            version: "1.0-1".into(),
            result: ScanResult::Clean,
            scanned_at: Utc::now(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: CacheEntry = serde_json::from_str(&json).unwrap();
        assert!(matches!(deserialized.result, ScanResult::Clean));
    }

    /// Round-trip with ScanResult::Error.
    #[test]
    fn test_cache_entry_error_roundtrip() {
        let entry = CacheEntry {
            package_base: "broken-pkg".into(),
            version: "0.0-1".into(),
            result: ScanResult::Error("network timeout".into()),
            scanned_at: Utc::now(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: CacheEntry = serde_json::from_str(&json).unwrap();
        match &deserialized.result {
            ScanResult::Error(msg) => assert_eq!(msg, "network timeout"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // ── ScanResult ──────────────────────────────────────────────────────────

    #[test]
    fn test_scan_result_clean_serde() {
        let result = ScanResult::Clean;
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ScanResult = serde_json::from_str(&json).unwrap();
        assert!(matches!(deserialized, ScanResult::Clean));
    }

    #[test]
    fn test_scan_result_error_serde() {
        let result = ScanResult::Error("parse failure".into());
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ScanResult = serde_json::from_str(&json).unwrap();
        match deserialized {
            ScanResult::Error(msg) => assert_eq!(msg, "parse failure"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // ── UserDecision ────────────────────────────────────────────────────────

    #[test]
    fn test_user_decision_approve() {
        let d = UserDecision::Approve;
        let json = serde_json::to_string(&d).unwrap();
        let deserialized: UserDecision = serde_json::from_str(&json).unwrap();
        assert!(matches!(deserialized, UserDecision::Approve));
    }

    #[test]
    fn test_user_decision_reject() {
        let d = UserDecision::Reject;
        let json = serde_json::to_string(&d).unwrap();
        let deserialized: UserDecision = serde_json::from_str(&json).unwrap();
        assert!(matches!(deserialized, UserDecision::Reject));
    }

    // ── Config ──────────────────────────────────────────────────────────────

    /// Deserialise a minimal Config from TOML (the format we use on disk).
    #[test]
    fn test_config_deserialize_toml() {
        let toml_str = r#"
[ollama]
model = "llama3"
endpoint = "http://localhost:11434"

[cache]
ttl_hours = 24
"#;
        let config: Config = toml::from_str(toml_str).expect("Config should deserialise from TOML");
        assert_eq!(config.ollama.model, "llama3");
        assert_eq!(config.ollama.endpoint, "http://localhost:11434");
        assert!(config.ollama.prompt_override.is_none());
        assert_eq!(config.cache.ttl_hours, 24);
    }

    /// Deserialise a Config with prompt_override set.
    #[test]
    fn test_config_with_prompt_override() {
        let toml_str = r#"
[ollama]
model = "codellama"
endpoint = "http://localhost:11434"
prompt_override = "Analyse this PKGBUILD for safety issues."

[cache]
ttl_hours = 48
"#;
        let config: Config = toml::from_str(toml_str).expect("Config with prompt_override");
        assert_eq!(
            config.ollama.prompt_override.as_deref(),
            Some("Analyse this PKGBUILD for safety issues.")
        );
        assert_eq!(config.cache.ttl_hours, 48);
    }

    // ── PackageScan ─────────────────────────────────────────────────────────

    #[test]
    fn test_package_scan_default() {
        let scan = PackageScan {
            name: "foo".into(),
            base: "foo".into(),
            version: "1.0-1".into(),
            result: ScanResult::Clean,
            decision: None,
        };
        assert!(scan.decision.is_none());
    }

    #[test]
    fn test_package_scan_with_decision() {
        let scan = PackageScan {
            name: "bar".into(),
            base: "bar".into(),
            version: "2.0-1".into(),
            result: ScanResult::Suspicious {
                findings: vec!["insecure source".into()],
            },
            decision: Some(UserDecision::Reject),
        };
        assert_eq!(scan.decision, Some(UserDecision::Reject));
    }
}
