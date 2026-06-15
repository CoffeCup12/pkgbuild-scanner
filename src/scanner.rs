//! Scanner orchestrator — ties together AurClient, OllamaClient, FileCache,
//! and extract modules into a unified scanning pipeline.
//!
//! The Scanner handles:
//! 1. Fetching PKGBUILDs from the AUR (with cache-awareness)
//! 2. Validating PKGBUILD content
//! 3. Sending to Ollama for security analysis
//! 4. Caching results
//! 5. Deduplication by PackageBase (shared bases scanned once)

use std::collections::HashMap;

use crate::aur::AurClient;
use crate::cache::FileCache;
use crate::extract;
use crate::ollama::OllamaClient;
use crate::prompt;
use crate::types::{Config, PackageScan, ScanResult};

pub struct Scanner {
    aur: AurClient,
    ollama: OllamaClient,
    cache: FileCache,
    prompt: String,
}

impl Scanner {
    pub fn new(config: &Config) -> Self {
        Self {
            aur: AurClient::new(),
            ollama: OllamaClient::new(
                config.ollama.endpoint.clone(),
                config.ollama.model.clone(),
            ),
            cache: FileCache::new(),
            prompt: prompt::get_prompt(config).to_string(),
        }
    }

    pub async fn scan_packages(
        &self,
        package_names: &[&str],
    ) -> Result<Vec<PackageScan>, String> {
        let results = self
            .aur
            .fetch_pkgbuilds(&self.cache, package_names)
            .await?;

        // Phase 1: Build scan results map, deduplicating by PackageBase
        let mut scan_map: HashMap<String, ScanResult> = HashMap::new();

        for (pkg, pkgbuild_opt) in &results {
            let base = &pkg.package_base;
            if scan_map.contains_key(base) {
                continue;
            }

            let result = match pkgbuild_opt {
                Some(text) => {
                    // Cache miss — validate, scan, store
                    if let Err(e) = extract::validate_pkgbuild(text) {
                        ScanResult::Error(format!("PKGBUILD validation failed: {e}"))
                    } else {
                        match self.ollama.scan(text, &self.prompt).await {
                            Ok(scan_result) => {
                                self.cache.store_result(base, &pkg.version, &scan_result);
                                scan_result
                            }
                            Err(e) => {
                                ScanResult::Error(format!("Ollama scan failed: {e}"))
                            }
                        }
                    }
                }
                None => {
                    // Cache hit — retrieve from cache
                    self.cache
                        .check_cache(base, &pkg.version)
                        .unwrap_or_else(|| {
                            ScanResult::Error("cache inconsistency: cache hit but result missing"
                                .to_string())
                        })
                }
            };

            scan_map.insert(base.clone(), result);
        }

        // Phase 2: Build output Vec, ordered by input
        let packages: Vec<PackageScan> = results
            .iter()
            .map(|(pkg, _)| PackageScan {
                name: pkg.name.clone(),
                base: pkg.package_base.clone(),
                version: pkg.version.clone(),
                result: scan_map
                    .get(&pkg.package_base)
                    .cloned()
                    .unwrap_or_else(|| {
                        ScanResult::Error("internal error: scan result missing".to_string())
                    }),
                decision: None,
            })
            .collect();

        Ok(packages)
    }

    pub async fn scan_packages_batch(
        &self,
        names: &[&str],
    ) -> Result<Vec<PackageScan>, String> {
        self.scan_packages(names).await
    }
}

// ─── Tests (TDD — written before implementation) ───────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Create an in-memory gzipped tarball containing `pkgname/PKGBUILD`.
    fn create_test_tarball(pkg_name: &str, pkgbuild_content: &str) -> Vec<u8> {
        let mut tar_buffer = Vec::new();
        let mut tar_builder = tar::Builder::new(&mut tar_buffer);

        // Directory entry
        {
            let mut dir_header = tar::Header::new_gnu();
            dir_header.set_entry_type(tar::EntryType::Directory);
            dir_header.set_size(0);
            dir_header.set_mode(0o755);
            dir_header.set_cksum();
            tar_builder
                .append_data(&mut dir_header, format!("{pkg_name}/"), &[][..])
                .unwrap();
        }

        // PKGBUILD file entry
        {
            let content = pkgbuild_content.as_bytes();
            let mut file_header = tar::Header::new_gnu();
            file_header.set_entry_type(tar::EntryType::Regular);
            file_header.set_size(content.len() as u64);
            file_header.set_mode(0o644);
            file_header.set_cksum();
            tar_builder
                .append_data(&mut file_header, format!("{pkg_name}/PKGBUILD"), content)
                .unwrap();
        }

        let tar_data = tar_builder.into_inner().unwrap();

        let mut gz_vec = Vec::new();
        {
            use flate2::write::GzEncoder;
            use flate2::Compression;
            let mut encoder = GzEncoder::new(&mut gz_vec, Compression::default());
            encoder.write_all(&tar_data).unwrap();
            encoder.finish().unwrap();
        }
        gz_vec
    }

    /// Build a Scanner whose AUR and Ollama clients point at the same mock server.
    fn test_scanner(server: &MockServer, cache_dir: &std::path::Path) -> Scanner {
        Scanner {
            aur: AurClient::with_client(reqwest::Client::new(), server.uri()),
            ollama: OllamaClient::with_client(
                reqwest::Client::new(),
                server.uri(),
                "test-model".into(),
            ),
            cache: FileCache::with_dir(cache_dir.to_path_buf()),
            prompt: "audit this PKGBUILD".to_string(),
        }
    }

    /// Mount a mock AUR RPC response returning the given packages.
    async fn mount_aur_rpc(server: &MockServer, packages: serde_json::Value) {
        let body = serde_json::json!({ "results": packages });
        Mock::given(method("GET"))
            .and(path("/rpc/v5/info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    /// Mount a mock tarball download returning a PKGBUILD with the given content.
    async fn mount_tarball(
        server: &MockServer,
        url_path: &str,
        pkg_name: &str,
        content: &str,
        expect: u64,
    ) {
        let tarball = create_test_tarball(pkg_name, content);
        Mock::given(method("GET"))
            .and(path(url_path))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball))
            .expect(expect)
            .mount(server)
            .await;
    }

    /// Mount a mock Ollama response returning a CLEAN verdict.
    async fn mount_ollama_clean(server: &MockServer, expect: u64) {
        Mock::given(method("POST"))
            .and(path("/api/generate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"response": "VERDICT: CLEAN\n\nThis appears safe."}),
            ))
            .expect(expect)
            .mount(server)
            .await;
    }

    // ── test_scan_packages_cache_hit ──────────────────────────────────────

    #[tokio::test]
    async fn test_scan_packages_cache_hit() {
        let server = MockServer::start().await;
        let cache_dir = tempfile::tempdir().unwrap();

        // Pre-populate cache with a Clean result for "cached-base" v1.0-1
        let scanner = test_scanner(&server, cache_dir.path());
        scanner
            .cache
            .store_result("cached-base", "1.0-1", &ScanResult::Clean);

        // Mount AUR RPC returning the package
        mount_aur_rpc(
            &server,
            serde_json::json!([{
                "Name": "cached-pkg",
                "PackageBase": "cached-base",
                "Version": "1.0-1",
                "URLPath": "/cgit/aur.git/snapshot/cached-base.tar.gz",
                "Description": "Already cached"
            }]),
        )
        .await;

        // Mount tarball with .expect(0) — must NOT be called since cache hit
        mount_tarball(
            &server,
            "/cgit/aur.git/snapshot/cached-base.tar.gz",
            "cached-base",
            "# Maintainer: Test\npkgname=cached-pkg\npkgver=1.0\n",
            0,
        )
        .await;

        // Mount Ollama with .expect(0) — must NOT be called
        mount_ollama_clean(&server, 0).await;

        let results = scanner.scan_packages(&["cached-pkg"]).await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "cached-pkg");
        assert_eq!(results[0].base, "cached-base");
        assert_eq!(results[0].version, "1.0-1");
        assert!(matches!(results[0].result, ScanResult::Clean));
        assert!(results[0].decision.is_none());
    }

    // ── test_scan_packages_cache_miss ─────────────────────────────────────

    #[tokio::test]
    async fn test_scan_packages_cache_miss() {
        let server = MockServer::start().await;
        let cache_dir = tempfile::tempdir().unwrap();
        let scanner = test_scanner(&server, cache_dir.path());

        // Empty cache — no pre-population

        // Mount AUR RPC
        mount_aur_rpc(
            &server,
            serde_json::json!([{
                "Name": "new-pkg",
                "PackageBase": "new-base",
                "Version": "2.0-1",
                "URLPath": "/cgit/aur.git/snapshot/new-base.tar.gz",
                "Description": "Brand new package"
            }]),
        )
        .await;

        // Mount tarball — should be called exactly once
        mount_tarball(
            &server,
            "/cgit/aur.git/snapshot/new-base.tar.gz",
            "new-base",
            "# Maintainer: Dev\npkgname=new-pkg\npkgver=2.0\n",
            1,
        )
        .await;

        // Mount Ollama — should be called exactly once
        mount_ollama_clean(&server, 1).await;

        let results = scanner.scan_packages(&["new-pkg"]).await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "new-pkg");
        assert!(matches!(results[0].result, ScanResult::Clean));

        // Verify result was stored in cache
        let cached = scanner.cache.check_cache("new-base", "2.0-1");
        assert!(matches!(cached, Some(ScanResult::Clean)));
    }

    // ── test_scan_packages_dedup ──────────────────────────────────────────

    #[tokio::test]
    async fn test_scan_packages_dedup() {
        let server = MockServer::start().await;
        let cache_dir = tempfile::tempdir().unwrap();
        let scanner = test_scanner(&server, cache_dir.path());

        // Two packages sharing the same PackageBase
        mount_aur_rpc(
            &server,
            serde_json::json!([
                {
                    "Name": "libfoo",
                    "PackageBase": "shared-lib",
                    "Version": "3.0-1",
                    "URLPath": "/cgit/aur.git/snapshot/shared-lib.tar.gz",
                    "Description": "Library A"
                },
                {
                    "Name": "libfoo-dev",
                    "PackageBase": "shared-lib",
                    "Version": "3.0-1",
                    "URLPath": "/cgit/aur.git/snapshot/shared-lib.tar.gz",
                    "Description": "Library B (dev)"
                }
            ]),
        )
        .await;

        // Tarball should be downloaded exactly ONCE
        mount_tarball(
            &server,
            "/cgit/aur.git/snapshot/shared-lib.tar.gz",
            "shared-lib",
            "# Maintainer: Shared\npkgname=libfoo\npkgver=3.0\n",
            1,
        )
        .await;

        // Ollama should be called exactly ONCE
        mount_ollama_clean(&server, 1).await;

        let results = scanner
            .scan_packages(&["libfoo", "libfoo-dev"])
            .await
            .unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "libfoo");
        assert_eq!(results[0].base, "shared-lib");
        assert!(matches!(results[0].result, ScanResult::Clean));

        assert_eq!(results[1].name, "libfoo-dev");
        assert_eq!(results[1].base, "shared-lib");
        assert!(matches!(results[1].result, ScanResult::Clean));

        // Both should have same result from the shared scan
        match (&results[0].result, &results[1].result) {
            (ScanResult::Clean, ScanResult::Clean) => {}
            _ => panic!("both results should be Clean from dedup"),
        }
    }

    // ── test_scan_packages_partial_failure ────────────────────────────────

    #[tokio::test]
    async fn test_scan_packages_partial_failure() {
        let server = MockServer::start().await;
        let cache_dir = tempfile::tempdir().unwrap();
        let scanner = test_scanner(&server, cache_dir.path());

        // Two independent packages with different bases
        mount_aur_rpc(
            &server,
            serde_json::json!([
                {
                    "Name": "pkg-ok",
                    "PackageBase": "base-ok",
                    "Version": "1.0-1",
                    "URLPath": "/cgit/aur.git/snapshot/base-ok.tar.gz",
                    "Description": "This one works"
                },
                {
                    "Name": "pkg-fail",
                    "PackageBase": "base-fail",
                    "Version": "1.0-1",
                    "URLPath": "/cgit/aur.git/snapshot/base-fail.tar.gz",
                    "Description": "This one fails at Ollama level"
                }
            ]),
        )
        .await;

        // Tarball for base-ok — works fine
        mount_tarball(
            &server,
            "/cgit/aur.git/snapshot/base-ok.tar.gz",
            "base-ok",
            "pkgname=pkg-ok\npkgver=1.0\n",
            1,
        )
        .await;

        // Tarball for base-fail — downloads fine, scans separately
        mount_tarball(
            &server,
            "/cgit/aur.git/snapshot/base-fail.tar.gz",
            "base-fail",
            "pkgname=pkg-fail\npkgver=1.0\n",
            1,
        )
        .await;

        // Differentiate Ollama calls by request body content.
        // pkg-ok → CLEAN verdict
        Mock::given(method("POST"))
            .and(path("/api/generate"))
            .and(wiremock::matchers::body_string_contains("pkg-ok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"response": "VERDICT: CLEAN\n"}),
            ))
            .expect(1)
            .mount(&server)
            .await;

        // pkg-fail → HTTP 500 (network error)
        Mock::given(method("POST"))
            .and(path("/api/generate"))
            .and(wiremock::matchers::body_string_contains("pkg-fail"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let results = scanner
            .scan_packages(&["pkg-ok", "pkg-fail"])
            .await
            .unwrap();

        assert_eq!(results.len(), 2);

        // First package should have Clean result
        assert_eq!(results[0].name, "pkg-ok");
        assert!(matches!(results[0].result, ScanResult::Clean));

        // Second package should have Error (Ollama HTTP 500)
        assert_eq!(results[1].name, "pkg-fail");
        match &results[1].result {
            ScanResult::Error(_msg) => {} // expected
            other => panic!("expected Error for pkg-fail, got {other:?}"),
        }
    }
}
