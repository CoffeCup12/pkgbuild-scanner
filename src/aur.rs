//! AUR RPC client — queries the AUR info API and downloads/extracts PKGBUILDs.
//!
//! Uses `reqwest` for HTTP, `flate2` + `tar` for tarball extraction,
//! and `tempfile` for auto-cleaned temporary directories.

use crate::cache::FileCache;
use crate::types::{AurPackage, AurRpcResponse};
use flate2::read::GzDecoder;
use std::collections::{HashMap, HashSet};
use tar::Archive;

// ─── AurClient ────────────────────────────────────────────────────────────────

/// HTTP client for the Arch User Repository (AUR) RPC and snapshot APIs.
pub struct AurClient {
    client: reqwest::Client,
    base_url: String,
}

impl AurClient {
    /// Create a new client pointed at the official AUR.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: "https://aur.archlinux.org".to_string(),
        }
    }

    /// Create a client with a pre-built `reqwest::Client` and custom base URL.
    ///
    /// Used in tests to point at a wiremock server.
    pub fn with_client(client: reqwest::Client, base_url: String) -> Self {
        Self { client, base_url }
    }

    /// Query package info from the AUR RPC v5 `/info` endpoint.
    ///
    /// Builds a URL like `https://aur.archlinux.org/rpc/v5/info?arg[]=pkg1&arg[]=pkg2`
    /// and deserialises the JSON response into a `Vec<AurPackage>`.
    pub async fn query_packages(&self, names: &[&str]) -> Result<Vec<AurPackage>, String> {
        let query_string = names
            .iter()
            .map(|n| format!("arg[]={}", n))
            .collect::<Vec<_>>()
            .join("&");
        let url = format!("{}/rpc/v5/info?{}", self.base_url, query_string);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("Failed to query AUR RPC: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("AUR RPC returned HTTP {}", resp.status()));
        }

        let body = resp
            .text()
            .await
            .map_err(|e| format!("Failed to read AUR RPC response: {}", e))?;

        let rpc_response: AurRpcResponse = serde_json::from_str(&body)
            .map_err(|e| format!("Failed to parse AUR RPC response: {}", e))?;

        Ok(rpc_response.results)
    }

    /// Download a tarball from `https://aur.archlinux.org{url_path}`,
    /// extract it into a temp directory, find the `PKGBUILD` file (case-sensitive),
    /// read its contents as UTF-8, and return the string.
    ///
    /// The temp directory is automatically cleaned up when it goes out of scope.
    pub async fn download_and_extract_pkgbuild(&self, url_path: &str) -> Result<String, String> {
        let url = format!("{}{}", self.base_url, url_path);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("Failed to download tarball: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Tarball download returned HTTP {}", resp.status()));
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| format!("Failed to read tarball response: {}", e))?;

        let gz_decoder = GzDecoder::new(&body[..]);
        let mut archive = Archive::new(gz_decoder);

        let tmp_dir =
            tempfile::tempdir().map_err(|e| format!("Failed to create temp dir: {}", e))?;

        archive
            .unpack(tmp_dir.path())
            .map_err(|e| format!("Failed to extract tarball: {}", e))?;

        let pkgbuild_path = find_pkgbuild(tmp_dir.path())
            .ok_or_else(|| "No PKGBUILD found in extracted tarball".to_string())?;

        let content = std::fs::read_to_string(&pkgbuild_path)
            .map_err(|e| format!("Failed to read PKGBUILD: {}", e))?;

        // tmp_dir is dropped here — temp files are cleaned up automatically
        Ok(content)
    }

    /// Query package info and (optionally) download PKGBUILDs for the given
    /// package names.
    ///
    /// For each unique `PackageBase` the cache is checked first. If a
    /// cache entry exists with a matching version the download is skipped
    /// and `None` is returned as the PKGBUILD text. On a cache miss the
    /// tarball is downloaded and extracted as before, returning `Some(text)`.
    ///
    /// Deduplicates by `PackageBase`: if two packages share the same base,
    /// the tarball is downloaded only once.
    pub async fn fetch_pkgbuilds(
        &self,
        cache: &FileCache,
        names: &[&str],
    ) -> Result<Vec<(AurPackage, Option<String>)>, String> {
        let packages = self.query_packages(names).await?;

        let mut results: Vec<(AurPackage, Option<String>)> = Vec::with_capacity(packages.len());
        let mut downloaded: HashSet<String> = HashSet::new();
        let mut base_to_pkgbuild: HashMap<String, String> = HashMap::new();

        for pkg in packages {
            let base = pkg.package_base.clone();
            if !downloaded.contains(&base) {
                // Check cache first — skip download on a hit.
                if let Some(_result) = cache.check_cache(&base, &pkg.version) {
                    downloaded.insert(base);
                } else {
                    let content = self.download_and_extract_pkgbuild(&pkg.url_path).await?;
                    base_to_pkgbuild.insert(base.clone(), content);
                    downloaded.insert(base);
                }
            }
            let content = base_to_pkgbuild.get(&pkg.package_base).cloned();
            results.push((pkg, content));
        }

        Ok(results)
    }
}

impl Default for AurClient {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helper ───────────────────────────────────────────────────────────────────

/// Recursively search a directory tree for a file named `PKGBUILD` (case-sensitive).
fn find_pkgbuild(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_pkgbuild(&path) {
                return Some(found);
            }
        } else if path.file_name() == Some(std::ffi::OsStr::new("PKGBUILD")) {
            return Some(path);
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════════════
// Unit tests  (TDD: wiremock-based HTTP mocking)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Build an `AurClient` whose `base_url` points at a wiremock server.
    fn test_client(server: &MockServer) -> AurClient {
        AurClient {
            client: reqwest::Client::new(),
            base_url: server.uri(),
        }
    }

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
            use flate2::Compression;
            use flate2::write::GzEncoder;
            let mut encoder = GzEncoder::new(&mut gz_vec, Compression::default());
            encoder.write_all(&tar_data).unwrap();
            encoder.finish().unwrap();
        }
        gz_vec
    }

    // ── query_packages ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_query_packages_success() {
        let server = MockServer::start().await;

        let body = serde_json::json!({
            "results": [
                {
                    "Name": "cower",
                    "PackageBase": "cower",
                    "Version": "18-1",
                    "URLPath": "/cgit/aur.git/snapshot/cower.tar.gz",
                    "Description": "A simple AUR helper"
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path("/rpc/v5/info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let client = test_client(&server);
        let packages = client.query_packages(&["cower"]).await.unwrap();

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "cower");
        assert_eq!(packages[0].package_base, "cower");
        assert_eq!(packages[0].version, "18-1");
        assert_eq!(packages[0].url_path, "/cgit/aur.git/snapshot/cower.tar.gz");
        assert_eq!(
            packages[0].description.as_deref(),
            Some("A simple AUR helper")
        );
    }

    #[tokio::test]
    async fn test_query_packages_empty() {
        let server = MockServer::start().await;

        let body = serde_json::json!({ "results": [] });

        Mock::given(method("GET"))
            .and(path("/rpc/v5/info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let client = test_client(&server);
        let packages = client.query_packages(&["nonexistent"]).await.unwrap();

        assert!(packages.is_empty());
    }

    #[tokio::test]
    async fn test_query_packages_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/rpc/v5/info"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = test_client(&server);
        let result = client.query_packages(&["anything"]).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTP 500"));
    }

    // ── download_and_extract_pkgbuild ─────────────────────────────────────────

    #[tokio::test]
    async fn test_download_and_extract_pkgbuild_success() {
        let server = MockServer::start().await;

        let tarball = create_test_tarball(
            "cower",
            "# Maintainer: Test User\npkgname=cower\npkgver=18\npkgrel=1\n",
        );

        Mock::given(method("GET"))
            .and(path("/cgit/aur.git/snapshot/cower.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball))
            .mount(&server)
            .await;

        let client = test_client(&server);
        let pkgbuild = client
            .download_and_extract_pkgbuild("/cgit/aur.git/snapshot/cower.tar.gz")
            .await
            .unwrap();

        assert!(pkgbuild.starts_with("# Maintainer:"));
        assert!(pkgbuild.contains("pkgname=cower"));
    }

    #[tokio::test]
    async fn test_download_and_extract_pkgbuild_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/cgit/aur.git/snapshot/broken.tar.gz"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = test_client(&server);
        let result = client
            .download_and_extract_pkgbuild("/cgit/aur.git/snapshot/broken.tar.gz")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTP 500"));
    }

    #[tokio::test]
    async fn test_download_and_extract_no_pkgbuild() {
        let server = MockServer::start().await;

        // Create a tarball that does NOT contain a PKGBUILD file.
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let mut tar_buffer = Vec::new();
        let mut tar_builder = tar::Builder::new(&mut tar_buffer);

        // Only a .SRCINFO file, no PKGBUILD
        let content = b"pkgbase = empty-pkg\n";
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, "empty-pkg/.SRCINFO", &content[..])
            .unwrap();
        drop(tar_builder);

        let tar_data = std::mem::take(&mut tar_buffer);

        let mut gz_buffer = Vec::new();
        let mut encoder = GzEncoder::new(&mut gz_buffer, Compression::default());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap();

        Mock::given(method("GET"))
            .and(path("/cgit/aur.git/snapshot/empty-pkg.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(gz_buffer))
            .mount(&server)
            .await;

        let client = test_client(&server);
        let result = client
            .download_and_extract_pkgbuild("/cgit/aur.git/snapshot/empty-pkg.tar.gz")
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No PKGBUILD found"));
    }

    // ── fetch_pkgbuilds dedup ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_fetch_pkgbuilds_dedup() {
        let server = MockServer::start().await;

        // Two packages sharing the same PackageBase
        let info_body = serde_json::json!({
            "results": [
                {
                    "Name": "libfoo",
                    "PackageBase": "shared-lib",
                    "Version": "2.0-1",
                    "URLPath": "/cgit/aur.git/snapshot/shared-lib.tar.gz",
                    "Description": "Library package A"
                },
                {
                    "Name": "libfoo-dev",
                    "PackageBase": "shared-lib",
                    "Version": "2.0-1",
                    "URLPath": "/cgit/aur.git/snapshot/shared-lib.tar.gz",
                    "Description": "Library package B (dev headers)"
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path("/rpc/v5/info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(info_body))
            .mount(&server)
            .await;

        let tarball = create_test_tarball(
            "shared-lib",
            "# Maintainer: Shared Dev\npkgbase=shared-lib\n",
        );

        // .expect(1) ensures the download mock is hit exactly once
        Mock::given(method("GET"))
            .and(path("/cgit/aur.git/snapshot/shared-lib.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball))
            .expect(1)
            .mount(&server)
            .await;

        // Use an empty cache — all packages will be cache-miss → download
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = FileCache::with_dir(cache_dir.path().to_path_buf());

        let client = test_client(&server);
        let results = client
            .fetch_pkgbuilds(&cache, &["libfoo", "libfoo-dev"])
            .await
            .unwrap();

        assert_eq!(
            results.len(),
            2,
            "should return one entry per input package"
        );
        assert_eq!(results[0].0.name, "libfoo");
        assert_eq!(results[1].0.name, "libfoo-dev");
        // Cache miss → PKGBUILD text is Some(...)
        assert!(
            results[0]
                .1
                .as_ref()
                .unwrap()
                .contains("pkgbase=shared-lib")
        );
        assert!(
            results[1]
                .1
                .as_ref()
                .unwrap()
                .contains("pkgbase=shared-lib")
        );
    }

    // ── fetch_pkgbuilds cache hit ─────────────────────────────────────────────

    /// Pre-populate the cache, then call fetch_pkgbuilds — the download
    /// endpoint must NOT be hit and PKGBUILD text must be None.
    #[tokio::test]
    async fn test_fetch_pkgbuilds_cache_hit() {
        let server = MockServer::start().await;

        // Single package returned by RPC
        let info_body = serde_json::json!({
            "results": [
                {
                    "Name": "cached-pkg",
                    "PackageBase": "cached-base",
                    "Version": "1.0-1",
                    "URLPath": "/cgit/aur.git/snapshot/cached-base.tar.gz",
                    "Description": "Already cached package"
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path("/rpc/v5/info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(info_body))
            .mount(&server)
            .await;

        // Explicitly assert that the tarball endpoint is NEVER called
        // (because the cache should be hit first).
        Mock::given(method("GET"))
            .and(path("/cgit/aur.git/snapshot/cached-base.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![]))
            .expect(0)
            .mount(&server)
            .await;

        // Pre-populate the cache with a matching version
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = FileCache::with_dir(cache_dir.path().to_path_buf());
        cache.put("cached-base", "1.0-1", &crate::types::ScanResult::Clean);

        let client = test_client(&server);
        let results = client
            .fetch_pkgbuilds(&cache, &["cached-pkg"])
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.name, "cached-pkg");
        // Cache hit → PKGBUILD text is None
        assert!(results[0].1.is_none());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Integration tests  (gated behind `--features integration`)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(all(test, feature = "integration"))]
mod integration_tests {
    use super::*;

    /// Query the real AUR for "cower" — verify structural fields are present.
    #[tokio::test]
    async fn test_query_real_aur_cower() {
        let client = AurClient::new();
        let packages = client
            .query_packages(&["cower"])
            .await
            .expect("should query real AUR");

        assert!(!packages.is_empty(), "cower should exist on AUR");
        let pkg = &packages[0];
        assert_eq!(pkg.name, "cower");
        assert_eq!(pkg.package_base, "cower");
        assert!(!pkg.version.is_empty(), "Version must be present");
        assert!(
            pkg.url_path.contains("cower"),
            "URLPath should reference cower"
        );
    }

    /// Download the real cower PKGBUILD and verify its content.
    #[tokio::test]
    async fn test_download_real_cower_pkgbuild() {
        let client = AurClient::new();
        let packages = client
            .query_packages(&["cower"])
            .await
            .expect("should query real AUR");

        let pkg = &packages[0];

        let pkgbuild = client
            .download_and_extract_pkgbuild(&pkg.url_path)
            .await
            .expect("should download real cower tarball");

        assert!(
            pkgbuild.starts_with("# Maintainer:"),
            "PKGBUILD should start with Maintainer comment, got: {}",
            &pkgbuild[..80.min(pkgbuild.len())]
        );
    }
}
