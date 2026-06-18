//! File-based cache for scan results.
//!
//! Each package base gets its own JSON file named `{sanitized_base}.json`.
//! The file contains a single [`CacheEntry`] with the version and result
//! stored inside. Retrieval checks for an exact version match — no fuzzy or
//! prefix matching.

use std::path::PathBuf;

use crate::types::{CacheEntry, ScanResult};

/// A file-backed key-value store for cached [`ScanResult`]s.
///
/// Thread-safe (no mutable shared state — just a `PathBuf`).
#[derive(Debug, Clone)]
pub struct FileCache {
    dir: PathBuf,
}

impl FileCache {
    /// Create a new `FileCache` rooted at `{dirs::cache_dir()}/pkgbuild-scanner/`.
    ///
    /// Attempts to create the cache directory if it does not exist. Returns the
    /// struct regardless of whether directory creation succeeds — the cache
    /// will simply not persist if the directory cannot be created, but the
    /// application will not crash.
    pub fn new() -> Self {
        let dir = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("pkgbuild-scanner");
        let _ = std::fs::create_dir_all(&dir);
        Self { dir }
    }

    /// Create a `FileCache` rooted at an explicit directory (for testing).
    pub fn with_dir(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Retrieve a cached scan result for the given package base and version.
    ///
    /// Returns `Some(result)` only if a cache file exists AND the stored
    /// version matches the requested version exactly. Returns `None` on any
    /// error (missing file, parse failure, version mismatch).
    pub fn get(&self, package_base: &str, version: &str) -> Option<ScanResult> {
        let path = self
            .dir
            .join(format!("{}.json", Self::sanitize_filename(package_base)));
        let data = std::fs::read_to_string(path).ok()?;
        let entry: CacheEntry = serde_json::from_str(&data).ok()?;
        if entry.version == version {
            Some(entry.result)
        } else {
            None
        }
    }

    /// Store a scan result in the cache.
    ///
    /// Creates or replaces the cache file for this package base. Uses
    /// pretty-printed JSON for human readability during debugging.
    pub fn put(&self, package_base: &str, version: &str, result: &ScanResult) {
        let path = self
            .dir
            .join(format!("{}.json", Self::sanitize_filename(package_base)));
        let entry = CacheEntry {
            package_base: package_base.to_string(),
            version: version.to_string(),
            result: result.clone(),
            scanned_at: chrono::Utc::now(),
            commit_hash: None,
        };
        if let Ok(json) = serde_json::to_string_pretty(&entry) {
            let _ = std::fs::write(&path, json);
        }
    }

    /// Thin public wrapper around [`Self::get`].
    ///
    /// Returns `Some(result)` if a cache entry exists and the version matches.
    /// This is the API that the scanner orchestrator (Task 9) will call.
    pub fn check_cache(&self, package_base: &str, version: &str) -> Option<ScanResult> {
        self.get(package_base, version)
    }

    /// Thin public wrapper around [`Self::put`].
    ///
    /// Stores a scan result in the cache keyed by package base and version.
    /// This is the API that the scanner orchestrator (Task 9) will call.
    pub fn store_result(&self, package_base: &str, version: &str, result: &ScanResult) {
        self.put(package_base, version, result);
    }

    // ── Paru-mode cache methods ─────────────────────────────────────────────

    /// Build a paru-mode cache key filename.
    ///
    /// With a commit hash (≥8 chars): `paru-{base}-{hash8}.json`
    /// Without: `paru-{base}.json`
    pub fn make_paru_cache_key(
        &self,
        package_base: &str,
        _version: &str,
        commit_hash: Option<&str>,
    ) -> String {
        let base = Self::sanitize_filename(package_base);
        match commit_hash {
            Some(hash) if hash.len() >= 8 => {
                format!("paru-{}-{}.json", base, &hash[..8])
            }
            _ => format!("paru-{}.json", base),
        }
    }

    /// Store a scan result in the paru-mode cache.
    ///
    /// Includes the commit hash in the cache entry for validation on retrieval.
    pub fn store_paru_result(
        &self,
        package_base: &str,
        version: &str,
        commit_hash: Option<&str>,
        result: &ScanResult,
    ) {
        let filename = self.make_paru_cache_key(package_base, version, commit_hash);
        let path = self.dir.join(filename);
        let entry = CacheEntry {
            package_base: package_base.to_string(),
            version: version.to_string(),
            result: result.clone(),
            scanned_at: chrono::Utc::now(),
            commit_hash: commit_hash.map(|s| s.to_string()),
        };
        if let Ok(json) = serde_json::to_string_pretty(&entry) {
            let _ = std::fs::write(&path, json);
        }
    }

    /// Retrieve a paru-mode cached scan result.
    ///
    /// Returns `Some(result)` only if the cache file exists AND both the
    /// version and commit hash match the requested values.
    pub fn get_paru_result(
        &self,
        package_base: &str,
        version: &str,
        commit_hash: Option<&str>,
    ) -> Option<ScanResult> {
        let filename = self.make_paru_cache_key(package_base, version, commit_hash);
        let path = self.dir.join(filename);
        let data = std::fs::read_to_string(path).ok()?;
        let entry: CacheEntry = serde_json::from_str(&data).ok()?;
        if entry.version == version && entry.commit_hash.as_deref() == commit_hash {
            Some(entry.result)
        } else {
            None
        }
    }

    /// Remove the cache file for a given package base.
    ///
    /// This is a no-op if the file does not exist.
    pub fn invalidate(&self, package_base: &str) {
        let path = self
            .dir
            .join(format!("{}.json", Self::sanitize_filename(package_base)));
        let _ = std::fs::remove_file(path);
    }

    /// Sanitize a package base name for use as a filename.
    ///
    /// Replaces `/` with `_` to prevent directory traversal in file paths.
    fn sanitize_filename(base: &str) -> String {
        base.replace('/', "_")
    }
}

impl Default for FileCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ── Round-trip ─────────────────────────────────────────────────────────

    /// Put a Clean result, then get it back — should return Some(Clean).
    #[test]
    fn test_put_get_roundtrip() {
        let dir = tempdir().unwrap();
        let cache = FileCache::with_dir(dir.path().to_path_buf());

        cache.put("test-pkg", "1.0-1", &ScanResult::Clean);
        let result = cache.get("test-pkg", "1.0-1");
        assert!(matches!(result, Some(ScanResult::Clean)));
    }

    // ── Version mismatch ───────────────────────────────────────────────────

    /// Put with version "14-2", get with "14-3" — version does not match →
    /// None.
    #[test]
    fn test_version_mismatch() {
        let dir = tempdir().unwrap();
        let cache = FileCache::with_dir(dir.path().to_path_buf());

        cache.put("versioned-pkg", "14-2", &ScanResult::Clean);
        let result = cache.get("versioned-pkg", "14-3");
        assert!(result.is_none());
    }

    // ── Invalidate ─────────────────────────────────────────────────────────

    /// Put, invalidate, then get — should return None.
    #[test]
    fn test_invalidate() {
        let dir = tempdir().unwrap();
        let cache = FileCache::with_dir(dir.path().to_path_buf());

        cache.put("invalidate-me", "2.0-1", &ScanResult::Clean);
        // Verify it's there first
        assert!(cache.get("invalidate-me", "2.0-1").is_some());
        // Invalidate
        cache.invalidate("invalidate-me");
        // Verify it's gone
        assert!(cache.get("invalidate-me", "2.0-1").is_none());
    }

    // ── Missing file ───────────────────────────────────────────────────────

    /// Get on a key that was never put — should return None.
    #[test]
    fn test_get_missing_file() {
        let dir = tempdir().unwrap();
        let cache = FileCache::with_dir(dir.path().to_path_buf());

        let result = cache.get("never-put", "1.0-1");
        assert!(result.is_none());
    }

    // ── Filename sanitisation ──────────────────────────────────────────────

    /// Verify that `/` is replaced with `_` in package base names.
    #[test]
    fn test_sanitize_filename() {
        assert_eq!(FileCache::sanitize_filename("a/b"), "a_b");
    }

    // ── Paru-mode cache ─────────────────────────────────────────────────────

    /// make_paru_cache_key with 8-char hash → "paru-{base}-{hash}.json"
    #[test]
    fn test_make_paru_cache_key_with_hash() {
        let cache = FileCache::with_dir(tempdir().unwrap().path().to_path_buf());
        let key = cache.make_paru_cache_key("foo", "1.0", Some("abc123de"));
        assert_eq!(key, "paru-foo-abc123de.json");
    }

    /// make_paru_cache_key without hash → "paru-{base}.json"
    #[test]
    fn test_make_paru_cache_key_without_hash() {
        let cache = FileCache::with_dir(tempdir().unwrap().path().to_path_buf());
        let key = cache.make_paru_cache_key("foo", "1.0", None);
        assert_eq!(key, "paru-foo.json");
    }

    /// store_paru_result with hash, get_paru_result with same hash → Some
    #[test]
    fn test_paru_put_get_hash_match() {
        let dir = tempdir().unwrap();
        let cache = FileCache::with_dir(dir.path().to_path_buf());

        cache.store_paru_result("pkg", "1.0-1", Some("aaa"), &ScanResult::Clean);
        let result = cache.get_paru_result("pkg", "1.0-1", Some("aaa"));
        assert!(matches!(result, Some(ScanResult::Clean)));
    }

    /// store_paru_result with hash "aaa", get_paru_result with "bbb" → None
    #[test]
    fn test_paru_put_get_hash_mismatch() {
        let dir = tempdir().unwrap();
        let cache = FileCache::with_dir(dir.path().to_path_buf());

        cache.store_paru_result("pkg", "1.0-1", Some("aaa"), &ScanResult::Clean);
        let result = cache.get_paru_result("pkg", "1.0-1", Some("bbb"));
        assert!(result.is_none());
    }

    /// store_paru_result with None, get_paru_result with None → Some
    #[test]
    fn test_paru_put_get_no_hash() {
        let dir = tempdir().unwrap();
        let cache = FileCache::with_dir(dir.path().to_path_buf());

        cache.store_paru_result("pkg", "1.0-1", None, &ScanResult::Clean);
        let result = cache.get_paru_result("pkg", "1.0-1", None);
        assert!(matches!(result, Some(ScanResult::Clean)));
    }

    /// Yay-mode and paru-mode caches are isolated — different filenames
    #[test]
    fn test_paru_yay_key_isolation() {
        let dir = tempdir().unwrap();
        let cache = FileCache::with_dir(dir.path().to_path_buf());

        // Yay-mode store → foo.json; paru-mode read of same base → paru-foo.json
        cache.put("iso-yay", "1.0-1", &ScanResult::Clean);
        assert!(cache.get_paru_result("iso-yay", "1.0-1", None).is_none());

        // Paru-mode store → paru-iso-paru.json; yay-mode read → iso-paru.json
        cache.store_paru_result("iso-paru", "1.0-1", None, &ScanResult::Clean);
        assert!(cache.get("iso-paru", "1.0-1").is_none());
    }
}
