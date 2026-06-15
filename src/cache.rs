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
}
