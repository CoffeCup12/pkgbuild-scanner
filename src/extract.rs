//! PKGBUILD extraction and validation.
//!
//! Provides functions to extract PKGBUILD content from AUR tarballs (`.tar.gz`)
//! and validate that the extracted content looks like a legitimate PKGBUILD file.
//!
//! # Safety
//!
//! PKGBUILDs are never sourced or executed — they are read as raw bytes/strings only.

use flate2::read::GzDecoder;
use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use tar::Archive;

/// Extract the PKGBUILD content from a `.tar.gz` tarball at the given path.
///
/// Opens the file, decompresses it with a `GzDecoder`, iterates over tar entries,
/// and returns the content of the first entry whose file name is `PKGBUILD`
/// (checked via `file_name()` — works for both `{pkgbase}/PKGBUILD` and flat `PKGBUILD`).
///
/// # Errors
///
/// Returns an error if:
/// - The tarball file cannot be opened or read
/// - The tarball is not valid gzip or tar format
/// - No entry named `PKGBUILD` is found
/// - The PKGBUILD entry cannot be read as UTF-8
pub fn extract_pkgbuild(tarball_path: &Path) -> Result<String, String> {
    let file = File::open(tarball_path).map_err(|e| format!("Failed to open tarball: {}", e))?;

    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    let entries = archive
        .entries()
        .map_err(|e| format!("Failed to read tarball entries: {}", e))?;

    for entry in entries {
        let mut entry = entry.map_err(|e| format!("Failed to read tarball entry: {}", e))?;
        let entry_path = entry
            .path()
            .map_err(|e| format!("Failed to get entry path: {}", e))?;

        if entry_path.file_name() == Some(OsStr::new("PKGBUILD")) {
            let mut content = String::new();
            entry
                .read_to_string(&mut content)
                .map_err(|e| format!("Failed to read PKGBUILD content: {}", e))?;
            return Ok(content);
        }
    }

    Err("No PKGBUILD found in tarball".to_string())
}

/// Validate that `content` looks like a legitimate PKGBUILD file.
///
/// Checks:
/// 1. Content is non-empty
/// 2. Size is under 10 MB (sanity check — real PKGBUILDs are <100 KB)
/// 3. Contains at least one expected PKGBUILD field (`pkgname=`, `pkgver=`,
///    `source=`, `makedepends=`, `depends=`)
///
/// Returns `Ok(())` if valid, `Err` with a human-readable description otherwise.
pub fn validate_pkgbuild(content: &str) -> Result<(), String> {
    if content.is_empty() {
        return Err("PKGBUILD is empty".to_string());
    }

    if content.len() > 10_000_000 {
        return Err("PKGBUILD exceeds 10 MB size limit".to_string());
    }

    let has_field = content.contains("pkgname=")
        || content.contains("pkgver=")
        || content.contains("source=")
        || content.contains("makedepends=")
        || content.contains("depends=");

    if !has_field {
        return Err("PKGBUILD does not contain any expected fields \
             (pkgname=, pkgver=, source=, makedepends=, depends=)"
            .to_string());
    }

    Ok(())
}

/// Remove a temporary directory and all its contents.
///
/// No-op if the directory does not exist. Errors (e.g. permissions) are silently
/// ignored since this is intended for best-effort temp directory cleanup.
pub fn cleanup_temp_dir(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Unit tests  (TDD)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::Builder;
    use tar::Header;
    use tempfile::TempDir;

    // ── helpers ────────────────────────────────────────────────────────────────

    /// Create a `.tar.gz` file at `path` with the given archive entries.
    ///
    /// Each entry is `(archive_path, content_bytes)`. An empty byte slice is
    /// treated as a directory entry.
    fn create_tarball(path: &Path, entries: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let encoder = GzEncoder::new(file, Compression::default());
        let mut tar = Builder::new(encoder);

        for (archive_path, content) in entries {
            let mut header = Header::new_gnu();
            if content.is_empty() {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
            } else {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(content.len() as u64);
            }
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, *archive_path, *content)
                .unwrap();
        }

        let encoder = tar.into_inner().unwrap();
        encoder.finish().unwrap();
    }

    // ── extract_pkgbuild ───────────────────────────────────────────────────────

    #[test]
    fn test_extract_valid_pkgbuild() {
        let tmp = TempDir::new().unwrap();
        let tar_path = tmp.path().join("test.tar.gz");

        let pkgbuild_content = "# Maintainer: Test\npkgname=test-pkg\npkgver=1.0.0\n";
        create_tarball(
            &tar_path,
            &[
                ("test-pkg/", b""), // directory entry
                ("test-pkg/PKGBUILD", pkgbuild_content.as_bytes()),
            ],
        );

        let result = extract_pkgbuild(&tar_path).unwrap();
        assert_eq!(result, pkgbuild_content);
    }

    #[test]
    fn test_extract_flat_pkgbuild() {
        // Flat tarball where PKGBUILD is at the root (no subdirectory)
        let tmp = TempDir::new().unwrap();
        let tar_path = tmp.path().join("flat.tar.gz");

        let pkgbuild_content = "pkgname=flat-pkg\n";
        create_tarball(&tar_path, &[("PKGBUILD", pkgbuild_content.as_bytes())]);

        let result = extract_pkgbuild(&tar_path).unwrap();
        assert_eq!(result, pkgbuild_content);
    }

    #[test]
    fn test_extract_no_pkgbuild() {
        let tmp = TempDir::new().unwrap();
        let tar_path = tmp.path().join("test.tar.gz");

        create_tarball(
            &tar_path,
            &[
                ("empty-pkg/", b""),
                ("empty-pkg/.SRCINFO", b"pkgbase = empty-pkg\n"),
            ],
        );

        let err = extract_pkgbuild(&tar_path).unwrap_err();
        assert!(
            err.contains("No PKGBUILD"),
            "expected 'No PKGBUILD' error, got: {err}"
        );
    }

    #[test]
    fn test_extract_invalid_tarball() {
        let tmp = TempDir::new().unwrap();
        let bad_path = tmp.path().join("not-a-tar.gz");

        std::fs::write(&bad_path, b"this is not a valid gzip file").unwrap();

        let err = extract_pkgbuild(&bad_path).unwrap_err();
        assert!(!err.is_empty(), "expected an error for invalid tarball");
    }

    // ── validate_pkgbuild ──────────────────────────────────────────────────────

    #[test]
    fn test_validate_empty() {
        let err = validate_pkgbuild("").unwrap_err();
        assert!(err.contains("empty"), "expected 'empty' error");
    }

    #[test]
    fn test_validate_not_pkgbuild() {
        let err = validate_pkgbuild("this is not a PKGBUILD at all").unwrap_err();
        assert!(
            err.contains("expected fields"),
            "expected 'expected fields' error, got: {err}"
        );
    }

    #[test]
    fn test_validate_valid() {
        let result = validate_pkgbuild(
            "# Maintainer: Test\npkgname=foo\npkgver=1.0\nsource=(https://example.com)\n",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_too_large() {
        let large = "x".repeat(10_000_001);
        let err = validate_pkgbuild(&large).unwrap_err();
        assert!(
            err.contains("10 MB"),
            "expected size limit error, got: {err}"
        );
    }

    #[test]
    fn test_validate_accepted_fields() {
        // Each of the accepted fields should pass validation individually
        assert!(validate_pkgbuild("pkgname=foo\n").is_ok());
        assert!(validate_pkgbuild("pkgver=1.0\n").is_ok());
        assert!(validate_pkgbuild("source=(url)\n").is_ok());
        assert!(validate_pkgbuild("makedepends=(cmake)\n").is_ok());
        assert!(validate_pkgbuild("depends=(glibc)\n").is_ok());
    }

    // ── cleanup_temp_dir ───────────────────────────────────────────────────────

    #[test]
    fn test_cleanup_removes_dir() {
        let tmp = TempDir::new().unwrap();
        let dir_path = tmp.path().join("to-clean");
        std::fs::create_dir_all(&dir_path).unwrap();
        std::fs::write(dir_path.join("file.txt"), b"data").unwrap();

        assert!(dir_path.exists());
        cleanup_temp_dir(&dir_path);
        assert!(!dir_path.exists(), "directory should have been removed");
    }

    #[test]
    fn test_cleanup_nonexistent() {
        let tmp = TempDir::new().unwrap();
        let ghost_path = tmp.path().join("does-not-exist");

        // Should not panic
        cleanup_temp_dir(&ghost_path);
        assert!(!ghost_path.exists());
    }
}
