// SAFETY: This module is STRICTLY read-only on paru's clone state.
// See .omo/plans/paru-support.md #Guardrail-G1
//
// Never calls aur_fetch::Fetch::mark_seen(), merge(), save_diffs(), or commit().
// Shares ~/.cache/paru/clone/ with the real paru binary.

use aur_fetch::Fetch;
use std::path::{Path, PathBuf};
use std::process::Command;

// ─── Public types ──────────────────────────────────────────────────────────────

/// Result of generating a diff for an AUR package.
#[derive(Debug)]
pub struct DiffResult {
    /// The generated diff text (plain, no ANSI color codes).
    pub diff_text: String,
    /// The HEAD commit hash in the cloned repo (40-char hex string).
    /// None if the clone directory is absent or git rev-parse fails.
    pub commit_hash: Option<String>,
    /// True when the `AUR_SEEN` ref does not exist — this is a first-time review.
    pub is_first_time: bool,
}

// ─── DiffGenerator ─────────────────────────────────────────────────────────────

/// Generator for PKGBUILD diffs using the shared paru clone state.
///
/// Uses `~/.cache/paru/clone/` as the clone directory so that package histories
/// are shared with the real paru.  This module is **strictly read-only** — it
/// never touches `AUR_SEEN`, never merges, and never writes diffs.
pub struct DiffGenerator {
    fetch: Fetch,
}

impl DiffGenerator {
    /// Create a new `DiffGenerator` pointed at `~/.cache/paru/clone/`.
    ///
    /// Falls back to `/tmp/paru/clone/` when the XDG cache directory is
    /// unavailable.
    pub fn new() -> Self {
        let cache_base = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("paru")
            .join("clone");

        Self {
            fetch: Fetch::with_combined_cache_dir(&cache_base),
        }
    }

    /// Generate a diff for a single package base.
    ///
    /// # Steps
    /// 1. Download / fetch the package from the AUR.
    /// 2. Detect `is_first_time` by checking for the `AUR_SEEN` ref.
    /// 3. Determine which packages are unseen (need review).
    /// 4. Generate a plain-text diff (`color = false`).
    /// 5. Extract the HEAD commit hash with `git rev-parse HEAD`.
    ///
    /// # Guardrail
    /// This method **NEVER** calls `mark_seen()`, `merge()`, `save_diffs()`,
    /// or `commit()`.  The paru clone state is treated as strictly read-only.
    pub fn generate_diff(&self, pkgbase: &str) -> Result<DiffResult, String> {
        let mut url = self.fetch.aur_url.clone();
        url.set_path(pkgbase);
        let repos = vec![aur_fetch::Repo {
            url,
            name: pkgbase.to_string(),
        }];
        self.generate_diff_from_repos(&repos, pkgbase)
    }

    /// Internal pipeline shared by `generate_diff` and the test harness.
    /// Accepts pre-built `Repo` objects so tests can point at local `file://`
    /// upstreams without being broken by `url.set_path()` path replacement.
    fn generate_diff_from_repos(
        &self,
        repos: &[aur_fetch::Repo],
        pkgbase: &str,
    ) -> Result<DiffResult, String> {
        // ── 1. Download ────────────────────────────────────────────────────
        self.fetch
            .download_repos::<fn(aur_fetch::Callback)>(repos)
            .map_err(|e| format!("Failed to download package '{}': {}", pkgbase, e))?;

        let pkg_vec = vec![pkgbase.to_string()];
        let clone_path = self.fetch.clone_dir.join(pkgbase);

        // ── 2. First-time detection ────────────────────────────────────────
        let is_first_time = !git_ref_exists(&clone_path, "AUR_SEEN");

        // ── 3. Unseen packages (need review) ───────────────────────────────
        let unseen = self
            .fetch
            .unseen(&pkg_vec)
            .map_err(|e| format!("Failed to check unseen for '{}': {}", pkgbase, e))?;

        // ── 4. Generate plain-text diff ────────────────────────────────────
        let diffs = self
            .fetch
            .diff(&unseen, false) // color = false → no ANSI escapes
            .map_err(|e| format!("Failed to diff '{}': {}", pkgbase, e))?;

        let diff_text = diffs.join("");

        // ── 5. Extract HEAD commit hash ────────────────────────────────────
        let commit_hash = git_rev_parse_head(&clone_path).ok();

        Ok(DiffResult {
            diff_text,
            commit_hash,
            is_first_time,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Git helpers (private — shells out to system `git` like aur-fetch does)
// ═══════════════════════════════════════════════════════════════════════════════

/// Check whether a named git ref (e.g. `AUR_SEEN`) exists in `repo_path`.
fn git_ref_exists(repo_path: &Path, ref_name: &str) -> bool {
    Command::new("git")
        .current_dir(repo_path)
        .args(["rev-parse", "--verify", ref_name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Return the full 40-character hex SHA-1 of `HEAD` in `repo_path`.
fn git_rev_parse_head(repo_path: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .current_dir(repo_path)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|e| format!("Failed to run git rev-parse: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if hash.len() == 40 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(hash)
    } else {
        Err(format!("Invalid commit hash: '{}'", hash))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Unit tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // ── helpers ────────────────────────────────────────────────────────────

    /// Run `git` inside `dir` and panic on failure.
    /// Canonicalises `dir` before setting it as `current_dir()` to avoid
    /// spurious ENOENT on freshly created directories when the full test
    /// suite exercises the process table.
    fn git(dir: &Path, args: &[&str]) {
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

    /// Create a bare-upstream repo seeded with PKGBUILD v1 and return a
    /// `DiffGenerator` pointed at it.  The `clone_dir` is left empty —
    /// aur-fetch's `download_repos()` will populate it on the first call
    /// to `generate_diff_from_repos()`.
    ///
    /// Returns the temp dir, the `DiffGenerator`, and a pre-built `Repo`
    /// with the correct `file://` URL so that `download_repos()` succeeds.
    fn setup_test_env(
        pkgbase: &str,
    ) -> (tempfile::TempDir, DiffGenerator, aur_fetch::Repo) {
        let tmp = tempfile::tempdir().unwrap();
        let upstream = tmp.path().join("upstream").join(pkgbase);
        let clone_dir = tmp.path().join("clone");
        let work = tmp.path().join("work");

        // ── 1. Bare upstream ───────────────────────────────────────────────
        fs::create_dir_all(&upstream).unwrap();
        git(&upstream, &["init", "--bare", "--initial-branch=master"]);

        // ── 2. Working tree (separate from clone_dir) → push v1 to bare ────
        fs::create_dir_all(&work).unwrap();
        git(&work, &["init", "--initial-branch=master"]);
        fs::write(
            work.join("PKGBUILD"),
            "# Maintainer: Test\npkgname=test\npkgver=1.0\npkgrel=1\n",
        )
        .unwrap();
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

        // ── 3. Fetch + Repo with the correct full URL ─────────────────────
        let mut fetch = Fetch::with_combined_cache_dir(&clone_dir);
        // aur_url is not used by the tests — set a dummy to catch accidents.
        fetch.aur_url = "file:///dev/null".parse().unwrap();

        let repo = aur_fetch::Repo {
            url: format!("file://{}", upstream.display()).parse().unwrap(),
            name: pkgbase.to_string(),
        };

        (tmp, DiffGenerator { fetch }, repo)
    }

    /// Return the path that aur-fetch will clone into for `pkgbase`.
    fn clone_path(tmp: &tempfile::TempDir, pkgbase: &str) -> PathBuf {
        tmp.path().join("clone").join(pkgbase)
    }

    /// Run `generate_diff_from_repos` with a single package.
    fn diff_one(dg: &DiffGenerator, repo: &aur_fetch::Repo, pkgbase: &str) -> Result<DiffResult, String> {
        dg.generate_diff_from_repos(std::slice::from_ref(repo), pkgbase)
    }

    // ── test 1: diff captures known changes ────────────────────────────────

    #[test]
    fn test_generate_diff_with_known_changes() {
        let (_tmp, dg, repo) = setup_test_env("testpkg");

        // Let aur-fetch clone v1 into clone_dir
        diff_one(&dg, &repo, "testpkg").unwrap();

        // Mark v1 as seen
        let p = clone_path(&_tmp, "testpkg");
        git(&p, &["tag", "AUR_SEEN"]);

        // Push v2 to upstream
        fs::write(
            p.join("PKGBUILD"),
            "# Maintainer: Test\npkgname=test\npkgver=2.0\npkgrel=1\nsource=('https://example.com/v2.tar.gz')\n",
        )
        .unwrap();
        git(&p, &["add", "PKGBUILD"]);
        git(&p, &["commit", "-m", "v2: add new source"]);
        git(&p, &["push", "origin", "master"]);

        // Second generate_diff fetches v2 and diffs against AUR_SEEN
        let result = diff_one(&dg, &repo, "testpkg").unwrap();

        assert!(
            result.diff_text.contains("source="),
            "diff should mention the new source line, got:\n{}",
            result.diff_text
        );
        assert!(!result.is_first_time, "AUR_SEEN exists → not first time");
    }

    // ── test 2: first-time flag (no AUR_SEEN) ──────────────────────────────

    #[test]
    fn test_is_first_time_flag() {
        let (_tmp, dg, repo) = setup_test_env("firstpkg");

        // aur-fetch clones — no AUR_SEEN anywhere
        let result = diff_one(&dg, &repo, "firstpkg").unwrap();

        assert!(
            result.is_first_time,
            "fresh clone without AUR_SEEN should be first-time"
        );
    }

    // ── test 3: seen package flag (AUR_SEEN exists) ────────────────────────

    #[test]
    fn test_seen_package_flag() {
        let (_tmp, dg, repo) = setup_test_env("seenpkg");

        // Let aur-fetch clone first
        diff_one(&dg, &repo, "seenpkg").unwrap();

        // Now tag AUR_SEEN
        let p = clone_path(&_tmp, "seenpkg");
        git(&p, &["tag", "AUR_SEEN"]);

        // Second call — AUR_SEEN exists
        let result = diff_one(&dg, &repo, "seenpkg").unwrap();

        assert!(
            !result.is_first_time,
            "AUR_SEEN exists → is_first_time should be false"
        );
    }

    // ── test 4: commit hash extraction ─────────────────────────────────────

    #[test]
    fn test_commit_hash_extraction() {
        let (_tmp, dg, repo) = setup_test_env("hashpkg");

        let result = diff_one(&dg, &repo, "hashpkg").unwrap();

        let hash = result
            .commit_hash
            .as_ref()
            .expect("commit_hash should be Some after clone");
        assert_eq!(
            hash.len(),
            40,
            "commit hash should be 40 hex chars, got len={}: '{}'",
            hash.len(),
            hash
        );
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "commit hash should be all hex digits, got '{}'",
            hash
        );
    }

    // ── test 5: clone failure is graceful ──────────────────────────────────

    #[test]
    fn test_clone_failure_graceful() {
        // Point at a non-existent file:// upstream so git clone fails.
        let tmp = tempfile::tempdir().unwrap();
        let clone_dir = tmp.path().join("clone");

        let mut fetch = Fetch::with_combined_cache_dir(&clone_dir);
        fetch.aur_url = format!("file://{}", tmp.path().join("nope").display())
            .parse()
            .unwrap();

        let dg = DiffGenerator { fetch };

        let result = dg.generate_diff("nonexistent-pkg-zzz");
        assert!(
            result.is_err(),
            "clone of nonexistent pkg should return Err"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("Failed to download"),
            "error should mention download failure, got: {}",
            err
        );
    }
}
