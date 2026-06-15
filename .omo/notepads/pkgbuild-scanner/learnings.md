# Learnings — pkgbuild-scanner

## Conventions
- Single Rust crate, no workspace
- TDD: RED → GREEN → REFACTOR
- TOML config at ~/.config/pkgbuild-scanner/
- JSON cache at ~/.cache/pkgbuild-scanner/

## Patterns
- Use Command::status() not output() for interactive yay passthrough
- Use clap with trailing_var_arg = true, allow_hyphen_values = true
- Split RPC Version field on LAST - (handle epoch prefix)
- PackageBase as cache key (not Name)

## Gotchas
- NEVER source/execute PKGBUILDs — read as plain text only
- AUR RPC returns URLPath, not PKGBUILD — two-step fetch required
- yay has no plugin system — binary-level wrapping only

## Rust Dependencies & Versions
- `edition = "2024"` requires Rust ≥1.85 (verified: rustc 1.96.0)
- reqwest v0.12 pinned deliberately over v0.13 for stability
- toml v0.8 pinned deliberately over v1.x for stable serde integration
- wiremock added to dev-dependencies for HTTP mock testing
- chrono with `serde` feature required for CacheEntry DateTime<Utc> serialization
- flate2 + tar for archive extraction (PKGBUILD tarballs from AUR)
- Rust 1.96.0 auto-locked v0.12 for reqwest and v0.8 for toml (compatible versions)

## Types & Data Structures (src/types.rs)
- `AurRpcResponse` uses `#[serde(rename_all = "PascalCase")]` + explicit `#[serde(rename = "results")]` on the `results` field because AUR top-level response is camelCase but the attribute is applied per convention
- `AurPackage` uses `rename_all = "PascalCase"` to match AUR JSON keys (`Name`, `PackageBase`, `Version`, `Description`)
- `URLPath` needs explicit `#[serde(rename = "URLPath")]` because PascalCase rename would produce `UrlPath` (capital U, P, lowercase ath)
- `UserDecision` must derive `PartialEq` if used with `assert_eq!` in tests
- `CacheEntry` round-trip preserves `DateTime<Utc>` thanks to chrono's `serde` feature
- `ScanResult` uses serde's default adjacently-tagged enum representation (`"Clean"`, `{"Suspicious": ...}`, `{"Error": ...}`)
- Version parsing: `str::rfind('-')` splits on LAST hyphen for epoch-safe pkgver/pkgrel extraction
- Cache key: deterministic `"pkgbase:version"` format via `format!()` — no side effects

## Task 6 — File-based cache (src/cache.rs)
- `FileCache` is a `PathBuf` wrapper with `new()` (XDG cache dir) and `with_dir()` (testing constructor)
- One JSON file per package base: `{sanitized_base}.json` with a `CacheEntry` inside (not a single monolithic file)
- Version stored INSIDE the file alongside the result; retrieval requires **exact** version match (`entry.version == requested_version`)
- `sanitize_filename()` replaces `/` with `_` to prevent directory traversal
- `CacheEntry` includes `scanned_at: DateTime<Utc>` timestamp for TTL checks elsewhere
- `get()` returns `None` on ANY error (missing file, parse failure, version mismatch) — no error propagation
- `put()` uses `serde_json::to_string_pretty` for human-readable JSON
- `invalidate()` is a no-op if file doesn't exist (`remove_file().ok()`)
- Tests use `tempfile::tempdir()` + `with_dir()` for isolation — never touch real `~/.cache/`

## Task 7 — Security audit prompt (src/prompt.rs)
- `prompt.rs` defines `DEFAULT_PROMPT` (1156 chars, <2000) and `get_prompt(config)`
- Uses `#[cfg(not(test))]` / `#[cfg(test)]` pattern to import `Config` from `crate::types` in production but from a local `mock_types` module in tests — avoids dependency on types.rs being complete
- `concat!()` macro used to build the prompt string (compile-time concatenation, zero runtime cost)
- Prompt covers 10 malware categories + false positive guidance
- Response format contract: `VERDICT: CLEAN` or `VERDICT: SUSPICIOUS` followed by `FINDING: <description>` lines

## Task 4 — AUR RPC client (src/aur.rs)
- `AurClient` stores `reqwest::Client` + `base_url: String` (defaults to `https://aur.archlinux.org`)
- `query_packages()` builds URL `{base_url}/rpc/v5/info?arg[]=name1&arg[]=name2`, parses `AurRpcResponse`, returns `Vec<AurPackage>`
- `download_and_extract_pkgbuild()` downloads `{base_url}{url_path}`, GzDecoder + tar::Archive extraction into tempfile::tempdir(), recursive `find_pkgbuild()` locates `PKGBUILD` (case-sensitive), reads as UTF-8
- `fetch_pkgbuilds()` combines query + download, deduplicates by `PackageBase` using `HashSet<String>` + `HashMap<String, String>` (base → content cache)
- Wiremock testing pattern: `MockServer::start().await`, build `AurClient { client: reqwest::Client::new(), base_url: server.uri() }`, mount mocks by path+method, verify `.expect(n)` for dedup tests
- In-memory tarball creation: `tar::Builder` with `append_data` for directory + file entries, then `GzEncoder::new()` wrapping `Vec<u8>` with `encoder.finish().unwrap()` to get compressed bytes
- Integration tests gated behind `#[cfg(all(test, feature = "integration"))]` with `[features] integration = []` in Cargo.toml
- `reqwest::get()` avoided in favour of `self.client.get()` for testability (custom base_url for wiremock)
- `GzEncoder::finish()` consumes the encoder and returns the inner writer; with `&mut Vec<u8>` as writer, the vec is mutated in-place, so the vec variable is still accessible after the encoder's scope ends
