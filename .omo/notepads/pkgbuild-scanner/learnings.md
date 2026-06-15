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

## Task 11 — Cache integration with scanner (src/cache.rs + src/aur.rs)
- `FileCache` now has `check_cache()` and `store_result()` — thin public wrappers around `get()`/`put()` for the scanner orchestrator (Task 9)
- `fetch_pkgbuilds()` signature changed to `(&self, cache: &FileCache, names: &[&str]) -> Result<Vec<(AurPackage, Option<String>)>, String>`
- Cache check happens per unique `PackageBase` before download; on hit, `None` is returned as PKGBUILD text (skip), on miss `Some(text)` is returned
- Test pattern for cache hit: create `FileCache` with `tempdir`, pre-populate with `cache.put()`, mount tarball mock with `.expect(0)` to assert download is never called
- Tests must pass `&cache` argument to `fetch_pkgbuilds`; existing dedup test uses empty cache (cache miss → download as before)

## Task 10 — PKGBUILD extraction + validation (src/extract.rs)
- `extract_pkgbuild()`: opens `.tar.gz` via `File::open` → `GzDecoder::new` → `tar::Archive::new`, iterates entries, checks `entry_path.file_name() == Some(OsStr::new("PKGBUILD"))` — handles both `{pkgbase}/PKGBUILD` and flat `PKGBUILD`
- Entry content read with `entry.read_to_string(&mut content)` — never sources/executes the PKGBUILD
- `validate_pkgbuild()`: checks non-empty, under 10MB, contains at least one of `pkgname=`, `pkgver=`, `source=`, `makedepends=`, `depends=` (via `str::contains`)
- `cleanup_temp_dir()`: uses `std::fs::remove_dir_all(dir)` with `let _ =` to silently ignore all errors (race-safe for temp cleanup)
- Test helper `create_tarball()` builds tar.gz in-memory using `tar::Builder` wrapping `GzEncoder::new(File::create(...))` — writes directly to a temp file
- Entry type distinction in helper: empty byte slice → `EntryType::Directory`; non-empty → `EntryType::Regular`
- Flat tarball test (`test_extract_flat_pkgbuild`) covers case where PKGBUILD is at archive root (no subdirectory)
- 11 unit tests in the module, all pass

## Task 8 — Ollama HTTP client (src/ollama.rs)
- `OllamaClient` stores `reqwest::Client`, `endpoint: String`, `model: String`
- `new()` constructor uses `reqwest::Client::builder().timeout(Duration::from_secs(120))` for 120s timeout
- `with_client()` alternate constructor accepts pre-built `reqwest::Client` for wiremock testing (avoids 120s timeout on mocked requests)
- `scan()` sends POST to `{endpoint}/api/generate` with JSON body `{"model", "prompt", "stream": false}` using `serde_json::json!()` macro
- Prompt format: `"{prompt}\n\nPKGBUILD:\n```\n{pkgbuild}\n```"` — always wraps PKGBUILD in context
- Response parsing: `serde_json::Value` → `response["response"].as_str()` → `parse_verdict()` static method
- `parse_verdict()` checks for `VERDICT: CLEAN` or `VERDICT: SUSPICIOUS` at the **very start** of response text (case-sensitive)
- FINDING extraction: `.lines().filter(|line| line.starts_with("FINDING:"))` → trim prefix + whitespace
- Unparseable responses return `Ok(ScanResult::Error("unparseable response"))` — never panics
- Wiremock test helper: `OllamaClient::with_client(reqwest::Client::new(), server.uri(), "test-model".into())`
- 13 unit tests: 5 `parse_verdict` (pure logic), 8 `scan` integration (wiremock + connection refused)
- Missing `"response"` field → `Err` (not `ScanResult::Error`)
- Malformed JSON → `Err`
- Connection refused test uses `http://127.0.0.1:19999` with 1s timeout client

## Task 9 — Scanner orchestrator (src/scanner.rs)
- `Scanner` ties AurClient + OllamaClient + FileCache + prompt into a unified pipeline
- `Scanner::new(config)` creates AurClient::new(), OllamaClient::new(endpoint, model), FileCache::new(), prompt from `prompt::get_prompt(config).to_string()`
- `scan_packages()` two-phase algorithm: Phase 1 builds `HashMap<String, ScanResult>` keyed by PackageBase (dedup); Phase 2 builds ordered `Vec<PackageScan>` matching input order
- Cache miss flow: validate PKGBUILD with `extract::validate_pkgbuild()` → scan with `ollama.scan()` → store result with `cache.store_result()`
- Cache hit flow: `fetch_pkgbuilds` returns `None` for cached bases → scanner calls `cache.check_cache()` to retrieve stored result
- Validation failures → `ScanResult::Error("PKGBUILD validation failed: ...")`
- Ollama Err (network/timeout) → `ScanResult::Error("Ollama scan failed: ...")` — error variant, not panic
- `scan_packages_batch()` delegates to `scan_packages()` (batch handled at AUR query level)
- `package_names` is `&[&str]` to accept both `&["foo"]` (stack array) and `&vec_of_strings[..]` (slice)

### AurClient testability fix
- Added `AurClient::with_client(client, base_url)` constructor (same pattern as `OllamaClient::with_client`) to allow wiremock testing without accessing private fields

### Prompt module fix
- `prompt.rs` previously used `#[cfg(test)]` mock types to avoid dependency on `types.rs` being complete
- Since all types are now fully defined in Task 9, removed mock types and always import from `crate::types::Config`
- Updated prompt tests to construct full `Config` and `OllamaConfig` structs

### Scanner tests (4 wiremock tests)
- Single `MockServer` serves both AUR RPC + tarball download + Ollama `/api/generate`
- `test_scan_packages_cache_hit`: pre-populate cache → `.expect(0)` on both tarball and Ollama mocks
- `test_scan_packages_cache_miss`: empty cache → `.expect(1)` on tarball + Ollama, verify result persisted in cache
- `test_scan_packages_dedup`: two packages sharing PackageBase → `.expect(1)` on tarball + Ollama (called once)
- `test_scan_packages_partial_failure`: body-string matchers differentiate Ollama calls — first gets CLEAN, second gets HTTP 500 → `ScanResult::Error`
- `wiremock::matchers::body_string_contains` needed when two POST mocks share same path but need different responses
- Test helper `create_test_tarball()` mirrors the pattern from aur.rs tests (tar::Builder + GzEncoder)
- All 4 tests pass; full test suite: 66 passed, 0 failed

## Task 14 — Interactive prompt (src/interactive.rs)
- `present_findings_with_reader<R: BufRead>` accepts any `BufRead` source for testability (Cursor in tests, stdin in production)
- `present_findings` wraps `present_findings_with_reader` with `std::io::stdin().lock()`
- Three-way routing: Clean → auto-approve (green ✓), Error → auto-reject (red ✗), Suspicious → prompt [y/N] (default No)
- ANSI color constants: `\x1b[32m` (green), `\x1b[33m` (yellow), `\x1b[31m` (red), `\x1b[0m` (reset)
- `std::io::stdout().flush()` required after `print!()` because it's line-buffered and has no implicit newline
- `eq_ignore_ascii_case("y")` for case-insensitive approval check — only literal `"y"` or `"Y"` triggers approve
- `has_suspicious()` returns true if ANY scan is Suspicious or Error (used by T15 to gate yay delegation)
- `print_summary()` prints a boxed table with colored APPROVE/REJECT status per package + totals
- `results` in main.rs must be declared `mut` to apply decisions via `iter_mut().zip()`
- `pub mod interactive;` required in main.rs to register the module
- 11 unit tests: 4 has_suspicious (all clean, with suspicious, with error, empty), 6 present_findings (all clean, all error, suspicious approve, suspicious reject n, suspicious default reject, mixed), 1 print_summary (no-panic check)

## Task 12 — CLI entrypoint (src/main.rs)
- `#[derive(Parser)]` with `#[command(trailing_var_arg = true)]` captures all CLI args into `args: Vec<String>`
- `#[arg(trailing_var_arg = true, allow_hyphen_values = true)]` required on the args field so clap doesn't reject flags after the first positional
- `find_real_yay()`: split `PATH` by `:`, check `{dir}/yay` with `std::fs::metadata`, exclude self via `std::fs::canonicalize` comparison with `std::env::current_exe()`
- `Cli::parse_from(&["yay", "-S", "cower"])` works with `&[&str; N]` — the full path in tests is `tests::test_*` (not `main::tests::*`) because the module is `mod tests` directly in `main.rs`
- Main routing: `args.is_empty()` → help; first arg `== "-S" || starts_with("-S")` → install mode (scan); otherwise → passthrough stub
- Stub phase: install mode prints results + `"would delegate to yay: {args:?}"`; passthrough mode prints same stub. T14/T15 will replace these.
- `crate::config::load_or_default()` and `crate::scanner::Scanner::new(&config)` wire up the full pipeline
- `pub mod config;` declaration required in main.rs to make config module accessible

## Task 13 — Command router (src/routes.rs)
- `Command` enum: `Install(Vec<String>)` (package names), `Update` (system upgrade), `Passthrough(Vec<String>)` (forward to real yay)
- `route(args: &[String]) -> Command`: classifies CLI args in priority order
  - Non-`-S` first arg → Passthrough
  - `-S` prefix with non-install chars (`s`, `i`, `l`, `g`) in suffix → Passthrough (search/info/list/groups are not install ops)
  - Pure install/update flag + package names → Install (overrides update signal)
  - Pure update flag (`yu` or `ua` in suffix) with no packages → Update
  - Otherwise → Passthrough (e.g. bare `-S` with no packages)
- `extract_package_names(args: &[String]) -> Vec<String>`: skips args[0] (the flag), collects all non-hyphen args as package names — handles interspersed flags like `--noconfirm`
- Suffix parsing: `first[2..]` gets chars after `-S`; non-install chars are `s`, `i`, `l`, `g` (search, info, list, groups)
- Valid install/update suffix chars include `y` (refresh), `u` (sysupgrade), `a` (AUR), plus any other modifiers — so use blocklist (reject `s`,`i`,`l`,`g`) rather than allowlist
- Main.rs updated: `match route(&cli.args)` replaces `starts_with("-S")` check, with separate `Command::Install`, `Command::Update`, `Command::Passthrough` arms
- 16 unit tests: 12 route tests + 4 extract_package_names tests; all pass within full suite (100 tests total)
