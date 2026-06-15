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

## Task 7 — Security audit prompt (src/prompt.rs)
- `prompt.rs` defines `DEFAULT_PROMPT` (1156 chars, <2000) and `get_prompt(config)`
- Uses `#[cfg(not(test))]` / `#[cfg(test)]` pattern to import `Config` from `crate::types` in production but from a local `mock_types` module in tests — avoids dependency on types.rs being complete
- `concat!()` macro used to build the prompt string (compile-time concatenation, zero runtime cost)
- Prompt covers 10 malware categories + false positive guidance
- Response format contract: `VERDICT: CLEAN` or `VERDICT: SUSPICIOUS` followed by `FINDING: <description>` lines
