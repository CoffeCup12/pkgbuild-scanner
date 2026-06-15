# pkgbuild-scanner — AUR PKGBUILD Malware Scanner

## TL;DR

> **Quick Summary**: Build a Rust CLI tool that wraps `yay` to intercept AUR package installs, fetches PKGBUILDs via the AUR RPC API, scans them with a local Ollama model for malware, and prompts the user per-package before allowing installation.
>
> **Deliverables**:
> - Single Rust binary: `pkgbuild-scanner` (aliased as `yay`)
> - TOML config file at `~/.config/pkgbuild-scanner/config.toml`
> - Cache at XDG cache dir
> - Built-in comprehensive security audit prompt (default: qwen3.5:2b)
>
> **Estimated Effort**: Medium (15 implementation tasks, 3 waves + final)
> **Parallel Execution**: YES — 3 waves (7 + 4 + 4 tasks), then 4 review agents
> **Critical Path**: Task 1 → Task 4 → Task 8 → Task 9 → Task 12 → Task 15

---

## Context

### Original Request
Build a tool that automatically scans every PKGBUILD with an Ollama model when using `yay -Syu` or `yay -S` to install AUR packages, detecting potential malware before build/install.

### Interview Summary
**Key Discussions**:
- **Language**: Rust — single crate, no workspace.
- **Integration**: Wrapper binary that replaces `yay` (user aliases `yay` → `pkgbuild-scanner`). Non-install commands pass through to real `/usr/bin/yay`.
- **PKGBUILD fetching**: AUR RPC API — two-step: query `/rpc/v5/info/{pkg}` for `URLPath`, download tarball from that URL, extract PKGBUILD as text.
- **Detection**: Built-in comprehensive security audit prompt sent to Ollama. User can override in config. Default model: `qwen3.5:2b`.
- **Caching**: Cache scan results by PackageBase + version (pkgver-pkgrel). Cache at XDG cache dir.
- **Interactive**: Per-package y/n prompt when suspicious findings detected. Clean packages auto-approved.
- **Testing**: TDD with unit tests + integration tests (mock AUR RPC, mock Ollama).
- **Distribution**: Binary releases (GitHub) + cargo install + AUR package.

**Research Findings**:
- AUR RPC returns `URLPath`, not PKGBUILD directly — must download + extract tarball to get PKGBUILD text.
- **NEVER source/execute PKGBUILDs** — `makepkg` sources them immediately (Phase 0c), executing any code outside functions. Read as plain text only.
- Use `PackageBase` (not `Name`) as cache key — split packages share one PKGBUILD.
- RPC `Version` field is `"pkgver-pkgrel"` with optional epoch prefix — split on LAST `-`.
- yay has no plugin/hook system — binary-level wrapping is the only integration point.
- Name collisions possible: a package in both AUR and official repos. Scan AUR PKGBUILD anyway (harmless).
- Existing competitors: aur-guard, ks-aur-scanner, traur, lime. Our differentiator: **LLM-powered analysis**.
- Rust patterns: `Command::status()` for interactive passthrough (inherits stdio), `clap` with `trailing_var_arg = true`.

### Metis Review
**Identified Gaps** (addressed):
- **Two-step PKGBUILD fetch**: Incorporated — AUR client module handles info query → tarball download → extract.
- **PKGBUILD execution risk**: Guardrail added — read as text only, never source/execute.
- **Cache key should be PackageBase**: Incorporated — cache module uses PackageBase + version.
- **Version parsing**: Dedicated utility for splitting `Version` on last `-` with epoch handling.
- **Name collision edge case**: Documented limitation — scan AUR PKGBUILD even if yay might use official package.
- **Architecture**: Pre-process wrapper (Option A) confirmed — simplest and handles 90%+ of cases.

---

## Work Objectives

### Core Objective
A Rust CLI binary that intercepts `yay -S`/`yay -Syu` commands, scans AUR PKGBUILDs with a local Ollama model for malware indicators, and lets the user approve/reject each package before installation proceeds.

### Concrete Deliverables
- `Cargo.toml` with all dependencies declared
- `src/main.rs` — CLI entrypoint with clap
- `src/config.rs` — TOML config parsing, defaults
- `src/aur.rs` — AUR RPC client (info query + tarball download + extraction)
- `src/cache.rs` — File-based scan result cache
- `src/ollama.rs` — Ollama HTTP client
- `src/scanner.rs` — Orchestrator (fetch → cache check → scan → results)
- `src/prompt.rs` — Interactive per-package y/n
- `src/routes.rs` — Command routing (install vs passthrough)
- `src/exec.rs` — yay delegation with exit code propagation
- Unit tests for all modules, integration tests with mock servers

### Definition of Done
- [ ] `cargo build --release` produces working binary
- [ ] `cargo test` — all unit + integration tests pass
- [ ] `pkgbuild-scanner -Syu` → scans AUR packages with Ollama → prompts for suspicious ones → delegates to real yay
- [ ] `pkgbuild-scanner -R <pkg>` → passes through to real yay without scanning
- [ ] Config file at `~/.config/pkgbuild-scanner/config.toml` is read correctly

### Must Have
- Scan AUR PKGBUILDs for malware before yay builds/installs them
- Ollama integration with configurable model and prompt
- Interactive per-package y/n decisions
- Cache scan results by PackageBase + version
- Full passthrough for non-install yay commands (query, remove, search, etc.)
- TDD with unit + integration tests

### Must NOT Have (Guardrails)
- **NEVER** source, execute, or run `makepkg` on an untrusted PKGBUILD — read as plain text only
- No GUI/TUI — CLI only
- No daemon/background service — on-demand execution only
- No scanning of official repo packages — AUR only
- No scanning of already-installed packages
- No automatic blocking without user interaction — always prompt
- Do NOT store PKGBUILD content in cache — only scan verdicts
- Use `PackageBase` (not `Name`) as cache key for split packages

---

## Verification Strategy (MANDATORY)

> **ZERO HUMAN INTERVENTION** - ALL verification is agent-executed. No exceptions.

### Test Decision
- **Infrastructure exists**: NO (greenfield project)
- **Automated tests**: TDD — each task follows RED (failing test) → GREEN (minimal impl) → REFACTOR
- **Framework**: `cargo test` (Rust built-in test framework)

### QA Policy
Every task MUST include agent-executed QA scenarios.
Evidence saved to `.omo/evidence/task-{N}-{scenario-slug}.{ext}`.

- **CLI**: Use `interactive_bash` — run binary, validate output, check exit codes
- **API/Backend**: Use `bash` (curl) — mock HTTP servers for AUR RPC and Ollama
- **Unit tests**: Use `cargo test` — verify individual module behavior

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (Start Immediately — foundation + scaffolding, MAX PARALLEL):
├── Task 1: Project scaffolding + Cargo.toml [quick]
├── Task 2: Type definitions + data structures [quick]
├── Task 3: Config module (TOML parsing, defaults, XDG paths) [quick]
├── Task 4: AUR RPC client (info query + tarball download) [deep]
├── Task 5: Version parsing utility [quick]
├── Task 6: Cache module (file-based, PackageBase + version key) [quick]
└── Task 7: Security audit prompt template [quick]

Wave 2 (After Wave 1 — core modules, MAX PARALLEL):
├── Task 8: Ollama HTTP client [unspecified-high]
├── Task 9: Scanner orchestrator (fetch → cache → scan → result) [deep]
├── Task 10: PKGBUILD extraction + validation [quick]
└── Task 11: Cache integration with scanner [quick]

Wave 3 (After Wave 2 — CLI integration, MAX PARALLEL):
├── Task 12: CLI entrypoint (clap, trailing_var_arg) [quick]
├── Task 13: Command router (install vs passthrough detection) [deep]
├── Task 14: Interactive prompt (per-package y/n) [quick]
└── Task 15: yay delegator (Command::status, exit code propagation) [deep]

Wave FINAL (After ALL tasks — 4 parallel reviews, then user okay):
├── Task F1: Plan compliance audit (oracle)
├── Task F2: Code quality review (unspecified-high)
├── Task F3: Real manual QA (unspecified-high)
└── Task F4: Scope fidelity check (deep)
-> Present results -> Get explicit user okay

Critical Path: Task 1 → Task 4 → Task 8 → Task 9 → Task 12 → Task 15 → F1-F4 → user okay
Parallel Speedup: ~60% faster than sequential
Max Concurrent: 7 (Wave 1)
```

### Dependency Matrix

| Task | Depends On | Blocks | Wave |
|------|-----------|--------|------|
| 1 | — | 2-15 | 1 |
| 2 | — | 3, 4, 6, 8, 10, 12, 14 | 1 |
| 3 | 2 | 12 | 1 |
| 4 | 2 | 9, 10 | 1 |
| 5 | — | 6, 9 | 1 |
| 6 | 2, 5 | 9, 11 | 1 |
| 7 | — | 8 | 1 |
| 8 | 2, 7 | 9 | 2 |
| 9 | 4, 6, 8, 10 | 12, 13, 14 | 2 |
| 10 | 4 | 9 | 2 |
| 11 | 6 | 9 | 2 |
| 12 | 2, 3, 9 | 13, 14, 15 | 3 |
| 13 | 9, 12 | 15 | 3 |
| 14 | 2, 9, 12 | 15 | 3 |
| 15 | 12, 13, 14 | F1-F4 | 3 |

### Agent Dispatch Summary

- **Wave 1**: **7** — T1 → `quick`, T2 → `quick`, T3 → `quick`, T4 → `deep`, T5 → `quick`, T6 → `quick`, T7 → `quick`
- **Wave 2**: **4** — T8 → `unspecified-high`, T9 → `deep`, T10 → `quick`, T11 → `quick`
- **Wave 3**: **4** — T12 → `quick`, T13 → `deep`, T14 → `quick`, T15 → `deep`
- **FINAL**: **4** — F1 → `oracle`, F2 → `unspecified-high`, F3 → `unspecified-high`, F4 → `deep`

---

## TODOs

> Implementation + Test = ONE Task. Never separate.
> EVERY task MUST have: Recommended Agent Profile + Parallelization info + QA Scenarios.
> **A task WITHOUT QA Scenarios is INCOMPLETE.**
> **FORMAT**: Task labels MUST use bare numbers: `1.`, `2.`, `3.` — NOT `T1.`, `Task 1.`, `Phase 1:`.

- [x] 1. Project scaffolding + Cargo.toml

  **What to do**:
  - Initialize Cargo project: `cargo init` in repo root
  - Populate `Cargo.toml` with all dependencies:
    - `clap` (v4, with `derive` feature) — CLI argument parsing
    - `reqwest` (with `json`, `tokio` features) — HTTP client for AUR RPC + Ollama
    - `serde` + `serde_json` (with `derive`) — serialization
    - `toml` — config file parsing
    - `dirs` — XDG paths (~/.config, ~/.cache)
    - `tokio` (with `full` features) — async runtime
    - `flate2` + `tar` — tarball decompression and extraction
    - `tempfile` — temp directory management
  - Create directory structure: `src/` with placeholder `main.rs`
  - Add `[dev-dependencies]` for test utilities if needed
  - Verify `cargo build` compiles successfully

  **Must NOT do**:
  - Do NOT use a workspace layout — single crate only
  - Do NOT add unused dependencies

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Boilerplate scaffolding with known dependencies
  - **Skills**: `[]`
  - **Skills Evaluated but Omitted**: N/A

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 2-7)
  - **Blocks**: All subsequent tasks
  - **Blocked By**: None (can start immediately)

  **References**:
  - N/A (greenfield project)

  **Acceptance Criteria**:
  - [ ] `Cargo.toml` exists with all required dependencies declared
  - [ ] `cargo build` compiles without errors
  - [ ] `cargo test` runs (0 tests initially)

  **QA Scenarios**:

  ```
  Scenario: Project compiles from clean state
    Tool: bash
    Preconditions: Empty repo (only .git/, .omo/)
    Steps:
      1. cargo build 2>&1
      2. Check exit code is 0
    Expected Result: Exit code 0, "Compiling pkgbuild-scanner" in output, binary produced at target/debug/pkgbuild-scanner
    Failure Indicators: Non-zero exit code, missing dependency errors, compilation errors
    Evidence: .omo/evidence/task-1-build.txt

  Scenario: Verify all required dependencies are present
    Tool: bash
    Preconditions: Cargo.toml exists
    Steps:
      1. cargo metadata --format-version=1 --no-deps 2>&1
      2. Verify output contains clap, reqwest, serde, serde_json, toml, dirs, tokio, flate2, tar, tempfile
    Expected Result: All 10 dependency names present in metadata output
    Failure Indicators: Missing dependency name
    Evidence: .omo/evidence/task-1-deps.txt
  ```

  **Evidence to Capture**:
  - [ ] `.omo/evidence/task-1-build.txt` — build output
  - [ ] `.omo/evidence/task-1-deps.txt` — cargo metadata output

  **Commit**: YES (groups with Wave 1)
  - Message: `feat: add project scaffold and Cargo.toml with dependencies`
  - Files: `Cargo.toml`, `src/main.rs`

- [x] 2. Type definitions + data structures

  **What to do**:
  - Create `src/types.rs` with all shared data structures:
    - `AurRpcResponse` — deserializes AUR RPC `/rpc/v5/info` JSON response (`results: Vec<AurPackage>`)
    - `AurPackage` — fields: `Name`, `PackageBase`, `Version`, `URLPath`, `Description`
    - `ScanResult` — enum: `Clean`, `Suspicious { findings: Vec<String> }`, `Error(String)`
    - `CacheEntry` — struct: `package_base: String`, `version: String`, `result: ScanResult`, `scanned_at: DateTime<Utc>`
    - `Config` — struct (shared with config module): `ollama { model, endpoint, prompt_override }`, `cache { ttl_hours }`
    - `UserDecision` — enum: `Approve`, `Reject`
    - `PackageScan` — struct: `name: String`, `base: String`, `version: String`, `result: ScanResult`, `decision: Option<UserDecision>`
  - Derive `Serialize`, `Deserialize`, `Clone`, `Debug` where appropriate
  - Add unit tests for deserialization of `AurRpcResponse` from sample JSON

  **Must NOT do**:
  - Do NOT put business logic in types.rs — data structures only
  - Do NOT use `String` for enums that should be parsed — use proper enum variants

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Straightforward data modeling with serde derives
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1, 3-7)
  - **Blocks**: Tasks 3, 4, 6, 8, 10, 12, 14
  - **Blocked By**: Task 1 (needs Cargo.toml)

  **References**:
  - AUR RPC v5 response format: `https://aur.archlinux.org/rpc/v5/info/{name}` — test with `curl` to see real JSON shape

  **Acceptance Criteria**:
  - [ ] `src/types.rs` exists with all structs/enums
  - [ ] `AurRpcResponse` correctly deserializes from sample AUR JSON
  - [ ] Unit test: deserialize real AUR response → correct fields populated

  **QA Scenarios**:

  ```
  Scenario: Deserialize real AUR RPC response
    Tool: bash
    Preconditions: Network available
    Steps:
      1. curl -s "https://aur.archlinux.org/rpc/v5/info/cower" > /tmp/test-aur.json
      2. cargo test types::test_deserialize_aur_response -- --nocapture 2>&1
    Expected Result: Test passes, cower's Name/PackageBase/Version/URLPath correctly parsed
    Failure Indicators: Deserialization error, wrong field types, test panic
    Evidence: .omo/evidence/task-2-deser.txt

  Scenario: CacheEntry serialization roundtrip
    Tool: bash
    Preconditions: src/types.rs compiled
    Steps:
      1. cargo test types::test_cache_entry_serde -- --nocapture 2>&1
    Expected Result: Test passes, serialize → deserialize preserves all fields including DateTime
    Failure Indicators: Serialization error, timestamp precision loss, field mismatch
    Evidence: .omo/evidence/task-2-cache-serde.txt
  ```

  **Evidence to Capture**:
  - [ ] `.omo/evidence/task-2-deser.txt` — test output
  - [ ] `.omo/evidence/task-2-cache-serde.txt` — serde roundtrip test output

  **Commit**: YES (groups with Wave 1)
  - Message: `feat: add type definitions and data structures`
  - Files: `src/types.rs`

- [x] 3. Config module (TOML parsing, defaults, XDG paths)

  **What to do**:
  - Create `src/config.rs` with:
    - `Config` struct implementing `Default`
    - Default values:
      - `ollama.model = "qwen3.5:2b"`
      - `ollama.endpoint = "http://localhost:11434"`
      - `ollama.prompt_override = None` (uses built-in prompt)
      - `cache.ttl_hours = 168` (1 week)
    - `Config::load()` — reads `~/.config/pkgbuild-scanner/config.toml`, merges with defaults
    - Uses `dirs::config_dir()` for XDG-compliant path
    - `Config::load_or_default()` — returns default if file doesn't exist
    - Unit tests: default values, file parsing, missing file handling, partial override (only some fields set)
  - Create TOML config template at `~/.config/pkgbuild-scanner/config.toml` with all fields commented as documentation

  **Must NOT do**:
  - Do NOT hardcode `~/.config` — use `dirs::config_dir()`
  - Do NOT panic on missing config file — return defaults gracefully

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Standard TOML config with well-known crates (serde, toml, dirs)
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1-2, 4-7)
  - **Blocks**: Task 12 (CLI needs config)
  - **Blocked By**: Task 2 (needs Config struct from types)

  **References**:
  - `toml` crate docs: `https://docs.rs/toml/latest/toml/`
  - `dirs` crate docs: `https://docs.rs/dirs/latest/dirs/`

  **Acceptance Criteria**:
  - [ ] `src/config.rs` exists with `Config::load()` and `Config::load_or_default()`
  - [ ] `Config::default()` returns correct defaults (model=qwen3.5:2b, endpoint=localhost:11434)
  - [ ] Unit test: missing config file → returns defaults without panic
  - [ ] Unit test: partial config file → overrides specified fields, keeps defaults for others
  - [ ] Unit test: full config file → all fields overridden

  **QA Scenarios**:

  ```
  Scenario: Load defaults when config file is missing
    Tool: bash
    Preconditions: No config file exists (or test uses temp dir)
    Steps:
      1. cargo test config::test_load_defaults -- --nocapture 2>&1
    Expected Result: Test passes, config.model == "qwen3.5:2b", config.endpoint == "http://localhost:11434", no panic
    Failure Indicators: Panic on missing file, wrong defaults, test failure
    Evidence: .omo/evidence/task-3-defaults.txt

  Scenario: Partial config override preserves defaults
    Tool: bash
    Preconditions: Test creates temp TOML file with only [ollama] model = "custom-model"
    Steps:
      1. cargo test config::test_partial_override -- --nocapture 2>&1
    Expected Result: Test passes, model == "custom-model", endpoint == "http://localhost:11434" (default preserved)
    Failure Indicators: Default values overwritten to empty, wrong merge logic
    Evidence: .omo/evidence/task-3-partial.txt
  ```

  **Evidence to Capture**:
  - [ ] `.omo/evidence/task-3-defaults.txt` — default config test output
  - [ ] `.omo/evidence/task-3-partial.txt` — partial override test output

  **Commit**: YES (groups with Wave 1)
  - Message: `feat: add config module with TOML parsing and defaults`
  - Files: `src/config.rs`

- [x] 4. AUR RPC client (info query + tarball download)

  **What to do**:
  - Create `src/aur.rs` with async AUR RPC client:
    - `AurClient` struct with `reqwest::Client`
    - `async fn query_packages(names: &[String]) -> Result<Vec<AurPackage>>` — calls `/rpc/v5/info?arg[]=...` (supports multi-info with up to ~100 packages per request; batch if needed), deserializes JSON response
    - `async fn download_and_extract_pkgbuild(url_path: &str) -> Result<String>` — downloads tarball from `https://aur.archlinux.org{url_path}`, extracts into temp dir, finds and reads PKGBUILD as text, returns String content, cleans up temp dir
    - `async fn fetch_pkgbuilds(names: &[String]) -> Result<Vec<(AurPackage, String)>>` — combines query + download for each package, deduplicates by PackageBase
  - Error handling: network errors, non-200 responses, JSON parse errors, tarball extraction failures, missing PKGBUILD in tarball — all return `Result` with descriptive errors
  - Unit tests with mock HTTP server (use `wiremock` or `httpmock` crate for `[dev-dependencies]`)
  - Integration test: query real AUR API for known packages (e.g., `cower`, `yay`) — gate behind `#[cfg(feature = "integration")]`

  **Must NOT do**:
  - Do NOT execute/source the PKGBUILD — read as plain text only
  - Do NOT leave temp files after extraction — always clean up
  - Do NOT download tarballs to user's working directory — use system temp dir

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Multi-step HTTP workflow (info API → download → extract → parse), error handling for network/parsing/extraction, mock server setup for tests
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1-3, 5-7)
  - **Blocks**: Tasks 9, 10
  - **Blocked By**: Task 2 (needs AurPackage, AurRpcResponse types)

  **References**:
  - AUR RPC v5 docs: `https://wiki.archlinux.org/title/Aurweb_RPC_interface`
  - Real endpoint: `curl "https://aur.archlinux.org/rpc/v5/info/cower"` to see response shape
  - `reqwest` async examples: `https://docs.rs/reqwest/latest/reqwest/`
  - `wiremock` for HTTP mocking: `https://docs.rs/wiremock/latest/wiremock/`

  **Acceptance Criteria**:
  - [ ] `query_packages(["cower"])` returns correct AurPackage with Name/PackageBase/Version/URLPath
  - [ ] `download_and_extract_pkgbuild("/cgit/aur.git/snapshot/cower.tar.gz")` returns non-empty PKGBUILD text
  - [ ] `fetch_pkgbuilds(["cower"])` returns vec of (AurPackage, String) with PKGBUILD content
  - [ ] Deduplication: two packages sharing same PackageBase → only one tarball download
  - [ ] Unit test: mock AUR RPC returns error → `query_packages` returns Err
  - [ ] Unit test: mock tarball download fails → `download_and_extract_pkgbuild` returns Err
  - [ ] Unit test: tarball has no PKGBUILD → returns Err with descriptive message
  - [ ] Temp files cleaned up after extraction (both success and error paths)

  **QA Scenarios**:

  ```
  Scenario: Query real AUR RPC for a known package
    Tool: bash
    Preconditions: Network available
    Steps:
      1. cargo test aur::test_query_cower -- --nocapture --include-ignored 2>&1
    Expected Result: Test passes, returns AurPackage with Name="cower", PackageBase="cower", non-empty Version, URLPath contains "cower"
    Failure Indicators: Network error, deserialization failure, missing fields, empty response
    Evidence: .omo/evidence/task-4-query.txt

  Scenario: Download and extract real PKGBUILD
    Tool: bash
    Preconditions: Network available
    Steps:
      1. cargo test aur::test_download_pkgbuild -- --nocapture --include-ignored 2>&1
    Expected Result: PKGBUILD text starts with "# Maintainer:", contains pkgname=, pkgver=, source=() fields
    Failure Indicators: Empty PKGBUILD, download failure, extraction error
    Evidence: .omo/evidence/task-4-download.txt

  Scenario: Mock server returns 500 — error handled gracefully
    Tool: bash
    Preconditions: wiremock dev-dependency available
    Steps:
      1. cargo test aur::test_rpc_error_handling -- --nocapture 2>&1
    Expected Result: Test passes, query_packages returns Err (not panic), error message mentions "500" or "server error"
    Failure Indicators: Panic, unwrap on None, test failure
    Evidence: .omo/evidence/task-4-error.txt
  ```

  **Evidence to Capture**:
  - [ ] `.omo/evidence/task-4-query.txt` — query test output
  - [ ] `.omo/evidence/task-4-download.txt` — download test output
  - [ ] `.omo/evidence/task-4-error.txt` — error handling test output

  **Commit**: YES (groups with Wave 1)
  - Message: `feat: add AUR RPC client with info query and tarball download`
  - Files: `src/aur.rs`, `Cargo.toml` (if wiremock added)

- [x] 5. Version parsing utility

  **What to do**:
  - Create `src/version.rs` with:
    - `fn parse_pkgver_pkgrel(version: &str) -> Option<(String, String)>` — splits AUR RPC `Version` field (e.g., `"14-2"`, `"1:5.13-2"`) into (pkgver, pkgrel)
    - Must split on LAST `-` to handle epoch prefix (`"1:5.13-2"` → pkgver=`"1:5.13"`, pkgrel=`"2"`)
    - Returns `None` if no `-` found (malformed version)
    - `fn make_cache_key(package_base: &str, version: &str) -> String` — combines PackageBase + full version into deterministic cache key
  - Unit tests: standard version (`14-2`), epoch version (`1:5.13-2`), no pkgrel, empty string, version with multiple hyphens (`5.4.2-1`)

  **Must NOT do**:
  - Do NOT use simple `split('-')` — must split on LAST `-` only
  - Do NOT assume version format — handle edge cases gracefully with `Option`

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Small, pure function with clear spec
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1-4, 6-7)
  - **Blocks**: Tasks 6, 9
  - **Blocked By**: None

  **References**:
  - PKGBUILD(5) man page: `man 5 PKGBUILD` — describes epoch:pkgver-pkgrel format

  **Acceptance Criteria**:
  - [ ] `parse_pkgver_pkgrel("14-2")` → `Some(("14", "2"))`
  - [ ] `parse_pkgver_pkgrel("1:5.13-2")` → `Some(("1:5.13", "2"))`
  - [ ] `parse_pkgver_pkgrel("5.4.2-1")` → `Some(("5.4.2", "1"))`
  - [ ] `parse_pkgver_pkgrel("noversion")` → `None`
  - [ ] `make_cache_key("cower", "14-2")` → deterministic string like `"cower:14-2"`

  **QA Scenarios**:

  ```
  Scenario: Version parsing correctness
    Tool: bash
    Preconditions: src/version.rs compiled
    Steps:
      1. cargo test version::test_parse_pkgver_pkgrel -- --nocapture 2>&1
    Expected Result: All test cases pass — standard, epoch, multiple hyphens, no-hyphen
    Failure Indicators: Incorrect split (e.g., "14" on "1:5.13-2"), None when Some expected, panic on empty
    Evidence: .omo/evidence/task-5-parse.txt

  Scenario: Cache key deterministic and unique
    Tool: bash
    Preconditions: src/version.rs compiled
    Steps:
      1. cargo test version::test_cache_key_uniqueness -- --nocapture 2>&1
    Expected Result: Different PackageBase or version → different keys; same inputs → same key
    Failure Indicators: Hash collision, non-deterministic output
    Evidence: .omo/evidence/task-5-cache-key.txt
  ```

  **Evidence to Capture**:
  - [ ] `.omo/evidence/task-5-parse.txt` — parse test output
  - [ ] `.omo/evidence/task-5-cache-key.txt` — cache key test output

  **Commit**: YES (groups with Wave 1)
  - Message: `feat: add version parsing utility`
  - Files: `src/version.rs`

- [x] 6. Cache module (file-based, PackageBase + version key)

  **What to do**:
  - Create `src/cache.rs` with:
    - `struct FileCache { dir: PathBuf }` — wraps XDG cache directory (default: `~/.cache/pkgbuild-scanner/`)
    - `impl FileCache::new() -> Self` — creates cache directory if it doesn't exist, uses `dirs::cache_dir()`
    - `fn get(&self, package_base: &str, version: &str) -> Option<ScanResult>` — reads cache file, deserializes CacheEntry, checks if version matches exactly, returns result if match
    - `fn put(&self, package_base: &str, version: &str, result: &ScanResult)` — creates/overwrites cache file with serialized CacheEntry (JSON format for human-debuggability)
    - `fn invalidate(&self, package_base: &str)` — removes cache entry for this base
    - Cache file naming: sanitize PackageBase → `{sanitized}.json`
    - Version check: cache hit only if stored version matches requested version exactly — no fuzzy matching
    - Thread safety: `FileCache` is `Send + Sync` (file operations are atomic)
  - Unit tests: put then get returns same result, different version → cache miss, invalidate removes entry, sanitize special chars in PackageBase

  **Must NOT do**:
  - Do NOT store PKGBUILD content in cache — only ScanResult verdict
  - Do NOT do fuzzy version matching — exact match only
  - Do NOT use a single cache file for all entries — one file per PackageBase

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Simple file-based key-value store with serde serialization
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1-5, 7)
  - **Blocks**: Tasks 9, 11
  - **Blocked By**: Tasks 2 (needs CacheEntry type), 5 (needs cache key generation)

  **References**:
  - `dirs::cache_dir()` returns `~/.cache` on Linux

  **Acceptance Criteria**:
  - [ ] `put("cower", "14-2", Clean)` then `get("cower", "14-2")` → `Some(Clean)`
  - [ ] `put("cower", "14-2", Clean)` then `get("cower", "14-3")` → `None` (version mismatch)
  - [ ] `invalidate("cower")` → subsequent `get` returns `None`
  - [ ] Cache dir created at `~/.cache/pkgbuild-scanner/` on first use
  - [ ] Sanitize: PackageBase with `/` characters → safe filename

  **QA Scenarios**:

  ```
  Scenario: Cache put and get roundtrip
    Tool: bash
    Preconditions: Temp cache dir used for test
    Steps:
      1. cargo test cache::test_put_get -- --nocapture 2>&1
    Expected Result: Test passes, put Clean then get same base+version returns Some(Clean)
    Failure Indicators: None returned, wrong result, deserialization error
    Evidence: .omo/evidence/task-6-roundtrip.txt

  Scenario: Version mismatch causes cache miss
    Tool: bash
    Preconditions: Temp cache dir used for test
    Steps:
      1. cargo test cache::test_version_mismatch -- --nocapture 2>&1
    Expected Result: Test passes, put with version "14-2", get with version "14-3" returns None
    Failure Indicators: Cache returns stale result, wrong version comparison logic
    Evidence: .omo/evidence/task-6-mismatch.txt

  Scenario: Invalidate removes cached entry
    Tool: bash
    Preconditions: Entry cached first
    Steps:
      1. cargo test cache::test_invalidate -- --nocapture 2>&1
    Expected Result: Test passes, after invalidate, get returns None, cache file no longer exists
    Failure Indicators: File not deleted, get still returns result
    Evidence: .omo/evidence/task-6-invalidate.txt
  ```

  **Evidence to Capture**:
  - [ ] `.omo/evidence/task-6-roundtrip.txt`
  - [ ] `.omo/evidence/task-6-mismatch.txt`
  - [ ] `.omo/evidence/task-6-invalidate.txt`

  **Commit**: YES (groups with Wave 1)
  - Message: `feat: add file-based cache module`
  - Files: `src/cache.rs`

- [x] 7. Security audit prompt template

  **What to do**:
  - Create `src/prompt.rs` with:
    - `const DEFAULT_PROMPT: &str` — comprehensive security audit prompt for Ollama
    - Prompt content MUST instruct the model to:
      1. Analyze the PKGBUILD for: malicious URLs (curl/wget to suspicious hosts), obfuscated commands (base64, eval), sudo abuse, `rm -rf` on system paths, data exfiltration, hidden network calls, privilege escalation, persistence mechanisms, reverse shells, pipe-to-shell patterns, source of untrusted scripts
      2. Return structured verdict: begin response with `VERDICT: CLEAN` or `VERDICT: SUSPICIOUS`
      3. If SUSPICIOUS, list each finding on a new line with `FINDING: <description>` format
      4. If CLEAN, explain briefly why
      5. Consider false positives: `curl` to `github.com` or official source URLs is normal
    - `fn get_prompt(config: &Config) -> &str` — returns `config.ollama.prompt_override` if set, otherwise `DEFAULT_PROMPT`
  - Unit test: `get_prompt` with no override returns `DEFAULT_PROMPT`, with override returns custom string

  **Must NOT do**:
  - Do NOT hardcode model-specific prompt formats (e.g., chat template) — the prompt is sent as raw text, model handles formatting
  - Do NOT make the prompt overly long — keep under 2000 chars to save tokens

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Single string constant + simple accessor function
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1-6)
  - **Blocks**: Task 8
  - **Blocked By**: None

  **References**:
  - Known AUR malware patterns (from Metis research):
    - Atomic Arch (2026): 400+ packages with obfuscated data exfiltration
    - CHAOS RAT (2025): reverse shell embedded in PKGBUILD functions
    - Acroread (2018): malicious source URLs
  - Common benign patterns: `curl -L -O https://github.com/...`, `git clone`, official source tarballs

  **Acceptance Criteria**:
  - [ ] `DEFAULT_PROMPT` is a non-empty string under 2000 characters
  - [ ] `DEFAULT_PROMPT` contains "VERDICT: CLEAN" and "VERDICT: SUSPICIOUS" format instructions
  - [ ] `DEFAULT_PROMPT` mentions at least 5 of the malware pattern categories
  - [ ] `get_prompt` with override set returns custom string
  - [ ] `get_prompt` without override returns `DEFAULT_PROMPT`

  **QA Scenarios**:

  ```
  Scenario: Default prompt is well-formed and complete
    Tool: bash
    Preconditions: src/prompt.rs compiled
    Steps:
      1. cargo test prompt::test_default_prompt_content -- --nocapture 2>&1
    Expected Result: Test passes, prompt is non-empty, under 2000 chars, contains VERDICT: format instructions
    Failure Indicators: Empty prompt, too long, no verdict format, missing pattern categories
    Evidence: .omo/evidence/task-7-default-prompt.txt

  Scenario: Prompt override from config is used
    Tool: bash
    Preconditions: src/prompt.rs compiled
    Steps:
      1. cargo test prompt::test_override -- --nocapture 2>&1
    Expected Result: Test passes, get_prompt with custom config returns the override string
    Failure Indicators: Returns default instead of custom, panic
    Evidence: .omo/evidence/task-7-override.txt
  ```

  **Evidence to Capture**:
  - [ ] `.omo/evidence/task-7-default-prompt.txt`
  - [ ] `.omo/evidence/task-7-override.txt`

  **Commit**: YES (groups with Wave 1)
  - Message: `feat: add security audit prompt template`
  - Files: `src/prompt.rs`

- [x] 8. Ollama HTTP client

  **What to do**:
  - Create `src/ollama.rs` with async Ollama API client:
    - `OllamaClient` struct with `reqwest::Client` + `endpoint: String` + `model: String`
    - `OllamaClient::new(endpoint: String, model: String) -> Self`
    - `async fn scan(&self, pkgbuild: &str, prompt: &str) -> Result<ScanResult>` — sends POST to `{endpoint}/api/generate`:
      - Body: `{ "model": self.model, "prompt": "{prompt}\n\nPKGBUILD:\n```\n{pkgbuild}\n```", "stream": false }`
      - Parses `response` field from JSON response
      - Extracts verdict: look for `VERDICT: CLEAN` or `VERDICT: SUSPICIOUS` at start of response
      - If SUSPICIOUS: extract `FINDING:` lines, return `ScanResult::Suspicious { findings }`
      - If CLEAN: return `ScanResult::Clean`
      - If model response doesn't match expected format: return `ScanResult::Error("unparseable response")`
    - Timeout: 120 seconds (LLM inference can be slow on consumer hardware)
  - Unit tests with mock Ollama server (wiremock)
  - Error handling: connection refused, timeout, non-200, empty response, malformed JSON, missing `response` field

  **Must NOT do**:
  - Do NOT send PKGBUILD without wrapping in prompt context
  - Do NOT use streaming API (`"stream": false`) — simpler response parsing
  - Do NOT hardcode the prompt into this module — accept prompt as parameter

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: HTTP client with structured response parsing, mock server testing, timeout handling
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 9-11)
  - **Blocks**: Task 9
  - **Blocked By**: Tasks 2 (needs ScanResult type), 7 (needs prompt)

  **References**:
  - Ollama API docs: `https://github.com/ollama/ollama/blob/main/docs/api.md#generate-a-completion`
  - Endpoint: `POST /api/generate` with `{ "model": "...", "prompt": "...", "stream": false }`
  - Response shape: `{ "model": "...", "created_at": "...", "response": "...", "done": true }`

  **Acceptance Criteria**:
  - [ ] Sends correct POST JSON to `{endpoint}/api/generate`
  - [ ] Parses `VERDICT: CLEAN` from response → returns `ScanResult::Clean`
  - [ ] Parses `VERDICT: SUSPICIOUS` + `FINDING:` lines → returns `ScanResult::Suspicious { findings }`
  - [ ] Unparseable response → returns `ScanResult::Error(...)`
  - [ ] Connection refused → returns `Err` (not panic)
  - [ ] Timeout (120s) → returns `Err`
  - [ ] Unit test: mock server returns clean verdict → `ScanResult::Clean`
  - [ ] Unit test: mock server returns suspicious verdict → `ScanResult::Suspicious` with findings
  - [ ] Unit test: mock server returns garbage → `ScanResult::Error`

  **QA Scenarios**:

  ```
  Scenario: Scan returns clean verdict from mock Ollama
    Tool: bash
    Preconditions: wiremock dev-dependency, mock server returns {"response": "VERDICT: CLEAN\n\nThis PKGBUILD appears safe..."}
    Steps:
      1. cargo test ollama::test_scan_clean -- --nocapture 2>&1
    Expected Result: Test passes, returns Ok(ScanResult::Clean)
    Failure Indicators: Parse error, wrong verdict, timeout, test panic
    Evidence: .omo/evidence/task-8-clean.txt

  Scenario: Scan detects suspicious patterns
    Tool: bash
    Preconditions: wiremock mock returns {"response": "VERDICT: SUSPICIOUS\nFINDING: curl to unknown IP\nFINDING: base64 encoded command"}
    Steps:
      1. cargo test ollama::test_scan_suspicious -- --nocapture 2>&1
    Expected Result: Test passes, returns Ok(ScanResult::Suspicious { findings: ["curl to unknown IP", "base64 encoded command"] })
    Failure Indicators: Wrong verdict enum, missing findings, parse error
    Evidence: .omo/evidence/task-8-suspicious.txt

  Scenario: Connection error handled gracefully
    Tool: bash
    Preconditions: wiremock mock server returns 500 or connection refused
    Steps:
      1. cargo test ollama::test_connection_error -- --nocapture 2>&1
    Expected Result: Test passes, returns Err, error message mentions connection/500
    Failure Indicators: Panic, unwrap on error, Ok instead of Err
    Evidence: .omo/evidence/task-8-error.txt
  ```

  **Evidence to Capture**:
  - [ ] `.omo/evidence/task-8-clean.txt`
  - [ ] `.omo/evidence/task-8-suspicious.txt`
  - [ ] `.omo/evidence/task-8-error.txt`

  **Commit**: YES (groups with Wave 2)
  - Message: `feat: add Ollama HTTP client with verdict parsing`
  - Files: `src/ollama.rs`

- [x] 9. Scanner orchestrator (fetch → cache → scan → result)

  **What to do**:
  - Create `src/scanner.rs` with:
    - `Scanner` struct holding: `AurClient`, `OllamaClient`, `FileCache`, `String` (prompt)
    - `async fn scan_packages(&self, aur_packages: &[&str]) -> Result<Vec<PackageScan>>`:
      1. For each package name: query AUR RPC (via `AurClient::query_packages`)
      2. Deduplicate by `PackageBase`
      3. For each unique PackageBase: parse version → check cache → if cache miss: download PKGBUILD → send to Ollama → cache result → create `PackageScan`
      4. Map results back to individual package names (split packages may share one scan result)
      5. Return `Vec<PackageScan>` ordered by input
    - `async fn scan_packages_batch(&self, aur_packages: &[&str]) -> Result<Vec<PackageScan>>` — batch AUR RPC query (up to ~100 names per request) for efficiency
  - Unit tests: cache hit skips Ollama, cache miss triggers scan, PackageBase deduplication, error propagation
  - Integration test: scan known clean AUR package (e.g., `cower`) — gate behind `#[cfg(feature = "integration")]` (requires real Ollama)

  **Must NOT do**:
  - Do NOT skip cache check — always check cache before calling Ollama
  - Do NOT scan official repo packages — scanner only handles AUR packages (caller filters)
  - Do NOT proceed if PKGBUILD download fails — return error for that package, continue with others

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Complex orchestrator tying together 3 modules (AUR, cache, Ollama), multi-step async workflow, error recovery, deduplication logic
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: NO (depends on Tasks 8, 10, 11 completing)
  - **Parallel Group**: Wave 2 (runs after all Wave 2 tasks are ready, but Task 9's own work starts after 8, 10, 11 complete)
  - **Blocks**: Tasks 12, 13, 14
  - **Blocked By**: Tasks 4 (AurClient), 6 (FileCache), 8 (OllamaClient), 10 (PKGBUILD extraction), 11 (cache integration)

  **References**:
  - AUR RPC batch query: `https://aur.archlinux.org/rpc/v5/info?arg[]=pkg1&arg[]=pkg2`
  - Split packages: multiple AUR packages can share one PackageBase (e.g., `qemu` and `qemu-headless` both from PackageBase `qemu`)

  **Acceptance Criteria**:
  - [ ] `scan_packages(&["cower"])` returns one PackageScan with result
  - [ ] Cache hit: second scan of same package+version returns cached result (no Ollama call)
  - [ ] PackageBase dedup: two packages sharing same base → one Ollama call, two PackageScans with same result
  - [ ] Network error on AUR RPC → error PackageScan for that package, continue scanning others
  - [ ] Integration test (opt-in): real scan of `cower` returns a result

  **QA Scenarios**:

  ```
  Scenario: Scanner caches results and returns on cache hit
    Tool: bash
    Preconditions: Mock AurClient (returns known PackageBase+Version), mock OllamaClient (records call count), temp cache
    Steps:
      1. cargo test scanner::test_cache_hit -- --nocapture 2>&1
    Expected Result: First call triggers Ollama (call count=1), second call with same base+version returns cached result (call count still=1)
    Failure Indicators: Second call triggers Ollama again, cache not checked, wrong result
    Evidence: .omo/evidence/task-9-cache-hit.txt

  Scenario: PackageBase deduplication for split packages
    Tool: bash
    Preconditions: Mock AUR returns two packages with same PackageBase but different Names
    Steps:
      1. cargo test scanner::test_split_package_dedup -- --nocapture 2>&1
    Expected Result: Ollama called once (not twice), both PackageScans have same ScanResult, different Names
    Failure Indicators: Ollama called twice, results don't share same verdict
    Evidence: .omo/evidence/task-9-dedup.txt

  Scenario: Partial failure continues for other packages
    Tool: bash
    Preconditions: Mock AUR: pkg1 succeeds, pkg2 fails (network error)
    Steps:
      1. cargo test scanner::test_partial_failure -- --nocapture 2>&1
    Expected Result: pkg1 has ScanResult, pkg2 has ScanResult::Error, no panic
    Failure Indicators: Entire batch fails, panic, only first result returned
    Evidence: .omo/evidence/task-9-partial.txt
  ```

  **Evidence to Capture**:
  - [ ] `.omo/evidence/task-9-cache-hit.txt`
  - [ ] `.omo/evidence/task-9-dedup.txt`
  - [ ] `.omo/evidence/task-9-partial.txt`

  **Commit**: YES (groups with Wave 2)
  - Message: `feat: add scanner orchestrator`
  - Files: `src/scanner.rs`

- [x] 10. PKGBUILD extraction + validation

  **What to do**:
  - This task extends `src/aur.rs` (or creates `src/extract.rs` if separation is cleaner):
    - `fn extract_pkgbuild(tarball_path: &Path) -> Result<String>` — opens `.tar.gz`, iterates entries, finds file named `PKGBUILD` (case-sensitive), reads its content as UTF-8 string
    - `fn validate_pkgbuild(content: &str) -> Result<()>` — basic validation:
      - Non-empty
      - Contains at least one of: `pkgname=`, `pkgver=`, `source=`, `makedepends=`, `depends=`
      - Is valid UTF-8
      - Under 10MB (sanity limit — real PKGBUILDs are <100KB)
    - `fn cleanup_temp_dir(dir: &Path)` — removes temp directory recursively
  - Unit tests: valid PKGBUILD, empty tarball, tarball without PKGBUILD, binary garbage in tarball, oversized file

  **Must NOT do**:
  - Do NOT execute/source the PKGBUILD — read as raw bytes / string only
  - Do NOT leave temp files on validation failure — always clean up
  - Do NOT use shell `tar` command — use Rust `flate2` + `tar` crates

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Focused utility functions — tarball extraction with known crates, text validation
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 8, 11)
  - **Blocks**: Task 9
  - **Blocked By**: Task 4 (AurClient provides tarball path)

  **References**:
  - `flate2` crate: `https://docs.rs/flate2/latest/flate2/` — GzDecoder
  - `tar` crate: `https://docs.rs/tar/latest/tar/` — Archive, Entry
  - AUR tarball structure: tarball contains directory `{pkgbase}/` with `PKGBUILD`, `.SRCINFO`, etc.

  **Acceptance Criteria**:
  - [ ] `extract_pkgbuild("path/to/cower.tar.gz")` → returns PKGBUILD string starting with `# Maintainer:`
  - [ ] `validate_pkgbuild(valid_pkgbuild)` → `Ok(())`
  - [ ] `validate_pkgbuild("")` → `Err`
  - [ ] `validate_pkgbuild("not a pkgbuild")` → `Err`
  - [ ] `extract_pkgbuild("empty.tar.gz")` → `Err` (no PKGBUILD found)
  - [ ] `cleanup_temp_dir` removes directory and all contents

  **QA Scenarios**:

  ```
  Scenario: Extract PKGBUILD from real AUR tarball
    Tool: bash
    Preconditions: Downloaded cower tarball to /tmp
    Steps:
      1. cargo test extract::test_extract_real_pkgbuild -- --nocapture --include-ignored 2>&1
    Expected Result: Returns PKGBUILD string containing "# Maintainer:", "pkgname=cower", "pkgver="
    Failure Indicators: Extraction error, wrong file found, empty string
    Evidence: .omo/evidence/task-10-extract.txt

  Scenario: Validate rejects empty content
    Tool: bash
    Preconditions: src/extract.rs compiled
    Steps:
      1. cargo test extract::test_validate_empty -- --nocapture 2>&1
    Expected Result: Test passes, validate_pkgbuild("") returns Err
    Failure Indicators: Ok on empty, wrong error type
    Evidence: .omo/evidence/task-10-validate.txt

  Scenario: Temp directory cleanup after success and failure
    Tool: bash
    Preconditions: Temp dir created
    Steps:
      1. cargo test extract::test_cleanup -- --nocapture 2>&1
    Expected Result: Test passes, temp dir does not exist after cleanup call, works on both existing and non-existing dirs
    Failure Indicators: Directory still exists, panic on non-existent dir
    Evidence: .omo/evidence/task-10-cleanup.txt
  ```

  **Evidence to Capture**:
  - [ ] `.omo/evidence/task-10-extract.txt`
  - [ ] `.omo/evidence/task-10-validate.txt`
  - [ ] `.omo/evidence/task-10-cleanup.txt`

  **Commit**: YES (groups with Wave 2)
  - Message: `feat: add PKGBUILD extraction and validation`
  - Files: `src/extract.rs` (or appends to `src/aur.rs`)

- [x] 11. Cache integration with scanner

  **What to do**:
  - In `src/cache.rs`, implement cache integration helpers:
    - `Scanner::check_cache(&self, base: &str, version: &str) -> Option<ScanResult>` — thin wrapper
    - In `scan_packages` loop: before calling Ollama, check `self.cache.get(base, version)`
    - If cache hit: use cached result, skip Ollama call, log "using cached result for {base} v{version}"
    - If cache miss: proceed with Ollama scan, then `self.cache.put(base, version, &result)` before returning
  - This task is primarily about wiring — most logic in cache/scanner modules already exists
  - Verify: cache hit path has end-to-end unit test (mock AUR + mock Ollama + real FileCache with temp dir)
  - Ensure concurrent scans don't race on cache writes (tokio mutex or file-level atomicity)

  **Must NOT do**:
  - Do NOT duplicate cache logic — reuse `FileCache` from Task 6
  - Do NOT skip cache check on any code path — always check cache first

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Integration/wiring task — existing modules already built, just connecting them
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 8, 10)
  - **Blocks**: Task 9
  - **Blocked By**: Task 6 (FileCache module)

  **References**:
  - Task 6 cache module: `src/cache.rs`
  - Task 9 scanner: `src/scanner.rs`

  **Acceptance Criteria**:
  - [ ] Scanner calls `cache.get()` before `ollama.scan()`
  - [ ] Cache hit: Ollama NOT called, cached ScanResult returned
  - [ ] Cache miss: Ollama called, result cached via `cache.put()`
  - [ ] Unit test: mock Ollama counts calls — 2 scans of same base+version → 1 Ollama call

  **QA Scenarios**:

  ```
  Scenario: End-to-end cache hit avoids Ollama
    Tool: bash
    Preconditions: Mock AurClient, mock OllamaClient (with spy counter), temp FileCache
    Steps:
      1. cargo test scanner::test_e2e_cache_hit -- --nocapture 2>&1
    Expected Result: First scan → Ollama called once. Second scan of same pkg → Ollama still called once. Both return same result.
    Failure Indicators: Ollama called twice, different results, cache not consulted
    Evidence: .omo/evidence/task-11-e2e-cache.txt
  ```

  **Evidence to Capture**:
  - [ ] `.omo/evidence/task-11-e2e-cache.txt`

  **Commit**: YES (groups with Wave 2)
  - Message: `feat: integrate cache with scanner orchestrator`
  - Files: `src/cache.rs` (modified)

- [x] 12. CLI entrypoint (clap, trailing_var_arg)

  **What to do**:
  - Create `src/main.rs` with:
    - `clap` derive-based CLI:
      - `struct Cli` with `#[command(trailing_var_arg = true)]`
      - `#[arg(trailing_var_arg = true, allow_hyphen_values = true)] args: Vec<String>` — captures ALL args after binary name
    - `#[tokio::main]` async entrypoint:
      1. Parse args via clap
      2. Load config (`Config::load_or_default()`)
      3. Route to command handler (Task 13)
      4. If scan mode: initialize Scanner, run scan, present results (Task 14), delegate to yay (Task 15)
      5. Exit with appropriate code
    - `fn find_real_yay() -> PathBuf` — searches PATH for `/usr/bin/yay` or `yay` binary, resolves absolute path (prevents recursive self-invocation)
  - Unit test: clap parses `yay -S cower`, `yay -Syu`, `yay -R cower`

  **Must NOT do**:
  - Do NOT use `env::args()` directly — use clap's parsed args
  - Do NOT invoke self recursively — always resolve absolute path to real yay
  - Do NOT panic on missing real yay — print error and exit with helpful message

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Standard clap setup with async main, straightforward arg routing
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 3 (with Tasks 13-15)
  - **Blocks**: Tasks 13, 14, 15
  - **Blocked By**: Tasks 2 (needs Config type), 3 (needs Config::load), 9 (needs Scanner)

  **References**:
  - clap trailing_var_arg: `https://docs.rs/clap/latest/clap/_derive/_tutorial/chapter_0/index.html`
  - clap `allow_hyphen_values`: prevents `--flag` being parsed as clap flags after `trailing_var_arg`
  - `std::env::current_exe()` for self-path resolution
  - `which::which("yay")` or manual PATH search

  **Acceptance Criteria**:
  - [ ] `pkgbuild-scanner -S cower` → parses correctly, routes to scan mode
  - [ ] `pkgbuild-scanner -Syu` → parses correctly, routes to scan mode
  - [ ] `pkgbuild-scanner -R cower` → parses correctly, routes to passthrough
  - [ ] `pkgbuild-scanner --help` → prints help message
  - [ ] Real yay not found → prints error, exits non-zero (does not recurse)
  - [ ] Config loaded from file or defaults

  **QA Scenarios**:

  ```
  Scenario: CLI parses install command correctly
    Tool: bash
    Preconditions: Binary compiled
    Steps:
      1. cargo run -- -S cower 2>&1; echo "EXIT: $?"
    Expected Result: Does NOT panic/error due to arg parsing. Route detection triggers (even if scanner fails — that's fine, we're testing CLI parsing)
    Failure Indicators: Clap error, "unrecognized argument", panic on missing real yay
    Evidence: .omo/evidence/task-12-install-parse.txt

  Scenario: CLI parses passthrough command correctly
    Tool: bash
    Preconditions: Binary compiled
    Steps:
      1. cargo run -- -R cower 2>&1; echo "EXIT: $?"
    Expected Result: Command recognized as passthrough, not scan mode
    Failure Indicators: Treated as install, clap parsing error
    Evidence: .omo/evidence/task-12-passthrough.txt

  Scenario: Real yay not found gives helpful error
    Tool: bash
    Preconditions: PATH modified to exclude /usr/bin
    Steps:
      1. PATH=/nonexistent cargo run -- -S cower 2>&1; echo "EXIT: $?"
    Expected Result: Error message about yay not found, non-zero exit code, no panic
    Failure Indicators: Panic, zero exit code, cryptic error
    Evidence: .omo/evidence/task-12-no-yay.txt
  ```

  **Evidence to Capture**:
  - [ ] `.omo/evidence/task-12-install-parse.txt`
  - [ ] `.omo/evidence/task-12-passthrough.txt`
  - [ ] `.omo/evidence/task-12-no-yay.txt`

  **Commit**: YES (groups with Wave 3)
  - Message: `feat: add CLI entrypoint with clap`
  - Files: `src/main.rs`

- [x] 13. Command router (install vs passthrough detection)

  **What to do**:
  - Create `src/routes.rs` with:
    - `enum Command { Install(Vec<String>), Update, Passthrough(Vec<String>) }` — Install holds package names, Update means -Syu/-Sua, Passthrough passes args to yay
    - `fn route(args: &[String]) -> Command`:
      - Recognizes install flags: `-S`, `--sync`, `-Syu`, `-Syua`, `-Sua`, `-Syu --noconfirm`, etc.
      - Recognizes update flags: `-Syu` (no package args), `-Syua`
      - Everything else → `Passthrough` (includes `-R`, `-Q`, `-Ss`, `-Si`, `-Y`, `-P`, etc.)
    - `fn extract_package_names(args: &[String]) -> Vec<String>` — after `-S`, extract non-flag args (filter out anything starting with `-`)
    - Handle edge cases: `-S --noconfirm cower` (flag before package), `-Scower` (combined flag form), `-Syu pkg1 pkg2 --noconfirm` (flags interspersed)
  - Unit tests: all yay subcommands correctly routed, flag filtering, edge cases

  **Must NOT do**:
  - Do NOT route `-S` without package names to scan mode — it's `-Syu` (update all)
  - Do NOT assume package names follow directly after `-S` — flags can be interspersed
  - Do NOT route unknown flags to scan — passthrough to real yay which handles its own errors

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Complex arg parsing with edge cases, flag interspersion, combined short flags, large test matrix
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 3 (with Tasks 12, 14-15)
  - **Blocks**: Task 15
  - **Blocked By**: Tasks 9, 12

  **References**:
  - yay man page: lists all subcommands and flags
  - yay recognized flags (from research): `-S`, `--sync`, `-R`, `--remove`, `-Q`, `--query`, `-Ss`, `-Si`, `-Su`, `-Syu`, `-Syua`, `-Sua`, `-Y`, `--yay`, `-P`, `--show`, etc.

  **Acceptance Criteria**:
  - [ ] `route(["-S", "cower"])` → `Install(["cower"])`
  - [ ] `route(["-Syu"])` → `Update`
  - [ ] `route(["-R", "cower"])` → `Passthrough`
  - [ ] `route(["-S", "--noconfirm", "cower", "yay"])` → `Install(["cower", "yay"])`
  - [ ] `route(["-Ss", "searchterm"])` → `Passthrough`
  - [ ] `route(["--help"])` → `Passthrough` (let yay handle its own help)

  **QA Scenarios**:

  ```
  Scenario: All install variants route correctly
    Tool: bash
    Preconditions: src/routes.rs compiled
    Steps:
      1. cargo test routes::test_install_routing -- --nocapture 2>&1
    Expected Result: All -S, -Syu, -Sua, -S pkg1 pkg2 variants route to Install or Update
    Failure Indicators: Install routed as Passthrough, wrong package names extracted
    Evidence: .omo/evidence/task-13-routing.txt

  Scenario: Flags interspersed with package names
    Tool: bash
    Preconditions: src/routes.rs compiled
    Steps:
      1. cargo test routes::test_flag_interspersion -- --nocapture 2>&1
    Expected Result: `-S --noconfirm cower --overwrite '*' yay` → Install(["cower", "yay"])
    Failure Indicators: Flags treated as package names, packages treated as flags
    Evidence: .omo/evidence/task-13-flags.txt

  Scenario: All passthrough commands identified correctly
    Tool: bash
    Preconditions: src/routes.rs compiled
    Steps:
      1. cargo test routes::test_passthrough_routing -- --nocapture 2>&1
    Expected Result: -R, -Q, -Ss, -Si, -Y, -P, --help all route to Passthrough
    Failure Indicators: Any non-install command routed to Install/Update
    Evidence: .omo/evidence/task-13-passthrough.txt
  ```

  **Evidence to Capture**:
  - [ ] `.omo/evidence/task-13-routing.txt`
  - [ ] `.omo/evidence/task-13-flags.txt`
  - [ ] `.omo/evidence/task-13-passthrough.txt`

  **Commit**: YES (groups with Wave 3)
  - Message: `feat: add command router for install vs passthrough`
  - Files: `src/routes.rs`

- [x] 14. Interactive prompt (per-package y/n)

  **What to do**:
  - Create `src/prompt.rs` (extend existing) or `src/interactive.rs` with:
    - `fn present_findings(scans: &[PackageScan]) -> Vec<UserDecision>`:
      1. Print header: "pkgbuild-scanner: analyzed N AUR packages"
      2. For each PackageScan:
         - If `Clean`: print "✓ {name} v{version} — clean" (green if terminal supports it)
         - If `Suspicious { findings }`: print "⚠ {name} v{version} — SUSPICIOUS", list each finding, prompt "Proceed with install? [y/N]: "
         - If `Error(msg)`: print "✗ {name} — error: {msg}", treat as auto-reject
      3. Read user input (stdin) for each suspicious package
      4. Default to `Reject` on empty input (just Enter) or anything not starting with 'y'/'Y'
      5. Return `Vec<UserDecision>` aligned with input order
    - `fn print_summary(decisions: &[UserDecision], scans: &[PackageScan])` — final summary before executing yay: "Installing: X packages, Skipping: Y packages"
  - Handle: stdin/stdout correctly when running as yay wrapper (terminal attached)
  - Handle: `--noconfirm` flag → skip prompts, auto-reject suspicious packages

  **Must NOT do**:
  - Do NOT use TUI libraries — simple stdin/stdout line-based interaction only
  - Do NOT auto-accept suspicious packages — default to Reject on empty input
  - Do NOT buffer all output — print per-package as results come in

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Simple stdin/stdout interaction, straightforward display logic
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 3 (with Tasks 12-13, 15)
  - **Blocks**: Task 15
  - **Blocked By**: Tasks 2 (needs PackageScan, UserDecision types), 9 (needs Scanner results), 12

  **References**:
  - Rust stdin reading: `std::io::stdin().read_line(&mut String)`
  - Terminal color: `colored` crate or ANSI escape codes directly

  **Acceptance Criteria**:
  - [ ] Clean packages: displayed with checkmark, no prompt, auto-approved
  - [ ] Suspicious packages: displayed with warning, findings listed, prompt for y/n
  - [ ] Empty input → Reject (not Approve)
  - [ ] 'y' or 'Y' → Approve
  - [ ] 'n', 'N', or anything else → Reject
  - [ ] Error packages: displayed with error marker, auto-rejected (no prompt)
  - [ ] Summary printed before delegating to yay
  - [ ] `--noconfirm` flag in args → skip all prompts, auto-reject suspicious

  **QA Scenarios**:

  ```
  Scenario: Clean packages auto-approved without prompt
    Tool: interactive_bash (tmux)
    Preconditions: Binary compiled, simulated scans with one Clean result
    Steps:
      1. Run: echo "" | cargo run -- -S clean-pkg 2>&1
    Expected Result: Output contains "✓ clean-pkg — clean", no "[y/N]" prompt, proceeds to summary
    Failure Indicators: Prompt appears for clean package, clean package rejected
    Evidence: .omo/evidence/task-14-clean.txt

  Scenario: Suspicious package prompts user and accepts 'y'
    Tool: interactive_bash (tmux)
    Preconditions: Binary compiled, simulated scans with one Suspicious result
    Steps:
      1. Send: echo "y" | cargo run -- -S susp-pkg 2>&1
    Expected Result: Output contains "⚠ susp-pkg — SUSPICIOUS", findings listed, prompt "[y/N]", accepts 'y', package in "Installing" list
    Failure Indicators: Prompt not shown, 'y' rejected, default behavior incorrect
    Evidence: .omo/evidence/task-14-suspicious-accept.txt

  Scenario: Empty input defaults to reject
    Tool: interactive_bash (tmux)
    Preconditions: Binary compiled, simulated scans with one Suspicious result
    Steps:
      1. Send: echo "" | cargo run -- -S susp-pkg 2>&1
    Expected Result: Prompt shown, empty input → Reject, package in "Skipping" list
    Failure Indicators: Empty input → Approve, hang waiting for input
    Evidence: .omo/evidence/task-14-reject.txt
  ```

  **Evidence to Capture**:
  - [ ] `.omo/evidence/task-14-clean.txt`
  - [ ] `.omo/evidence/task-14-suspicious-accept.txt`
  - [ ] `.omo/evidence/task-14-reject.txt`

  **Commit**: YES (groups with Wave 3)
  - Message: `feat: add interactive per-package y/n prompt`
  - Files: `src/interactive.rs` (or extended `src/prompt.rs`)

- [x] 15. yay delegator (Command::status, exit code propagation)

  **What to do**:
  - Create `src/exec.rs` with:
    - `fn delegate_to_yay(args: &[String]) -> std::process::ExitCode`:
      1. Resolves real yay path (absolute, prevent recursion)
      2. Builds `std::process::Command` with all args
      3. Calls `.status()` — inherits stdin/stdout/stderr for interactive passthrough
      4. Propagates exit code: `status.code().map(|c| ExitCode::from(c as u8)).unwrap_or(ExitCode::from(1))`
      5. On Unix: if process killed by signal, exit code = 128 + signal number
    - `fn build_install_command(approved: &[String], original_args: &[String]) -> Vec<String>` — reconstructs yay `-S` command with only approved packages, preserves flags (--noconfirm, --overwrite, etc.)
  - Unit tests: exit code propagation (0 → 0, 1 → 1), signal exit code (SIGTERM 15 → 143), approved package filtering preserves flags

  **Must NOT do**:
  - Do NOT use `Command::output()` — would capture stdout and break interactive yay (user sees no progress)
  - Do NOT call self — always resolve absolute path to real yay binary
  - Do NOT modify original_args in place — build new Vec

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Process management with exit code propagation, signal handling, stdin/stdout inheritance, flag preservation in command reconstruction
  - **Skills**: `[]`

  **Parallelization**:
  - **Can Run In Parallel**: NO (depends on Tasks 13, 14 completing)
  - **Parallel Group**: Wave 3 (runs sequentially after 12, 13, 14)
  - **Blocks**: F1-F4
  - **Blocked By**: Tasks 12, 13, 14

  **References**:
  - `std::process::Command::status()`: inherits stdio, returns `ExitStatus`
  - Unix signal exit codes: 128 + signal number (convention)
  - yay binary location: typically `/usr/bin/yay` (from AUR install) or `~/.local/bin/yay`

  **Acceptance Criteria**:
  - [ ] `delegate_to_yay(&["-R", "cower"])` → runs `yay -R cower`, propagates exit code
  - [ ] `build_install_command(&["cower"], &["-S", "--noconfirm", "cower", "yay"])` → `["-S", "--noconfirm", "cower"]` (only approved package kept)
  - [ ] `build_install_command(&[], &["-S", "susp-pkg"])` → `[]` or exits early (nothing to install)
  - [ ] Exit code 0 → `ExitCode::from(0)`
  - [ ] Exit code 1 → `ExitCode::from(1)`
  - [ ] Signal kill → exit code 128 + signal number

  **QA Scenarios**:

  ```
  Scenario: Passthrough command executes real yay
    Tool: bash
    Preconditions: Real yay installed (or mock yay script on PATH)
    Steps:
      1. Create mock /tmp/yay-mock that echoes args and exits 0
      2. PATH=/tmp:$PATH cargo run -- -R testpkg 2>&1; echo "EXIT: $?"
    Expected Result: Mock yay executes, exit code 0, args "-R testpkg" passed through
    Failure Indicators: Recursion (calls self), wrong args, non-zero exit
    Evidence: .omo/evidence/task-15-passthrough.txt

  Scenario: Install command filters rejected packages
    Tool: bash
    Preconditions: All modules built, mock or real yay available
    Steps:
      1. echo "n" | cargo run -- -S test-pkg1 test-pkg2 2>&1
    Expected Result: If both rejected, yay not called at all (or called with zero packages and exits)
    Failure Indicators: Rejected packages passed to yay, yay called with wrong args
    Evidence: .omo/evidence/task-15-filter.txt

  Scenario: Exit code propagation
    Tool: bash
    Preconditions: Mock yay exits with code 42
    Steps:
      1. cargo test exec::test_exit_code_propagation -- --nocapture 2>&1
    Expected Result: delegate_to_yay mock → exit code 42 propagated
    Failure Indicators: Exit code 0 regardless of child, wrong exit code mapping
    Evidence: .omo/evidence/task-15-exit-code.txt
  ```

  **Evidence to Capture**:
  - [ ] `.omo/evidence/task-15-passthrough.txt`
  - [ ] `.omo/evidence/task-15-filter.txt`
  - [ ] `.omo/evidence/task-15-exit-code.txt`

  **Commit**: YES (groups with Wave 3)
  - Message: `feat: add yay delegator with exit code propagation`
  - Files: `src/exec.rs`

---

## Final Verification Wave (MANDATORY — after ALL implementation tasks)

> 4 review agents run in PARALLEL. ALL must APPROVE. Present consolidated results to user and get explicit "okay" before completing.

- [x] F1. **Plan Compliance Audit** — `oracle`
  Read the plan end-to-end. For each "Must Have": verify implementation exists (read file, run binary, check output). For each "Must NOT Have": search codebase for forbidden patterns — reject with file:line if found. Check evidence files exist in `.omo/evidence/`. Compare deliverables against plan.
  Output: `Must Have [N/N] | Must NOT Have [N/N] | Tasks [N/N] | VERDICT: APPROVE/REJECT`

- [x] F2. **Code Quality Review** — `unspecified-high`
  Run `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`. Review all changed files for: `unwrap()` in non-test code, `unsafe` blocks, empty catch-all match arms, leftover debug prints, commented-out code. Check AI slop: excessive comments, over-abstraction, generic names (data/result/item/temp).
  Output: `Build [PASS/FAIL] | Test [N pass/N fail] | Clippy [CLEAN/N warnings] | Fmt [CLEAN/N diffs] | VERDICT`

- [x] F3. **Real Manual QA** — `unspecified-high`
  Start from clean state. Execute EVERY QA scenario from EVERY task — follow exact steps, capture evidence. Test cross-task integration: install command flow, passthrough command flow, cache hit/miss, error handling. Test edge cases: no network, Ollama down, malformed PKGBUILD, empty AUR response. Save to `.omo/evidence/final-qa/`.
  Output: `Scenarios [N/N pass] | Integration [N/N] | Edge Cases [N tested] | VERDICT`

- [x] F4. **Scope Fidelity Check** — `deep`
  For each task: read "What to do", read actual diff (git diff/log). Verify 1:1 — everything in spec was built (no missing), nothing beyond spec was built (no creep). Check "Must NOT do" compliance. Detect cross-task contamination. Flag unaccounted changes.
  Output: `Tasks [N/N compliant] | Contamination [CLEAN/N issues] | Unaccounted [CLEAN/N files] | VERDICT`

---

## Commit Strategy

- **Wave 1**: `feat: add project scaffold, types, config, AUR client, cache` — all Wave 1 files
- **Wave 2**: `feat: add Ollama client, scanner orchestrator` — all Wave 2 files
- **Wave 3**: `feat: add CLI, command routing, interactive prompt, yay delegation` — all Wave 3 files

---

## Success Criteria

### Verification Commands
```bash
cargo build --release    # Expected: compiles without errors
cargo test               # Expected: all tests pass
cargo clippy -- -D warnings  # Expected: no warnings
cargo fmt --check        # Expected: no formatting diffs
```

### Final Checklist
- [ ] All "Must Have" present
- [ ] All "Must NOT Have" absent
- [ ] All tests pass
- [ ] Binary can intercept `-S` and `-Syu` commands
- [ ] Binary passes through non-install commands to real yay
- [ ] Config file is read correctly
- [ ] Cache is read/written correctly
- [ ] Ollama integration works end-to-end
