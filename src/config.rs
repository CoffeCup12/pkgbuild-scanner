//! Configuration loading — TOML parsing, defaults, XDG paths.
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::config;
//!
//! let cfg = config::load_or_default();
//! println!("model: {}", cfg.ollama.model);
//! ```

use std::path::{Path, PathBuf};

use crate::types::{Backend, CacheConfig, Config, HelperConfig, OllamaConfig};

// ═══════════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════════

/// Return a `Config` populated with the standard defaults.
pub fn default_config() -> Config {
    Config {
        ollama: OllamaConfig {
            model: "qwen3.5:2b".into(),
            endpoint: "http://127.0.0.1:11434".into(),
            prompt_override: None,
        },
        cache: CacheConfig { ttl_hours: 168 },
        helper: HelperConfig::default(),
    }
}

/// Load `Config` from the default XDG config path
/// (`{config_dir}/pkgbuild-scanner/config.toml`).
///
/// If the file does not exist or cannot be parsed, returns
/// [`default_config()`] instead.
pub fn load_config() -> Config {
    load_config_from(&config_path())
}

/// Alias for [`load_config()`] that always succeeds.
///
/// Semantically identical — `load_config` already degrades to defaults
/// on any error.  This alias exists to make the intent explicit at call
/// sites that truly cannot fail.
pub fn load_or_default() -> Config {
    load_config()
}

/// Determine the AUR helper backend to use.
///
/// Priority:
/// 1. Explicit config — if `config.helper.backend` is `Some(...)`, return it.
/// 2. Auto-detect — scan `$PATH` for `paru`; if found, use `Backend::Paru`.
/// 3. Fallback — `Backend::Yay`.
///
/// Auto-detect is silent (no stderr warnings) — falling back to `yay` is
/// normal when no other helper is found.
pub fn detect_backend(config: &Config) -> Backend {
    if let Some(ref backend) = config.helper.backend {
        return backend.clone();
    }

    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        let candidate = std::path::PathBuf::from(dir).join("paru");
        if candidate.exists() {
            return Backend::Paru;
        }
    }

    Backend::Yay
}

// ═══════════════════════════════════════════════════════════════════════════════
// Internal helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Resolve the OS-level config directory via XDG (`dirs::config_dir()`)
/// and append the application sub-path.
fn config_path() -> PathBuf {
    let base = dirs::config_dir().expect("XDG config directory must be available");
    base.join("pkgbuild-scanner").join("config.toml")
}

/// Internal loader that accepts an arbitrary path (used by public API and
/// tests alike).
///
/// 1. If `path` does not exist → return [`default_config()`].
/// 2. Read file → parse as TOML → merge parsed values on top of defaults
///    so that partial config files preserve defaults for missing fields.
/// 3. On any I/O or parse error → return [`default_config()`].
fn load_config_from(path: &Path) -> Config {
    if !path.exists() {
        return default_config();
    }

    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return default_config(),
    };

    // Parse the file as a generic TOML value so we can overlay it on
    // top of the serialised defaults (enables partial config support).
    let user: toml::Value = match toml::from_str(&contents) {
        Ok(v) => v,
        Err(_) => return default_config(),
    };

    // Serialise defaults to a Value, then deep-merge user on top.
    let defaults_val =
        toml::Value::try_from(default_config()).expect("default Config must serialise to TOML");
    let merged = deep_merge(defaults_val, user);

    // Deserialise the merged Value back into a Config.
    merged
        .try_into()
        .expect("merged TOML Value must deserialise back to Config")
}

/// Recursively merge `overlay` into `base`.
///
/// - When both values are tables, keys are merged individually (user keys
///   take precedence, but keys present only in base are preserved).
/// - For all other value types (strings, numbers, arrays, …) the overlay
///   wins unconditionally.
fn deep_merge(base: toml::Value, overlay: toml::Value) -> toml::Value {
    match (base, overlay) {
        (toml::Value::Table(mut base_t), toml::Value::Table(overlay_t)) => {
            for (k, v) in overlay_t {
                if let Some(existing) = base_t.remove(&k) {
                    base_t.insert(k, deep_merge(existing, v));
                } else {
                    base_t.insert(k, v);
                }
            }
            toml::Value::Table(base_t)
        }
        (_, overlay) => overlay,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests  (TDD: written before production code)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Default values must match the specification exactly.
    #[test]
    fn test_default_config() {
        let cfg = default_config();
        assert_eq!(cfg.ollama.model, "qwen3.5:2b");
        assert_eq!(cfg.ollama.endpoint, "http://127.0.0.1:11434");
        assert!(cfg.ollama.prompt_override.is_none());
        assert_eq!(cfg.cache.ttl_hours, 168);
    }

    /// A non-existent config file must return defaults — no panics.
    #[test]
    fn test_load_config_missing_file() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.toml");
        let cfg = load_config_from(&missing);
        assert_eq!(cfg.ollama.model, "qwen3.5:2b");
        assert_eq!(cfg.ollama.endpoint, "http://127.0.0.1:11434");
        assert!(cfg.ollama.prompt_override.is_none());
        assert_eq!(cfg.cache.ttl_hours, 168);
    }

    /// A complete TOML file must override every default.
    #[test]
    fn test_load_config_full() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
[ollama]
model = "llama3"
endpoint = "http://192.168.1.100:11434"
prompt_override = "custom prompt"

[cache]
ttl_hours = 24
"#,
        )
        .unwrap();

        let cfg = load_config_from(&path);
        assert_eq!(cfg.ollama.model, "llama3");
        assert_eq!(cfg.ollama.endpoint, "http://192.168.1.100:11434");
        assert_eq!(cfg.ollama.prompt_override.as_deref(), Some("custom prompt"));
        assert_eq!(cfg.cache.ttl_hours, 24);
    }

    /// A partial TOML file (only `model` set) must keep defaults for
    /// all other fields.
    #[test]
    fn test_load_config_partial() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
[ollama]
model = "custom-model"
"#,
        )
        .unwrap();

        let cfg = load_config_from(&path);
        // model should come from the file
        assert_eq!(cfg.ollama.model, "custom-model");
        // everything else should be defaults
        assert_eq!(cfg.ollama.endpoint, "http://127.0.0.1:11434");
        assert!(cfg.ollama.prompt_override.is_none());
        assert_eq!(cfg.cache.ttl_hours, 168);
    }

    // ── detect_backend ───────────────────────────────────────────────────────

    /// Explicit config with backend=Paru must return Paru (no PATH scan).
    #[test]
    fn test_detect_backend_config_explicit() {
        let cfg = Config {
            ollama: OllamaConfig {
                model: "test".into(),
                endpoint: "http://127.0.0.1:11434".into(),
                prompt_override: None,
            },
            cache: CacheConfig { ttl_hours: 168 },
            helper: HelperConfig {
                backend: Some(Backend::Paru),
            },
        };
        assert_eq!(detect_backend(&cfg), Backend::Paru);
    }

    /// When config has no explicit backend and `paru` is on PATH, auto-detect
    /// must return Paru.
    #[test]
    fn test_detect_backend_auto_paru_in_path() {
        let dir = tempdir().unwrap();
        let paru_path = dir.path().join("paru");
        std::fs::write(&paru_path, "#!/bin/sh\necho mock paru\n").unwrap();

        let old_path = std::env::var("PATH").unwrap_or_default();
        // SAFETY: Test-only PATH manipulation; single-threaded test context.
        unsafe { std::env::set_var("PATH", dir.path().to_str().unwrap()) };

        let cfg = Config {
            ollama: OllamaConfig {
                model: "test".into(),
                endpoint: "http://127.0.0.1:11434".into(),
                prompt_override: None,
            },
            cache: CacheConfig { ttl_hours: 168 },
            helper: HelperConfig { backend: None },
        };

        let result = detect_backend(&cfg);
        // SAFETY: Restoring original PATH; single-threaded test context.
        unsafe { std::env::set_var("PATH", &old_path) };

        assert_eq!(result, Backend::Paru);
    }

    /// When config has no explicit backend and `paru` is not on PATH,
    /// auto-detect must return Yay.
    #[test]
    fn test_detect_backend_auto_no_paru() {
        let old_path = std::env::var("PATH").unwrap_or_default();
        // SAFETY: Test-only PATH manipulation; single-threaded test context.
        unsafe { std::env::set_var("PATH", "") };

        let cfg = Config {
            ollama: OllamaConfig {
                model: "test".into(),
                endpoint: "http://127.0.0.1:11434".into(),
                prompt_override: None,
            },
            cache: CacheConfig { ttl_hours: 168 },
            helper: HelperConfig { backend: None },
        };

        let result = detect_backend(&cfg);
        // SAFETY: Restoring original PATH; single-threaded test context.
        unsafe { std::env::set_var("PATH", &old_path) };

        assert_eq!(result, Backend::Yay);
    }

    /// A config file with only `[helper]` set must preserve defaults for
    /// `[ollama]` and `[cache]` sections.
    #[test]
    fn test_helper_config_partial() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
[helper]
backend = "paru"
"#,
        )
        .unwrap();

        let cfg = load_config_from(&path);
        assert_eq!(cfg.helper.backend, Some(Backend::Paru));
        // Other sections should use defaults
        assert_eq!(cfg.ollama.model, "qwen3.5:2b");
        assert_eq!(cfg.ollama.endpoint, "http://127.0.0.1:11434");
        assert_eq!(cfg.cache.ttl_hours, 168);
    }
}
