/// Built-in security audit prompt for PKGBUILD analysis via Ollama.
///
/// Use `get_prompt(config)` to retrieve the prompt, respecting user overrides.
use crate::types::{Backend, Config};

/// Default comprehensive security audit prompt for PKGBUILD analysis.
///
/// Instructs the Ollama model to analyse a PKGBUILD for malware indicators
/// and return either `VERDICT: CLEAN` or `VERDICT: SUSPICIOUS` followed by
/// per-finding lines.
pub const DEFAULT_PROMPT: &str = concat!(
    "You are an AUR PKGBUILD security auditor. PKGBUILDs are bash scripts ",
    "that define how to build and install packages from the Arch User Repository.\n\n",
    "Analyze the PKGBUILD for these malware indicators:\n",
    "- Malicious URLs or tampered source downloads\n",
    "- Obfuscated commands using eval, base64, rot13, hex, or other encoding\n",
    "- sudo abuse or privilege escalation attempts\n",
    "- Destructive operations like rm -rf on system paths (/, /etc, /usr, /boot)\n",
    "- Data exfiltration via curl, wget, or other network calls to unknown hosts\n",
    "- Hidden network connections or phone-home behavior\n",
    "- Persistence mechanisms (systemd units, cron jobs, bashrc/profile modification)\n",
    "- Reverse shells or unauthorized remote access payloads\n",
    "- Pipe-to-shell patterns (curl | bash, wget | sh)\n",
    "- Backdoor installation or credential theft\n\n",
    "CRITICAL: Avoid false positives. Network calls to github.com, gitlab.com, ",
    "archlinux.org, or sourceforge.net are normal. Only flag truly suspicious behavior.\n\n",
    "Begin your response with VERDICT: CLEAN or VERDICT: SUSPICIOUS at the very start. ",
    "If SUSPICIOUS, list each finding on a new line using FINDING: <description>. ",
    "Be specific and reference the exact code.",
);

/// Diff-specialised security audit prompt for PKGBUILD analysis via paru.
///
/// Paru provides PKGBUILD content as a git diff rather than the full file,
/// so this prompt teaches the model to focus on `+` (new) lines while still
/// using the standard VERDICT / FINDING output format.
pub const PARU_DIFF_PROMPT: &str = concat!(
    "You are an AUR PKGBUILD security auditor. You are reviewing a GIT DIFF of PKGBUILD changes.\n\n",
    "The diff is in unified git diff format:\n",
    "- Lines starting with '+' are NEW ADDITIONS (changes, new code)\n",
    "- Lines starting with '-' are REMOVALS (old code being deleted)\n",
    "- Lines starting with '@@' are hunk headers showing line numbers\n",
    "- Other lines are context (unchanged code)\n\n",
    "FOCUS ONLY on the '+' lines — these represent what was NEWLY ADDED or MODIFIED.\n",
    "Ignore '-' lines (removals) and context lines unless they provide context.\n\n",
    "Analyze the diff for these malware indicators:\n",
    "- Malicious URLs or tampered source downloads\n",
    "- Obfuscated commands using eval, base64, rot13, hex, or other encoding\n",
    "- sudo abuse or privilege escalation attempts\n",
    "- Destructive operations like rm -rf on system paths (/, /etc, /usr, /boot)\n",
    "- Data exfiltration via curl, wget, or other network calls to unknown hosts\n",
    "- Hidden network connections or phone-home behavior\n",
    "- Persistence mechanisms (systemd units, cron jobs, bashrc/profile modification)\n",
    "- Reverse shells or unauthorized remote access payloads\n",
    "- Pipe-to-shell patterns (curl | bash, wget | sh)\n",
    "- Backdoor installation or credential theft\n\n",
    "CRITICAL: Avoid false positives. Network calls to github.com, gitlab.com, ",
    "archlinux.org, or sourceforge.net are normal. Only flag truly suspicious behavior.\n\n",
    "Note: For first-time packages, the entire PKGBUILD may appear as '+' additions.\n",
    "In that case, review as if it were a full PKGBUILD.\n\n",
    "Begin your response with VERDICT: CLEAN or VERDICT: SUSPICIOUS at the very start.\n",
    "If SUSPICIOUS, list each finding on a new line using FINDING: <description>.\n",
    "Be specific and reference the exact code that was added.",
);

/// Returns the prompt to use, respecting the user's config override.
///
/// If `config.ollama.prompt_override` is `Some`, returns that value.
/// Otherwise returns [`DEFAULT_PROMPT`].
pub fn get_prompt(config: &Config) -> &str {
    config
        .ollama
        .prompt_override
        .as_deref()
        .unwrap_or(DEFAULT_PROMPT)
}

/// Returns the prompt to use for a given AUR helper backend.
///
/// Override logic (applied first, highest priority):
/// 1. If `config.ollama.prompt_override` is set, return it regardless of backend.
/// 2. If `backend` is [`Backend::Paru`], return [`PARU_DIFF_PROMPT`].
/// 3. For all other backends (including [`Backend::Yay`]), return [`DEFAULT_PROMPT`].
pub fn get_prompt_for_backend<'a>(config: &'a Config, backend: &Backend) -> &'a str {
    if let Some(ref override_prompt) = config.ollama.prompt_override {
        return override_prompt;
    }
    match backend {
        Backend::Paru => PARU_DIFF_PROMPT,
        Backend::Yay => DEFAULT_PROMPT,
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, DEFAULT_PROMPT, PARU_DIFF_PROMPT, get_prompt, get_prompt_for_backend};
    use crate::types::{Backend, OllamaConfig};

    #[test]
    fn test_get_prompt_returns_default_when_no_override() {
        let config = Config {
            ollama: OllamaConfig {
                model: String::new(),
                endpoint: String::new(),
                prompt_override: None,
            },
            cache: crate::types::CacheConfig { ttl_hours: 24 },
            helper: Default::default(),
        };
        assert_eq!(get_prompt(&config), DEFAULT_PROMPT);
    }

    #[test]
    fn test_get_prompt_returns_override_when_set() {
        let config = Config {
            ollama: OllamaConfig {
                model: String::new(),
                endpoint: String::new(),
                prompt_override: Some("custom prompt".to_string()),
            },
            cache: crate::types::CacheConfig { ttl_hours: 24 },
            helper: Default::default(),
        };
        assert_eq!(get_prompt(&config), "custom prompt");
    }

    #[test]
    fn test_get_prompt_for_backend_paru() {
        let config = Config {
            ollama: OllamaConfig {
                model: String::new(),
                endpoint: String::new(),
                prompt_override: None,
            },
            cache: crate::types::CacheConfig { ttl_hours: 24 },
            helper: Default::default(),
        };
        assert_eq!(
            get_prompt_for_backend(&config, &Backend::Paru),
            PARU_DIFF_PROMPT,
        );
    }

    #[test]
    fn test_get_prompt_for_backend_yay() {
        let config = Config {
            ollama: OllamaConfig {
                model: String::new(),
                endpoint: String::new(),
                prompt_override: None,
            },
            cache: crate::types::CacheConfig { ttl_hours: 24 },
            helper: Default::default(),
        };
        assert_eq!(
            get_prompt_for_backend(&config, &Backend::Yay),
            DEFAULT_PROMPT,
        );
    }

    #[test]
    fn test_get_prompt_for_backend_override() {
        let config = Config {
            ollama: OllamaConfig {
                model: String::new(),
                endpoint: String::new(),
                prompt_override: Some("override wins".to_string()),
            },
            cache: crate::types::CacheConfig { ttl_hours: 24 },
            helper: Default::default(),
        };
        // Override always wins, even for Paru backend
        assert_eq!(
            get_prompt_for_backend(&config, &Backend::Paru),
            "override wins",
        );
    }
}
