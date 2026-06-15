/// Built-in security audit prompt for PKGBUILD analysis via Ollama.
///
/// Use `get_prompt(config)` to retrieve the prompt, respecting user overrides.
use crate::types::Config;

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

#[cfg(test)]
mod tests {
    use super::{Config, DEFAULT_PROMPT, get_prompt};
    use crate::types::OllamaConfig;

    #[test]
    fn test_get_prompt_returns_default_when_no_override() {
        let config = Config {
            ollama: OllamaConfig {
                model: String::new(),
                endpoint: String::new(),
                prompt_override: None,
            },
            cache: crate::types::CacheConfig { ttl_hours: 24 },
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
        };
        assert_eq!(get_prompt(&config), "custom prompt");
    }
}
