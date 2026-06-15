/// Split "pkgver-pkgrel" on the LAST `-` to handle optional epoch prefix.
///
/// AUR RPC Version field format: `"pkgver-pkgrel"` with optional `"epoch:"` prefix.
/// Splitting on the LAST hyphen is essential — e.g. `"1:5.13-2"` must yield
/// pkgver=`"1:5.13"`, pkgrel=`"2"`.
pub fn parse_pkgver_pkgrel(version: &str) -> Option<(String, String)> {
    let idx = version.rfind('-')?;
    let pkgver = version[..idx].to_string();
    let pkgrel = version[idx + 1..].to_string();
    Some((pkgver, pkgrel))
}

/// Build a deterministic cache key from a package base and version string.
///
/// Format: `"{package_base}:{version}"`
pub fn make_cache_key(package_base: &str, version: &str) -> String {
    format!("{}:{}", package_base, version)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_pkgver_pkgrel ────────────────────────────────────────────────

    #[test]
    fn test_parse_simple_pkgver_pkgrel() {
        assert_eq!(parse_pkgver_pkgrel("14-2"), Some(("14".into(), "2".into())));
    }

    #[test]
    fn test_parse_with_epoch_prefix() {
        assert_eq!(
            parse_pkgver_pkgrel("1:5.13-2"),
            Some(("1:5.13".into(), "2".into()))
        );
    }

    #[test]
    fn test_parse_semver_like() {
        assert_eq!(
            parse_pkgver_pkgrel("5.4.2-1"),
            Some(("5.4.2".into(), "1".into()))
        );
    }

    #[test]
    fn test_parse_no_hyphen() {
        assert_eq!(parse_pkgver_pkgrel("noversion"), None);
    }

    #[test]
    fn test_parse_empty_string() {
        assert_eq!(parse_pkgver_pkgrel(""), None);
    }

    // ── make_cache_key ─────────────────────────────────────────────────────

    #[test]
    fn test_cache_key_deterministic() {
        assert_eq!(make_cache_key("cower", "14-2"), "cower:14-2");
    }

    #[test]
    fn test_cache_key_different_bases_different_keys() {
        assert_ne!(
            make_cache_key("a", "1-1"),
            make_cache_key("b", "1-1")
        );
    }

    #[test]
    fn test_cache_key_same_input_same_key() {
        assert_eq!(
            make_cache_key("a", "1-1"),
            make_cache_key("a", "1-1")
        );
    }
}
