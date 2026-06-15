//! Command router: classifies CLI args into Install / Update / Passthrough.
//!
//! The router inspects the first argument to decide whether the user is:
//! - installing AUR packages (scan PKGBUILD before delegating)
//! - performing a full system upgrade (scan all cached packages)
//! - doing something else (passthrough to real yay unchanged)

/// The three routing outcomes.
#[derive(Debug, PartialEq, Clone)]
pub enum Command {
    /// Install one or more AUR packages.  The inner `Vec` contains only bare
    /// package names (no flags).
    Install(Vec<String>),
    /// Full system upgrade (`-Syu` / `-Syua`) — no individual package names.
    Update,
    /// Everything else.  Forward the original `args` verbatim to real `yay`.
    Passthrough(Vec<String>),
}

/// Classify a `yay`-style argument list.
///
/// # Rules (applied in order)
/// 1. First arg does **not** start with `"-S"` → `Passthrough`.
/// 2. First arg starts with `"-S"` **but** contains non-`y`/`u` letters after
///    the `S` (e.g. `"-Ss"`, `"-Si"`) → `Passthrough` (search/info/list are
///    not install operations).
/// 3. First arg is a pure install/update flag (`-S`, `-Sy`, `-Su`, `-Syu`, …)
///    **and** at least one bare package name exists in the remaining args
///    → `Install` with those names.
/// 4. First arg is a pure update flag (contains `"yu"` or `"ua"`) **and**
///    no package names → `Update`.
/// 5. Otherwise → `Passthrough`.
pub fn route(args: &[String]) -> Command {
    if args.is_empty() {
        return Command::Passthrough(args.to_vec());
    }

    let first = &args[0];
    if !first.starts_with("-S") {
        return Command::Passthrough(args.to_vec());
    }

    let suffix = &first[2..];

    let is_non_install = |c: char| matches!(c, 's' | 'i' | 'l' | 'g');
    if suffix.chars().any(is_non_install) {
        return Command::Passthrough(args.to_vec());
    }

    let names = extract_package_names(args);

    if !names.is_empty() {
        return Command::Install(names);
    }

    if suffix.contains("yu") || suffix.contains("ua") {
        return Command::Update;
    }

    Command::Passthrough(args.to_vec())
}

/// Extract bare package names from a `yay`-style argument list.
///
/// Skips the **first** argument (which is expected to be the `-S*` flag) and
/// collects every subsequent argument that does **not** start with `'-'`.
/// This correctly handles interspersed flags (e.g. `--noconfirm`, `--needed`).
///
/// # Examples
/// ```
/// let args = vec!["-S".into(), "--noconfirm".into(), "cower".into()];
/// let names = extract_package_names(&args);
/// assert_eq!(names, vec!["cower"]);
/// ```
pub fn extract_package_names(args: &[String]) -> Vec<String> {
    args.iter()
        .skip(1) // skip the flag itself
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: turn string slices into Vec<String>
    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // ── route() tests ──────────────────────────────────────────────────────

    #[test]
    fn route_install_single_package() {
        let result = route(&a(&["-S", "cower"]));
        assert_eq!(result, Command::Install(vec!["cower".into()]));
    }

    #[test]
    fn route_install_multi_package() {
        let result = route(&a(&["-S", "cower", "yay"]));
        assert_eq!(result, Command::Install(vec!["cower".into(), "yay".into()]));
    }

    #[test]
    fn route_install_with_interspersed_flags() {
        let result = route(&a(&["-S", "--noconfirm", "cower", "--needed", "yay"]));
        assert_eq!(result, Command::Install(vec!["cower".into(), "yay".into()]));
    }

    #[test]
    fn route_update_syu() {
        let result = route(&a(&["-Syu"]));
        assert_eq!(result, Command::Update);
    }

    #[test]
    fn route_update_syua() {
        let result = route(&a(&["-Syua"]));
        assert_eq!(result, Command::Update);
    }

    #[test]
    fn route_passthrough_remove() {
        let result = route(&a(&["-R", "cower"]));
        assert_eq!(result, Command::Passthrough(a(&["-R", "cower"])));
    }

    #[test]
    fn route_passthrough_search() {
        let result = route(&a(&["-Ss", "cower"]));
        assert_eq!(result, Command::Passthrough(a(&["-Ss", "cower"])));
    }

    #[test]
    fn route_passthrough_query() {
        let result = route(&a(&["-Q", "cower"]));
        assert_eq!(result, Command::Passthrough(a(&["-Q", "cower"])));
    }

    #[test]
    fn route_passthrough_help() {
        let result = route(&a(&["--help"]));
        assert_eq!(result, Command::Passthrough(a(&["--help"])));
    }

    #[test]
    fn route_passthrough_empty() {
        let result = route(&[]);
        assert_eq!(result, Command::Passthrough(vec![]));
    }

    #[test]
    fn route_passthrough_s_flag_no_packages_no_update() {
        // "-S" alone with no packages and no "yu"/"ua" → passthrough
        let result = route(&a(&["-S"]));
        assert_eq!(result, Command::Passthrough(a(&["-S"])));
    }

    #[test]
    fn route_install_overrides_update_signal() {
        // "-Syu" with explicit package names → Install, not Update
        let result = route(&a(&["-Syu", "cower"]));
        assert_eq!(result, Command::Install(vec!["cower".into()]));
    }

    // ── extract_package_names() tests ──────────────────────────────────────

    #[test]
    fn extract_names_basic() {
        let args = a(&["-S", "cower", "yay"]);
        assert_eq!(extract_package_names(&args), vec!["cower", "yay"]);
    }

    #[test]
    fn extract_names_with_interspersed_flags() {
        let args = a(&["-S", "--noconfirm", "pkg1", "--needed", "pkg2"]);
        assert_eq!(extract_package_names(&args), vec!["pkg1", "pkg2"]);
    }

    #[test]
    fn extract_names_no_packages() {
        let args = a(&["-Syu"]);
        assert!(extract_package_names(&args).is_empty());
    }

    #[test]
    fn extract_names_flag_not_s() {
        // extract_package_names is a utility — it always skips args[0].
        // The caller (route) is responsible for only calling it on -S args.
        let args = a(&["-R", "cower"]);
        assert_eq!(extract_package_names(&args), vec!["cower"]);
    }
}
