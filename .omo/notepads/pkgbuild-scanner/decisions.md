# Decisions — pkgbuild-scanner

## Architecture
- Pre-process wrapper (Option A) — simplest, handles 90%+ cases
- Name collisions: scan AUR PKGBUILD anyway (harmless)
- Single crate, no workspace
