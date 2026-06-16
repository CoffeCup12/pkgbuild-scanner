# pkgbuild-scanner

AI-powered AUR PKGBUILD security scanner.

pkgbuild-scanner wraps `yay` to intercept AUR package installs, scans each
PKGBUILD with a local Ollama LLM for malware indicators, and prompts you
before allowing installation. Clean packages install normally. Suspicious
ones get flagged with specific findings for you to review.

## Why LLM-based?

Existing AUR scanners (aur-guard, ks-aur-scanner, traur) use hand-written
rule sets or pattern matchers. These catch known bad patterns but miss
novel or obfuscated malware. pkgbuild-scanner sends the full PKGBUILD to
an Ollama-hosted LLM, which can reason about intent and recognize
evasive techniques that no static rule would match.

## Prerequisites

- Rust 1.85 or later
- [Ollama](https://ollama.com) running locally (default endpoint:
  `http://127.0.0.1:11434`)
- An Ollama model pulled (default: `qwen3.5:2b`)
- `yay` installed on the system

## Installation

### Method 1: cargo install

```bash
cargo install --git https://github.com/shao/pkgbuild-scanner
```

### Method 2: build from source

```bash
git clone https://github.com/shao/pkgbuild-scanner
cd pkgbuild-scanner
cargo build --release
sudo cp target/release/pkgbuild-scanner /usr/local/bin/
```

### Method 3: AUR package (future)

An AUR package is planned. Track the repository for updates.

## Quick start

1. Make sure Ollama has the model you want to use:

   ```bash
   ollama pull qwen3.5:2b
   ```

2. Alias `yay` to pkgbuild-scanner in your shell rc:

   ```bash
   echo 'alias yay=pkgbuild-scanner' >> ~/.bashrc
   source ~/.bashrc
   ```

3. Install an AUR package as usual:

   ```bash
   yay -S some-aur-package
   ```

   pkgbuild-scanner intercepts the command, scans the PKGBUILD, and
   prompts you if anything suspicious is found. Approved packages are
   forwarded to the real `yay` for installation.

## Configuration

Create a TOML config file at `~/.config/pkgbuild-scanner/config.toml`.
All fields shown below are the defaults; you only need to specify what
you want to override.

```toml
# ~/.config/pkgbuild-scanner/config.toml

[ollama]
model = "qwen3.5:2b"              # any Ollama model you have pulled
endpoint = "http://127.0.0.1:11434"  # Ollama server URL

# Optional: replace the built-in security prompt entirely.
# prompt_override = "Your custom audit instructions here..."

[cache]
ttl_hours = 168  # re-scan cached packages after 1 week (168 hours)
```

A config file is not required. If the file does not exist, all defaults
apply. If the file is partial, missing fields use defaults.

## How it works

1. You run `yay -S some-package`.
2. pkgbuild-scanner parses the command and extracts package names.
3. For each package, it queries the AUR RPC API for metadata and the
   PackageBase identifier.
4. It checks `~/.cache/pkgbuild-scanner/`. If a scan exists for the same
   PackageBase and version, it is reused (no re-download or re-scan).
5. On a cache miss, it downloads the PKGBUILD tarball from the AUR and
   extracts it as plain text. The PKGBUILD is never executed.
6. The PKGBUILD text is sent to Ollama along with a security audit
   prompt. The LLM returns a verdict: `CLEAN` or `SUSPICIOUS` with
   per-finding details.
7. Results are cached by PackageBase + version for future runs.
8. For each package you see a summary. Suspicious results show an
   interactive prompt: approve or reject.
9. Approved packages are forwarded to the real `yay` for installation.
   Rejected packages are skipped.

## Cache

Scan results are stored in `~/.cache/pkgbuild-scanner/`, one JSON file
per PackageBase. The cache entry includes the package version, the scan
result, and a timestamp. When the same PackageBase is encountered again
with the same version, the cached result is used directly.

The TTL (`cache.ttl_hours`, default 168) controls how long a cached
result is considered valid. After the TTL expires, the package is
re-scanned on the next request.

## Security prompt

The built-in prompt instructs the LLM to check for these 10 malware
indicator categories:

- Malicious URLs or tampered source downloads
- Obfuscated commands (eval, base64, rot13, hex encoding)
- sudo abuse or privilege escalation
- Destructive operations (rm -rf on /, /etc, /usr, /boot)
- Data exfiltration via curl, wget, or other network calls
- Hidden network connections or phone-home behavior
- Persistence mechanisms (systemd units, cron, bashrc, profile)
- Reverse shells or unauthorized remote access
- Pipe-to-shell patterns (curl | bash, wget | sh)
- Backdoor installation or credential theft

You can replace the prompt entirely via the `prompt_override` config
option to use different categories or a stricter tone.

## Limitations

- **Name collision:** If a package exists in both the AUR and the
  official repositories, pkgbuild-scanner will scan it. It does not
  distinguish between the two sources.
- **Ollama dependency:** The tool requires Ollama to be running and the
  configured model to be pulled. No Ollama means no scanning.
- **First-scan latency:** On consumer hardware the first scan of a
  package takes roughly 30 seconds (download + LLM inference).
  Subsequent scans of the same version are instant (cache hit).

## License

MIT

## Contributing

Contributions, issues, and feature requests are welcome.

## Acknowledgments

Inspired by existing AUR security tooling:

- [aur-guard](https://github.com/faeraa/aur-guard) -- Rust, 38 rules,
  pre-build shim + pacman hook
- [ks-aur-scanner](https://github.com/ks2041/ks-aur-scanner) -- Rust,
  50+ patterns, SARIF output
- [traur](https://github.com/pjones/plasma-manager) -- Rust, 12 feature
  dimensions, trust scoring, ALPM hook
- [lime](https://github.com/Calandracas606/lime) -- Python, wraps
  paru/yay, Bubblewrap sandbox

Thanks to the Metis research team for their work on LLM-based malware
detection in package ecosystems.
