# YARA Convertor

A desktop app that checks whether existing **YARA** rules are compatible with
**YARA-X**, for anyone migrating a ruleset from the classic YARA engine to
YARA-X.

It is the friendly, foolproof version of running the compiler by hand
(`yr compile --relaxed-re-syntax`): no downloads, no flags to get wrong, per-rule
verdicts, and a summary across a whole ruleset.

## How it works

- **Tauri** app: web UI (HTML/TS/CSS) + a **Rust** core.
- The Rust core links the real **`yara-x` crate directly** (currently v1.20.0) —
  no shelling out to a `yr` binary, no version drift. Whatever the linked
  compiler says *is* the verdict.
- Frontend calls the `check_rules` command with the pasted text / loaded files
  and the compile options; Rust runs the YARA-X compiler and returns a
  structured report (errors + warnings, each with code, title, line, and the
  full CLI-style rendered message).

## Download & install (test builds)

Installers for macOS, Windows and Linux are published on the
[Releases page](https://github.com/zeekallab/yara-convertor/releases). Pushing a
`v*` tag builds them via GitHub Actions (`.github/workflows/release.yml`).

- **macOS** — download the `.dmg`, drag the app to Applications. It's unsigned,
  so the first launch is blocked: right‑click the app → **Open** → **Open**, or
  run `xattr -dr com.apple.quarantine "/Applications/YARA Convertor.app"`.
- **Windows** — download the `.msi` (or `-setup.exe`) and run it. SmartScreen
  may warn on an unsigned build: **More info → Run anyway**.
- **Linux** — download the `.AppImage` (`chmod +x` it, then run), the `.deb`
  (`sudo dpkg -i` / `sudo apt install ./<file>.deb`), or the `.rpm`
  (`sudo rpm -i <file>.rpm` / `sudo dnf install ./<file>.rpm`).

## Build from source

Requires [Rust](https://rustup.rs) and [Node.js](https://nodejs.org). On Linux
you also need the usual Tauri system libraries (WebKitGTK, etc.) — see the
[Tauri prerequisites](https://tauri.app/start/prerequisites/).

```bash
npm install
npm run tauri dev      # run the app locally
npm run tauri build    # produce an installer for your OS
```
