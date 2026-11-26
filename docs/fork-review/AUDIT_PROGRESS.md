# AUDIT_PROGRESS.md — fork-internal review documentation

> **Fork-internal document.** Not part of any upstream pull request.
> Tracks verification and remediation status of audit findings F-1 … F-36
> for the independent reviewer.

- Base commit (upstream/main): `54e8889` (v0.8.0)
- Work branch: `macos-dev` (fork `origin/macos-dev`)
- Toolchain: pinned to **stable** via `rust-toolchain.toml` (verified on 1.98.1, aarch64-apple-darwin)

## Legend

- **Status:** `open` | `fixed` | `rejected` | `not-reproducible` | `blocked` | `library-only`
- **Evidence:** runtime-reproduced / static-path / static-potential / suggestion
- **Reachability:** productive (GUI/CLI path) / library-only / unknown

## Findings ledger

| ID | Summary | Evidence | Reachability | Status | Commit |
|----|---------|----------|--------------|--------|--------|
| F-1 | `LocalFsBackend::write_bytes` truncates target non-atomically | static-path | productive (sync, remote copy, new-file) | open | — |
| F-2 | TransferEngine rename fallback deletes existing target | static-path | **library-only** (engine unused by GUI) | open | — |
| F-3 | curl downloads truncate target on failure | static-path | partially mitigated (bg worker stages `.part`); sync remote copy path remains | open | — |
| F-4 | S3 recursive delete removes only prefix marker | static-path | productive (S3 browse/delete) | open | — |
| F-5 | S3 list lacks pagination (>1000 keys) | static-path | productive | open | — |
| F-6 | WebDAV MOVE always `Overwrite: T` | static-path | productive | open | — |
| F-7 | macOS trash without Put-Back metadata | static-path | productive | open | — |
| F-8 | `copy_local_dir_preserving_bundle` removes target before rename | static-path | productive | open | — |
| F-9 | `load_default` swallows TOML parse errors (config reset risk) | static-path | productive | open | — |
| F-10 | Keychain write failures silently ignored | static-path | productive | open | — |
| F-11 | Hand-rolled archive JSON listing parser splits on `"],"` | static-path | productive (python3 archive path) | open | — |
| F-12 | python3 hard dependency (archive listing, SFTP PTY auth) | static-path | productive | open | — |
| F-13 | Engine `read_range` chunking O(n²) | static-path | library-only (see F-13b) | open | — |
| F-13b | `LocalFsBackend` lacks `read_range` override → inspector loads whole file | static-path | productive (UI inspector) | open | — |
| F-14 | Engine ignores pause/cancel handle | static-path | library-only | open | — |
| F-15 | Fake remote volume stats (500 GB/470 GB) | static-path | productive | open | — |
| F-16 | Preview placeholders (1920×1080, 120 s, page 1) | static-path | productive | open | — |
| F-17 | RwLock poisoning panics (no blanket `into_inner` allowed) | static-potential | productive | open | — |
| F-18 | Sandbox TOCTOU | static-potential | productive | open | — |
| F-19 | Edit-in-place last-writer-wins | static-path | productive | open | — |
| F-20 | Hand-rolled HMAC-SHA256 / `xml_unescape` order bug | static-path | productive | open | — |
| F-21 | Sync engine: whole-file RAM, silent `let _ = remove()`, no rollback | static-path | productive (Cmd+Shift+Y) | open | — |
| F-22 | 45 ms idle timer + polling (energy) | static-path | productive | open | — |
| F-23 | Drag-out downloads synchronously on UI thread; staging never purged | static-path | productive | open | — |
| F-24 | README claims stable 1.80+, but `is_multiple_of` needs 1.87 | static | n/a (docs) | open | — |
| F-25 | No `deny.toml`, no CI, no LICENSE file, license metadata inconsistent | static | n/a (infra) | open | — |
| F-26 | macOS file clipboard via osascript (no native flavors, single-file paste) | static-path | productive | open | — |
| F-27 | Hand-rolled ObjC drag: leaks, fragile transmutes | static-path | productive | open | — |
| F-28 | `smbclient` not present on macOS by default | static-path | productive | open | — |
| F-29 | Config in `~/.config` on macOS (do not migrate for cosmetics) | suggestion | — | rejected (keep, per brief) | — |
| F-30 | Quarantine handling (must NOT be removed) | n/a | — | rejected (no change, per brief) | — |
| F-31 | GCS/Azure routed through S3 SigV4 | static-potential | productive | open | — |
| F-32 | `ls -aln` parsing fragile | static-potential | productive | open | — |
| F-33 | SSH agent not used (password PTY path) | static-potential | productive | open | — |
| F-34 | No fsync before swap; no directory fsync after rename | static-path | productive | open | — |
| F-35 | Directory swap two-phase rename window; hidden `.bak` unrecoverable | static-path | productive | open | — |
| F-36 | Part-file permissions 0600; permission copy only partial | static-path | productive | open | — |

## Phase A — Baseline (2026-11-26)

- Git: `macos-dev` @ `54e8889`, clean tree; `origin` = fork (only `main` existed,
  `macos-dev` pushed with this work).
- Toolchain: default was nightly; project now pinned to **stable**
  (`rust-toolchain.toml`). Local environment note: Homebrew rustup wrapper
  breaks cargo proxy dispatch for subcommands (`cargo fmt`, `cargo clippy`
  via `~/.cargo/bin` fail; `rustup run stable cargo fmt` too). All commands
  are run with the toolchain bin directory prepended:
  `export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"`.
  This is an environment issue, not a repository defect.
- Baseline results (stable 1.98.1): see table below (populated from run).
- Advisories (`cargo audit`, 2026-11-26):
  - `pulldown-cmark 0.13.5` → patched `>=0.13.6` (transitive via slint 1.18.1)
  - `url 2.5.8` → patched `>=2.5.9` (direct dep)
  - warnings: `zvariant`/`zvariant_derive` unmaintained (RUSTSEC-2026-0370/0372,
    transitive via slint/zbus, Linux-only code path, no fixed release available),
    `rustix` unsound (patched 1.1.6), `async-executor` yanked.
- `cargo deny`: added `deny.toml` with permissive allow-list; no blanket
  advisory exceptions.
- CI: added `.github/workflows/ci.yml` (macos-14 arm64, ubuntu-24.04,
  windows-2022): fmt / check / clippy / test + cargo-deny job.
  Clippy is **not** yet run with `-D warnings` because the pre-existing
  baseline emits warnings (unused deps in `crates/vfs/Cargo.toml`, unused
  test variable, Slint `viewport-*` deprecations). Strict gate tracked as a
  follow-up cleanup; no new warnings may be added.
- License documentation (NOT changed, per brief): `Cargo.toml` declares
  `MIT OR Apache-2.0`; README says MIT; **no LICENSE file exists**. Upstream
  must decide; do not submit PRs touching licensing.

### Baseline command results

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo check --workspace --all-targets --locked` | PASS (56 pre-existing warning lines) |
| `cargo clippy --workspace --all-targets --locked` | PASS, no errors (56 pre-existing warning lines) |
| `cargo test --workspace --locked` | PASS — 66 tests (config 6, preview 2, sync 4, transfer 4, ui 41, vfs 4, vfs-remote 5) |

Pre-existing warning sources (baseline, not touched by functional work):
unused deps in `crates/vfs/Cargo.toml` (indexmap, log, serde_json, sha2, url),
unused workspace deps (smallvec, once_cell, memchr), unused `xdg_data` in
`crates/ui/src/gui/tests.rs`, Slint `viewport-width/height` deprecations in
`crates/ui/ui/modals.slint`.

## Upstream-able commit groups

(to be filled as work lands)
