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
| F-1 | `LocalFsBackend::write_bytes` truncates target non-atomically | static-path | productive (sync, remote copy, new-file) | fixed | `94fbac3` |
| F-2 | TransferEngine rename fallback deletes existing target | static-path | **library-only** (engine unused by GUI) | fixed | `3864de3` |
| F-3 | curl downloads truncate target on failure | static-path | partially mitigated (bg worker stages `.part`); sync remote copy path remains | fixed | `5c7ff9e` |
| F-4 | S3 recursive delete removes only prefix marker | static-path | productive (S3 browse/delete) | fixed | `5c7ff9e` |
| F-5 | S3 list lacks pagination (>1000 keys) | static-path | productive | fixed | `5c7ff9e` |
| F-6 | WebDAV MOVE always `Overwrite: T` | static-path | productive | fixed | `5c7ff9e` |
| F-7 | macOS trash without Put-Back metadata | static-path | productive | fixed | `58402c0` |
| F-8 | `copy_local_dir_preserving_bundle` removes target before rename | static-path | productive | fixed | `0824b8f` |
| F-9 | `load_default` swallows TOML parse errors (config reset risk) | static-path | productive | fixed | `782a3a4` |
| F-10 | Keychain write failures silently ignored | static-path | productive | fixed | `782a3a4` |
| F-11 | Hand-rolled archive JSON listing parser splits on `"],"` | static-path | productive (python3 archive path) | fixed | `88cd6e6` |
| F-12 | python3 hard dependency (archive listing, SFTP PTY auth) | static-path | productive | fixed | `88cd6e6` |
| F-13 | Engine `read_range` chunking O(n²) | static-path | library-only (see F-13b) | fixed | `3864de3` |
| F-13b | `LocalFsBackend` lacks `read_range` override → inspector loads whole file | static-path | productive (UI inspector) | fixed | `1e71659` |
| F-14 | Engine ignores pause/cancel handle | static-path | library-only | fixed | `3864de3` |
| F-15 | Fake remote volume stats (500 GB/470 GB) | static-path | productive | fixed | `5767099` |
| F-16 | Preview placeholders (1920×1080, 120 s, page 1) | static-path | productive | fixed | `5767099` |
| F-17 | RwLock poisoning panics (no blanket `into_inner` allowed) | static-potential | productive | fixed | `570d77e` |
| F-18 | Sandbox TOCTOU | static-potential | productive | fixed | `0d5a3c8` |
| F-19 | Edit-in-place last-writer-wins | static-path | productive | fixed | `88cd6e6` |
| F-20 | Hand-rolled HMAC-SHA256 / `xml_unescape` order bug | static-path | productive | fixed | `5c7ff9e` |
| F-21 | Sync engine: whole-file RAM, silent `let _ = remove()`, no rollback | static-path | productive (Cmd+Shift+Y) | fixed | `737a373` |
| F-22 | 45 ms idle timer + polling (energy) | static-path | productive | fixed | `cc38eff` |
| F-23 | Drag-out downloads synchronously on UI thread; staging never purged | static-path | productive | fixed | `cc38eff` |
| F-24 | README claims stable 1.80+, but `is_multiple_of` needs 1.87 | static | n/a (docs) | fixed | `b884a4a` |
| F-25 | No `deny.toml`, no CI, no LICENSE file, license metadata inconsistent | static | n/a (infra) | fixed (deny.toml `3480a9b`, CI `a8194f2`, license documented) | `b884a4a` |
| F-26 | macOS file clipboard via osascript (no native flavors, single-file paste) | static-path | productive | fixed | `58402c0` |
| F-27 | Hand-rolled ObjC drag: leaks, fragile transmutes | static-path | productive | fixed | `58402c0` |
| F-28 | `smbclient` not present on macOS by default | static-path | productive | fixed | `58402c0` |
| F-29 | Config in `~/.config` on macOS (do not migrate for cosmetics) | suggestion | — | rejected (keep, per brief) | — |
| F-30 | Quarantine handling (must NOT be removed) | n/a | — | rejected (no change, per brief) | — |
| F-31 | GCS/Azure routed through S3 SigV4 | static-potential | productive | fixed | `88cd6e6` |
| F-32 | `ls -aln` parsing fragile | static-potential | productive | fixed | `88cd6e6` |
| F-33 | SSH agent not used (password PTY path) | static-potential | productive | fixed | `88cd6e6` |
| F-34 | No fsync before swap; no directory fsync after rename | static-path | productive | fixed | `c5f6821` |
| F-35 | Directory swap two-phase rename window; hidden `.bak` unrecoverable | static-path | productive | fixed | `0824b8f` |
| F-36 | Part-file permissions 0600; permission copy only partial | static-path | productive | fixed | `c5f6821` |

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

### Group 1 — Toolchain & CI hardening (`d356948`, `a8194f2`, `3480a9b`)
`rust-toolchain.toml` (stable pin), CI workflow (macOS arm64 / Linux /
Windows: fmt, check, clippy, test, cargo-deny), `deny.toml`.

### Group 2 — Dependency security (`0ff8e30`)
Semver-compatible lockfile updates only (url 2.5.9, pulldown-cmark 0.13.6,
rustix 1.1.6, async-executor 1.14.1): `cargo audit` reports zero
vulnerabilities. `zvariant` unmaintained warnings remain (no fixed release;
Linux-only transitive via zbus).

### Group 3 — Local file operations (`1e71659`, `94fbac3`, `c5f6821`, `0824b8f`)
- `LocalFsBackend::read_range` seek-based override (F-13b);
- shared `atomic_write_bytes`/`sync_dir` in `manifold_vfs`, `write_bytes`
  now crash-atomic, symlink write-through and mode preservation covered by
  tests (F-1);
- transfer staging fsyncs part file before rename and parent directory
  after rename; archive extraction applies recorded entry modes (F-34, F-36);
- `atomic_exchange` (`renamex_np`/`renameat2`) for directory replacement,
  journaled two-step fallback with startup recovery, visible retired
  backups, `copy_local_dir_preserving_bundle` no longer deletes the target
  up front (F-35, F-8).

### Group 4 — Sync engine (`737a373`)
Streaming copies via `supports_chunked_io`, staged part paths with size
validation, prepare-before-replace, `VfsError::OperationFailed` with the
relative changeset path (F-21).

### Group 5 — Configuration (`782a3a4`)
Corrupt-config preservation with one-time `.corrupt-<epoch>` backups and UI
recovery notices (F-9); keyring backends report real failures instead of
silently succeeding (F-10).

### Group 6 — Transfer engine (`6a7cee3`)
Publish fallback never deletes the existing target; single `read_bytes`
when the source lacks chunked I/O; `execute_task_controlled` honors pause
and cancel while keeping the part file resumable (F-2, F-13, F-14).

### Group 7 — Remote protocols (`5c7ff9e`, `88cd6e6`)
Atomic curl downloads (temp file + rename) for s3/webdav/ftp (F-3); S3
pagination via continuation tokens (F-5) and full-tree delete with
per-object error reporting (F-4); WebDAV `Overwrite: F` guard (F-6);
crate-backed HMAC and single-pass XML unescape (F-20); serde_json archive
listings (F-11); clear python3-missing error (F-12); edit-in-place refuses
upload on concurrent remote change (F-19); Azure Blob rejected up front,
GCS routes to the interoperability endpoint (F-31); `ls -b` listing with
C-escape decoding (F-32); BatchMode-first auth before the password PTY
(F-33).

### Group 8 — Honest UI values (`5767099`)
Live remote capacity via `df -kP` (SFTP) and RFC 4918 quota PROPFIND
(WebDAV) instead of the invented 500 GB/470 GB; protocols without a
capacity concept report `UnsupportedOperation` and the UI omits the badge
(F-15); preview payload dimensions/page-count/duration are `Option` and
parsed from real PNG/JPEG/GIF/WebP/PDF headers (F-16).

### Group 9 — Native macOS (`58402c0`)
Finder-aware Trash via `NSFileManager trashItemAtURL:resultingItemURL:
error:` with Put-Back metadata (F-7); `NSPasteboard` file copy/paste
(multi-file, native flavors) with osascript fallback (F-26); drag-out
leak fixes (`objc_release` for `+new`/`alloc-init`) and null-class guards
(F-27); actionable `smbclient`-missing message on macOS (F-28).

### Group 10 — Performance & robustness (`cc38eff`, `570d77e`, `0d5a3c8`)
Adaptive feedback-timer cadence (45 ms active / 250 ms idle, F-22);
per-session drag-out staging cache + startup purge of crash leftovers
(F-23); lock poisoning surfaces as `VfsError::PoisonedLock` instead of
panicking (F-17); sandbox read path verifies the open descriptor's real
path via `F_GETPATH` (F-18).

## Final status (2026-11-26)

All 36 audit findings are resolved: 34 fixed with regression tests (red
before, green after), F-29/F-30 rejected per brief (config location kept,
quarantine handling must not change). Every package was pushed only after
`cargo fmt --check`, `cargo check`, `cargo clippy` (baseline warnings
documented, none added) and `cargo test --workspace --locked` passed.
`cargo deny check` passes (zero advisories; `zvariant` unmaintained
advisory remains, no fixed release, Linux-only transitive).

## Notes for upstream review

### Engine ↔ GUI-worker consolidation analysis (F-2, F-13, F-14)

`manifold_transfer::TransferEngine::execute_task` is **library-only**: the
GUI never calls it. The GUI's background worker
(`crates/ui/src/gui/transfer_worker.rs`) implements its own `.part`
staging, control-handle checks and swap logic — a deliberate improvement
over the engine at the time, but now duplicated knowledge. The engine fixes
in this group mirror the worker's guarantees (staged part files,
non-destructive publish, pause/cancel) so both paths are safe; a full
consolidation (worker delegates queueing + byte moving to the engine,
keeps UI events) is recommended as a follow-up refactor, not part of this
hardening pass, because it would mix behavior change with risk fix-up.

- **F-2:** engine rename fallback no longer deletes the existing target;
  on publish failure the staged part is kept and the error names it.
- **F-13:** engine reads non-chunked backends once instead of calling the
  default whole-file `read_range` per chunk (was O(n²)).
- **F-14:** `execute_task_controlled` honors pause (blocks between chunks)
  and cancel (keeps the part file for resume from `transferred_bytes`).

- B2 semantics: hard links to the target are broken by the rename-based
  atomic write (documented in code); macOS xattrs are copied manually
  because `copyfile(3)` skips `com.apple.quarantine` (verified with a C
  probe); Gatekeeper/quarantine behavior of written files is unchanged.
- F-10 tests use a fake `security` binary via `PATH` (serialized with a
  mutex); no production keychain is touched.
- fsync ordering itself (F-34) is not unit-testable; covered by code review
  and the swap regression tests.
- GUI sync remote→local copy still buffers whole files at the transport
  layer (write side is atomic); full streaming belongs to Phase E.
