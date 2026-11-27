# INDEPENDENT_REMEDIATION.md — Round 2 remediation of the independent review (R01 … R17)

> **Fork-internal document.** Not part of any upstream pull request.
> Companion to `AUDIT_PROGRESS.md` (Round 1, F-1 … F-36). This document is
> the authoritative status record after the independent review of Round 1;
> where the two disagree, this one wins.

- Work branch: `macos-dev` (fork `origin/macos-dev`), all packages pushed.
- Round 2 commit chain: `d0dbc39 … f3edac1` (21 commits).
- Every package was gated with: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace --locked` (15 suites), plus cross-lint for
  `x86_64-pc-windows-msvc`; regression tests were **red-verified** (the
  old behavior is patched back in, the test is shown to fail, the fix is
  restored, the test is shown to pass).

## Status taxonomy (binding)

| Status | Meaning |
|--------|---------|
| `FIXED_TESTED` | Defect fixed; regression test red on old code (verified), green on new code |
| `FIXED_STATIC` | Fix verified by static reasoning / build gates only, no runtime test possible |
| `FIXED_PLATFORM_VALIDATED` | Additionally validated on the target platform hardware |
| `PARTIAL` | Approved scope delivered, but the underlying goal (e.g. consolidation) is not reached |
| `BLOCKED` | Verification or completion blocked by an external factor (documented) |

## Package status overview

| R-Pkg | Subject | Status | Commit(s) |
|-------|---------|--------|-----------|
| R01 | Sync must never destroy the destination before publishing | FIXED_TESTED | `f12e390` |
| R02 | `atomic_write_bytes` must honour the umask | FIXED_TESTED | `201df09` |
| R03 | Swap journals: private dir + contract-validated recovery | FIXED_TESTED | `919d5d9` |
| R04 | `sync_dir` errors propagated; metadata fsync before rename | FIXED_TESTED | `9cc3897` |
| R05 | Streaming only when both ends support chunked I/O; size-0 split | FIXED_TESTED | `fec8dbd` |
| R06 | Write-back publish refused on non-atomic backends | FIXED_TESTED | `34b30ac` |
| R07 | macOS trash never degrades to the manual `~/.Trash` move | FIXED_TESTED | `c812e12` |
| R08 | Hand-rolled ObjC FFI: autorelease pools, BOOL, NSError | FIXED_TESTED | `d715a2d` |
| R09 | Edit-in-place data survives restarts (manifest) | FIXED_TESTED | `c3c16a9` |
| R10 | Sandbox TOCTOU closed with pinned parent fds | FIXED_TESTED | `60a040b` |
| R11 | F-19 conflict check never skipped on failed verification | FIXED_TESTED | `7efd086` |
| R12 | python3 dependency cut via OpenSSH askpass | FIXED_TESTED | `bf807df` |
| R13 | Staged-edit network I/O off the timer thread | FIXED_TESTED | `f3edac1` |
| R14 | CI pipeline repaired; MSRV corrected to 1.92 | FIXED_STATIC · CI run BLOCKED | `ca43933` |
| R15 | Zero-warning baseline + `-D warnings` gate | FIXED_TESTED | `4bee717` |
| R16 | TransferEngine ↔ GUI-worker consolidation | PARTIAL (plan documented) | `f486311` `c90afd9` |
| R17 | zvariant advisory verification | FIXED_STATIC | `d6edefa` |

Follow-up repairs inside the R14/R15 verification chain: `7639289`
(Windows `FlushFileBuffers` needs the write handle), `a1457f3` (strict
clippy green for Linux and Windows cross-targets).

## What each package changed

### R01 — Sync execution outcome (`f12e390`)
The Round 1 claim that sync "never destroys the destination" was not
tenable: the destination could be removed before the new content was
published. Introduced `SyncExecutionOutcome` so publish failures are
reported with the state the filesystem is left in; 6 regression tests.

### R02 — umask-honouring atomic writes (`201df09`)
`atomic_write_bytes` hardcoded `mode(0o666)` (relying on the kernel's
umask application only for newly created temp files) and did not
preserve an existing target's mode on overwrite. Fixed; tested with
child processes under different umasks (the process umask cannot be set
in-process without racing other tests).

### R03 — Swap journals in a private directory (`919d5d9`)
Swap journals were written to a world-accessible location and recovery
read any file matching the pattern. Journals now live in
`secure_runtime_subdir("swap-journals")` (0700); recovery only reads
that directory and validates the journal contract before acting. 4 tests.

### R04 — Durability errors surfaced (`9cc3897`)
`sync_dir` swallowed `fsync` failures. It now returns
`io::Result<()>`; content and metadata are fsynced before the rename
and the errors are propagated. 2 tests.

### R05 — Capability-checked streaming (`fec8dbd`)
Chunked streaming was chosen from the source capability alone, and a
size of 0 was conflated with "unknown size". Streaming now requires
`supports_chunked_io()` on **both** source and destination; the
empty-file case is separated from the unknown-size case. 3 tests.

### R06 — Atomic-replace capability (`34b30ac`)
The transfer engine's write-back publish fallback could silently
non-atomically replace an existing target on backends without rename
support. Added `supports_atomic_replace()`; the engine refuses the
fallback when it is false. 1 test.

### R07 — Trash without unsafe fallback (`c812e12`)
On macOS a failed native trash degraded to a manual move to `~/.Trash`,
which silently loses Finder Put-Back metadata. The manual fallback was
removed; the failure is surfaced as "macOS trash failed (…); refused
the less-safe manual move to ~/.Trash". Refusal-message test.

### R08 — ObjC FFI hardening (`d715a2d`)
Three concrete defects in the hand-rolled `objc_msgSend` layer (the FFI
itself is kept per the Round-1 decision to prefer native macOS APIs):
every synchronous entry point now runs inside an explicit
`@autoreleasepool` (worker threads have no run-loop pool, so
autoreleased `NSString`/`NSURL`/`NSArray` objects accumulated for the
process lifetime); `BOOL` is modelled as `c_schar` (x86_64 semantics —
reading it as Rust `bool` is UB for non-0/1 values); `trashItemAtURL`
captures the real `NSError` and surfaces its `localizedDescription`.
Red-verified test for the NSError propagation. The pool/BOOL changes
are correctness changes verified statically and by the existing runtime
tests; a leak regression test for the pool itself is not possible
without an allocator probe.

### R09 — Staging survives restarts (`c3c16a9`)
The shutdown cleanup deleted the whole `staging` runtime directory —
destroying user edit-in-place copies that had not been uploaded — and
the in-memory staged list was never persisted. Added a persisted
`manifest.json` (atomic write, poisoned-lock-safe), `recover_from_disk()`
and `purge_orphaned_files()` at startup, and removed `staging` from the
disposable cleanup list (now the testable `disposable_runtime_subdirs()`).
4 tests, red-verified against the non-persisting behavior.

### R10 — TOCTOU closure (`60a040b`)
The sandbox resolved paths and then operated on path names (race window
between check and action). Now every sandbox mutation operates through
pinned parent file descriptors (`pinned_parent()` via fd + `F_GETPATH`)
with `renameat`/`unlinkat`/`mkdirat`. 3 race tests (deterministic via a
test-only `TEST_RACE_HOOK`) red-verified, plus a normal-operations test.
Validated on macOS (the `F_GETPATH` semantics are macOS-specific); the
Linux build is green via cross-check but its CI run is blocked (below).

### R11 — Conflict check never skipped (`7efd086`)
When the pre-upload verification read failed (network drop), the F-19
remote-change check was skipped and the upload proceeded — destroying a
concurrent edit exactly when the connection was flaky. The check can no
longer be skipped: a failed verification aborts the upload and keeps the
local edit staged. Mock test with an unverifiable remote backend.

### R12 — OpenSSH askpass replaces the python3 PTY (`bf807df`)
Round 1 only made the missing-python3 error actionable. Password auth
now tries `SSH_ASKPASS` + `SSH_ASKPASS_REQUIRE=force` (OpenSSH ≥ 8.4)
before the python3 PTY: the secret travels through a 0600 file in a
private 0700 directory (never argv), helper and secret are removed by an
RAII guard, exit 255 still falls through to the PTY. Unix-only (the
helper is a POSIX shell script); Windows keeps the previous chain.
3 fake-ssh harness tests, 2 of them red-verified. **Not** validated
against a live SSH server — production network use in tests is out of
scope by the ground rules.

### R13 — No network I/O in the timer tick (`f3edac1`)
The F-22 adaptive timer fixed the wake cadence, but the tick itself ran
the staged-edit upload (remote verification read + upload) synchronously
on the GUI thread, dropped its errors via `if let Ok(..)`, and read
`/proc/mounts` on every tick. Uploads now run on a per-session
background worker with a result channel; errors surface as toast + log;
mount detection is throttled to every 8th tick. The 250 ms idle
heartbeat deliberately stays (it is the single drain point for all
background channels; stopping it would need a restart hook at every
activity entry point — documented in the callback). 2 red-verified
tests.

### R14 — CI repaired, MSRV corrected (`ca43933`)
The Round 1 CI was not runnable as written: `macos-14` runners were
retired 2026-11-02, the fake-curl harness used POSIX permissions on
Windows, xattr tests ran where they cannot pass, and the claimed MSRV
1.87 was wrong (Slint 1.18 requires ≥ 1.92). Fixed: `macos-15`,
`rust-toolchain.toml` pins 1.98.1 concretely, workspace `rust-version =
"1.92"`, an MSRV job on 1.92.0, cfg-gated test harnesses, README
corrected. **Status FIXED_STATIC + BLOCKED:** the workflow itself cannot
be executed — GitHub Actions is disabled on the fork (see Limitations).

### R15 — Zero-warning baseline (`4bee717`)
The Round 1 "no new warnings" claim rested on ~30 existing warnings.
Reached a zero-warning tree (Slint `viewport-*` → `content-*` renames,
removed 26 unused dependencies, lockfile −36 packages) and gated it with
`-D warnings` in CI and in every local gate since.

### R16 — TransferEngine ↔ GUI worker (PARTIAL, `f486311` `c90afd9`)
The approved scope allowed either a consolidation with a testable
equivalence proof **or** a documented migration plan. Equivalence is not
testable: the engine is test-only dead code while the GUI worker is the
production path with journal/fsync/event contracts the engine does not
have. Delivered per the approved alternative: cross-reference doc
comments on both execution paths and
`docs/fork-review/TRANSFER_ENGINE_MIGRATION.md`. The duplication itself
remains — hence PARTIAL, not fixed.

### R17 — zvariant advisory verification (`d6edefa`)
`RUSTSEC-2026-0370/-0371/-0372` (`zvariant`, `zvariant_derive`,
`zbus_names`) and `RUSTSEC-2026-0192` (`ttf-parser`) were re-checked
against the advisory database: all are `info`/`unmaintained`, all are
transitive through `slint → zbus 5` (Linux-only code path), and none is
fixable from this repository (slint 1.19.1 still pins zbus ≥ 5.14).
`deny.toml` documents this with `unmaintained = "workspace"`.

## Limitations and honest gaps

1. **GitHub Actions is disabled on the fork** (`martin-77/manifold`,
   HTTP 422 "Actions has been disabled for this repository"). The last
   green CI run covers `7639289`-era commits; `a1457f3`, `d6edefa`,
   `f486311`, `c90afd9`, `d715a2d`, `c3c16a9`, `bf807df`, `f3edac1`
   have **no CI proof** — the local gate (full workspace tests, strict
   clippy host + Windows cross-lint) is the only evidence. Re-enabling
   Actions and re-running CI is an external prerequisite.
2. **Smoke test scope:** the release smoke test (binary builds, starts,
   stays stable, exits, v0.8.0) is the functional baseline. It is not
   comprehensive functional or data-safety validation; no claim of that
   is made anywhere in this document.
3. **Live-network paths are not tested** (ground rule: no production
   data/network in tests). R12's askpass path uses a fake-ssh harness;
   real-server password auth remains unvalidated.
4. **Reviewer-confirmed Round 1 weaknesses still open:** the 1-TiB
   sparse-file test carries an OOM risk on small disks; the PATH-mutex
   tests are not isolated across test groups; F-12's archive-listing
   side still depends on python3 (fallback chain `zipinfo`/CLI exists,
   but python3 remains the primary lister).
5. **License metadata** (Cargo.toml "MIT OR Apache-2.0" vs README MIT,
   no LICENSE file) is an upstream decision and deliberately untouched.
6. R08's autorelease/BOOL changes and R14's workflow correctness are
   verified statically/by partial runtime tests as noted above — they
   are not `FIXED_PLATFORM_VALIDATED` beyond what macOS hardware covers.
