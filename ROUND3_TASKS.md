# ROUND3_TASKS.md — Round 3 work packages

> **Fork-internal document.** Tracks Round 3 tasks following the Round 2
> remediation (`INDEPENDENT_REMEDIATION.md`, packages R01 … R17).
> Task IDs are append-only: adding a task never renumbers or replaces
> existing ones. Status taxonomy and evidence rules follow Round 2
> (`FIXED_TESTED` requires a red-verified regression test, etc.).

## N01 — Critical SSH/SFTP compatibility with non-POSIX login shells

Priority: **P0 — core functionality broken.**
Status: **FIXED_TESTED** (local gate + red-verified regression tests;
real-world Fish validation on the CachyOS server pending — see
Implementation record)
Source: real-world test against a CachyOS server using **Fish** as its
default login shell.

### Confirmed failures

1. SFTP directory listings remain empty (the POSIX `ls` wrapper scripts
   are parsed by Fish and fail; the failure is indistinguishable from
   an empty directory).
2. The embedded SSH terminal disconnects immediately with
   `fish: $ is not a valid variable in fish.` — the generated command
   contains `exec "${SHELL:-/bin/sh}" -l`, which Fish cannot parse.

The current SFTP backend generates remote POSIX shell commands that
contain Fish-incompatible constructs:

- `for ...; do ... done` loops
- POSIX subshell grouping
- POSIX variable expansion (`${VAR:-default}`)
- POSIX-specific shell escaping (`'\''`-style quoting)

Relevant source (`crates/vfs-remote/src/lib.rs` unless noted):

- `run_remote_shell`
- `list_directory`
- `execute_shell_in_dir`
- `build_remote_ssh_terminal`
- GUI terminal initialization and SSH readiness sentinel handling
  (`crates/ui/src/gui/`)

### Required implementation

Separate **machine-generated remote commands** from **interactive
terminal sessions**.

**Machine-generated commands:**

- Execute POSIX scripts explicitly through a suitable remote POSIX
  shell instead of assuming the user's login shell is POSIX-compatible.
- Ensure the outer command and its quoting are compatible with Fish,
  Bash, Zsh and POSIX sh.
- Do not merely prepend `/bin/sh -c` without validating argument
  escaping.
- Review all SSH-generated commands, not only directory listings.
- Preserve correct handling of spaces, apostrophes, backslashes,
  Unicode and shell metacharacters in remote paths.
- Prevent shell-command injection.
- Propagate remote command failures and nonzero exit codes.
- Do not display a failed directory listing as an empty directory.

**Interactive SSH terminal:**

- Preserve the user's configured login shell.
- Fish users must receive a functioning interactive Fish terminal.
- Correct the initial working-directory handling.
- Correct readiness-sentinel handling.
- Do not force interactive users into Bash or sh.
- Do not require server-side shell configuration changes.

**SFTP architecture:**

- Investigate whether real SFTP subsystem operations can replace the
  existing SSH-command and ls-output-parsing implementation.
- Preserve OpenSSH transport, SSH-Agent, SSH configuration, ProxyJump
  and host-key verification wherever possible.
- Support SFTP-only servers that do not permit arbitrary SSH shell
  execution, or explicitly document this limitation until genuine
  subsystem support is implemented.
- Do not perform an uncontrolled rewrite of the entire network backend.

**Regression and integration tests:**

- Test against actual Fish, Bash, Zsh and POSIX sh interpreters
  wherever available.
- Cover: directory listing; empty directories versus failed listings;
  metadata; symbolic links; upload and download; rename; directory
  creation; delete; remote terminal startup; initial working directory;
  paths containing special characters; remote command failures.
- Use isolated temporary test data and local test servers.
- Do not change the CachyOS server's login shell or sshd configuration.
- Document actual verification results and remaining limitations.

### Definition of done

Implement, test, commit and push the fix to `origin/macos-dev`.
Treat this as a newly confirmed real-world functional defect rather
than a theoretical improvement.

### Implementation record (2026-11-27)

**Machine commands** — `crates/vfs-remote/src/lib.rs`:

- `wrap_posix_shell_command(script)` emits
  `echo <base64> | base64 -d | sh`. The outer pipeline contains only
  `[A-Za-z0-9+/=- ]` and `|` (asserted by a test), which every target
  shell parses identically; the POSIX script never reaches the login
  shell's parser, closing both the compatibility gap and the quoting
  injection surface. `base64 -d` verified on GNU, BusyBox and BSD/
  macOS semantics (locally checked on macOS).
- `run_remote_shell` (the single choke point for ALL 13 generated
  commands: `id -u`, `df`, `ls -abln` listing, `find` search, `mkdir`,
  `rm`, `mv`, `cp`, `ln`, `chmod`, `cat >>` chunk append, bottom-pane
  `execute_shell_in_dir`) now wraps when the server supports it.
- One probe per session (`shell_supports_b64_wrap`, cached in a
  `OnceLock`) decodes a 1-byte payload through the exact pipeline; on
  failure the backend keeps the legacy raw form (POSIX login shells).
- Exit codes: the wrapped pipeline propagates the script's status
  through `sh` → login shell → ssh → the auth executor, which already
  converts non-zero into `Err` — failed listings can no longer be
  mistaken for success.

**Interactive terminal** — `crates/ui/src/terminal.rs` +
`TerminalIntegration::build_remote_ssh_terminal`: the readiness
sentinel, `cd -- '<dir>'` and `exec "${SHELL:-/bin/sh}" -l` are moved
into the wrapped POSIX script. The login shell only sees the base64
pipeline (no more `fish: $ is not a valid variable`), the sentinel is
printed by the inner `sh` before the exec, and the user's real login
shell (Fish included) starts interactively on the `-tt`/`-t` TTY.
Initial working directory is applied inside the POSIX script with the
existing `'\''` escaping, which is now always interpreted by a POSIX
shell.

**Failed listing ≠ empty directory** — `crates/ui/src/gui/mod.rs`:
`BgDirLoadEvent` gained an `error` field; the background dir-load
workers (remote AND local) propagate listing errors instead of
`unwrap_or_default()`, and `poll_bg_dir_loads` keeps the previous pane
content while surfacing the error as toast + `[DIR_ERR]` log.

**SFTP subsystem** — investigated within scope: genuine subsystem
support would replace the `ls`-parsing layer wholesale; the module
header of `manifold-vfs-remote` now documents the shell-execution
architecture, the inherited OpenSSH guarantees, and the sftp-only /
forced-command server limitation as explicit future work. No
uncontrolled rewrite was performed.

**Tests** (red-verified where the defect is reproducible locally):

- `b64_encode_matches_system_base64` — byte-for-byte incl. 0..255.
- `wrapped_outer_command_is_shell_safe_charset` — the Fish-safety
  invariant of the outer command.
- `wrapped_scripts_execute_under_bash_zsh_and_sh` — runs the wrapper
  through the REAL local `/bin/sh`, `/bin/bash`, `/bin/zsh` (and Fish
  if installed) exactly as sshd invokes `$SHELL -c <outer>`; lists a
  directory with spaces, apostrophes, backslashes, Unicode and
  metacharacter names.
- `wrapped_script_propagates_nonzero_exit` — exit 7 survives the
  wrapper in all three interpreters.
- `wrapped_script_blocks_shell_injection` — `x'; touch PWNED; '` is
  listed literally, never executed.
- `test_remote_ssh_terminal_command_builder` +
  `test_remote_ssh_spec_builds_interactive_pty_args` — assert the
  wrapped outer form and decode the payload (sentinel, cd, exec).
  Both red on the old raw-command builder (verified).
- `failed_dir_listing_surfaces_error_and_keeps_pane` — red on the old
  error-swallowing poll (verified).

### Verification results & remaining limitations

- Local gate: 15/15 workspace suites, fmt, strict clippy (host +
  `x86_64-pc-windows-msvc` cross) green.
- **Fish was not installed on the local macOS test machine** — the
  Fish code path is covered analytically (outer-command charset test)
  and by the real-world CachyOS reproduction, but an automated Fish
  run still needs a machine with Fish on `PATH` (the integration test
  picks it up automatically when present).
- No live SSH server is spun up in CI (ground rule: no production
  network in tests); the interpreters are invoked the way sshd
  invokes them, but a real sshd round trip against a Fish-account
  server remains manual verification.
- Servers without `base64`/`sh` fall back to the legacy raw form and
  still require a POSIX login shell (documented).
- SFTP-only servers (no shell exec) remain unsupported — documented
  limitation, see module header.
