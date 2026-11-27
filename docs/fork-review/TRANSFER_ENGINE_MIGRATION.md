# TransferEngine ↔ GUI transfer worker: consolidation plan (R16)

Status: **PARTIAL — documented migration plan** (consolidation itself was
explicitly scoped to "only if equivalence is testable"; see *Why not
equivalence-tested* below).

## Current state (verified 2026-11-27)

There are two parallel transfer execution paths:

| | `TransferEngine::execute_task_controlled` (`crates/transfer`) | `perform_bg_single_transfer` (`crates/ui/src/gui/transfer_worker.rs`) |
|---|---|---|
| Used in production | **No** — only referenced by tests inside `crates/transfer` | **Yes** — the only path the GUI executes |
| Abstraction | `FileSystemBackend` trait objects | concrete `LocalFsBackend` + remote registry, local paths |
| Conflict handling | policy enum + sticky policy, `WaitingForConflictResolution` | GUI dialog flow via `ConflictModalDescriptor` |
| Resume / retry | `transferred_bytes` resume, retry with backoff | none (fresh part file per attempt) |
| Pause / cancel | `TransferControlHandle` | `TransferControlHandle` (shared type) |
| Throttling | `TokenBucketLimiter` (shared) | `TokenBucketLimiter` (shared) |
| Part file | `{target}.__manifold_part_{id}` via `write_bytes`/`append_bytes` | `local_part_sibling` `.part`, exclusive create |
| Durability | part content **not fsynced** before `rename` | part fsynced (`sync_all`) before publish |
| Crash safety of publish | plain `rename`, R06 fallback refusal for non-atomic backends | swap journal (R03) + atomic swap + backup retention |
| Progress reporting | task fields only | `BgWorkerEvent::Progress` channel to the UI |
| macOS specifics | none | app-bundle sanitize, quarantine-preserving swap |

The shared, non-duplicated parts are already in `crates/transfer`:
`TransferTask`, `TransferStatus`, `TransferPriority`, `TokenBucketLimiter`,
`TransferControlHandle`, `ConflictResolution`, `ConflictModalDescriptor`,
`DEFAULT_TRANSFER_CHUNK_SIZE`. The GUI imports these types and executes
with them.

## Why not equivalence-tested

An equivalence test needs one shared contract. The two paths have
deliberately different contracts:

1. The engine is backend-agnostic (works on any `FileSystemBackend`,
   including archives and remote stubs in tests); the worker is
   specialised per direction (local↔remote↔archive) with GUI events,
   journaling and macOS metadata handling that the engine does not and
   should not model.
2. The engine's durability semantics are **weaker** (no fsync of the
   staged part before `rename`, no swap journal). Asserting "same final
   state" would pass while hiding exactly the differences that matter
   (crash windows), which would be an unevidenced green test.

Therefore consolidation cannot be validated by an equivalence test today;
it must be done as a migration with the worker's hardened semantics as
the reference.

## Migration plan

1. **Adopt-first:** move the worker's publish semantics (exclusive part
   file, fsync before publish, swap journal per R03, R06 fallback
   refusal) into `TransferEngine::execute_task_controlled` as the single
   implementation. Each step lands with the corresponding worker test
   ported to the engine (the worker tests in `staging_tests` and
   `crates/ui/src/gui/tests.rs` are the behavioural spec).
2. **Event bridge:** give the engine an `Option<Arc<dyn Fn(TransferEvent)
   + Send + Sync>>` callback instead of a channel, so the GUI keeps its
   `BgWorkerEvent` mapping without the engine knowing about Slint.
3. **Direction dispatch:** the per-direction branches (scp streaming for
   remote↔local, archive URIs) move behind a `TransferRouter` trait the
   GUI implements; the engine stays direction-agnostic.
4. **Replace:** switch `transfer_worker.rs` to call the engine; delete
   the duplicated local→local streaming loop.
5. **Regression gate:** keep every existing worker test, run them against
   the engine path; only then remove the worker's private helpers.

Estimated scope: medium-large refactor of two 1.1k–1.8k line modules with
no user-visible behaviour change — appropriate for an upstream PR, not
for this hardening branch. Tracked here so the duplication is visible and
the next contributor does not fix one path and forget the other.

## Interim guard (what this branch does instead)

- doc comments on `TransferEngine::execute_task_controlled` and
  `perform_bg_single_transfer` pointing at each other and at this plan;
- the R01–R07 hardening fixes are already applied to **both** paths where
  each has the corresponding hazard (R06 guard in the engine, R03/R04
  journal/fsync in the worker).
