//! Directory Synchronization, Diff Engine, and Multi-Rename (Batch Renamer)
//! for Project Manifold (`Sections 3.5 & 3.6` of `BRIEF.md`).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use heck::{ToKebabCase, ToLowerCamelCase, ToSnakeCase, ToTitleCase};
use manifold_vfs::{FileMetadata, FileSystemBackend, VfsError};
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Synchronization strategy (`Section 3.5` of `BRIEF.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncStrategy {
    LeftToRight,
    RightToLeft,
    Bidirectional,
}

/// File comparison mode (`Section 3.5` of `BRIEF.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonMode {
    Metadata,
    ContentHash,
    BinaryDiff,
}

/// Planned operation for a single relative path in the synchronization changeset tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncOperation {
    CopyLeftToRight,
    CopyRightToLeft,
    DeleteLeft,
    DeleteRight,
    Conflict,
    Identical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncChangesetEntry {
    pub relative_path: String,
    pub left_meta: Option<FileMetadata>,
    pub right_meta: Option<FileMetadata>,
    pub operation: SyncOperation,
    pub approved: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncExecutionPlan {
    pub left_root: String,
    pub right_root: String,
    pub strategy: Option<SyncStrategy>,
    pub comparison_mode: Option<ComparisonMode>,
    pub entries: Vec<SyncChangesetEntry>,
}

struct SyncBuildCtx<'a> {
    left_vfs: &'a dyn FileSystemBackend,
    right_vfs: &'a dyn FileSystemBackend,
    strategy: SyncStrategy,
    mode: ComparisonMode,
}

impl SyncExecutionPlan {
    /// Builds a recursive, inspectable operational changeset tree between `left_vfs` and `right_vfs` (`GAP-03`).
    pub fn build(
        left_vfs: &dyn FileSystemBackend,
        left_root: &str,
        right_vfs: &dyn FileSystemBackend,
        right_root: &str,
        strategy: SyncStrategy,
        mode: ComparisonMode,
    ) -> Result<Self, VfsError> {
        let mut entries = Vec::new();
        let ctx = SyncBuildCtx {
            left_vfs,
            right_vfs,
            strategy,
            mode,
        };
        Self::build_recursive(&ctx, left_root, right_root, "", 0, &mut entries)?;

        Ok(Self {
            left_root: left_root.to_string(),
            right_root: right_root.to_string(),
            strategy: Some(strategy),
            comparison_mode: Some(mode),
            entries,
        })
    }

    fn build_recursive(
        ctx: &SyncBuildCtx<'_>,
        left_dir: &str,
        right_dir: &str,
        rel_prefix: &str,
        depth: usize,
        entries: &mut Vec<SyncChangesetEntry>,
    ) -> Result<(), VfsError> {
        if depth > 32 {
            return Ok(());
        }
        // A directory on one side may be a plain file on the other (the
        // replacement case); listing such a path yields NotADirectory on
        // real filesystems and NotFound on virtual ones. Both mean
        // "no children to compare" below the root.
        let not_a_dir = |e: &VfsError| match e {
            VfsError::NotFound(_) => true,
            VfsError::IoError(io) => io.kind() == std::io::ErrorKind::NotADirectory,
            _ => false,
        };
        let left_items = match ctx.left_vfs.list_directory(left_dir) {
            Ok(list) => list,
            Err(e) if depth > 0 && not_a_dir(&e) => Vec::new(),
            Err(e) => return Err(e),
        };
        let right_items = match ctx.right_vfs.list_directory(right_dir) {
            Ok(list) => list,
            Err(e) if depth > 0 && not_a_dir(&e) => Vec::new(),
            Err(e) => return Err(e),
        };

        let mut left_map: HashMap<String, FileMetadata> = HashMap::new();
        for item in left_items {
            left_map.insert(item.name.clone(), item);
        }

        let mut right_map: HashMap<String, FileMetadata> = HashMap::new();
        for item in right_items {
            right_map.insert(item.name.clone(), item);
        }

        let mut all_names = BTreeSet::new();
        all_names.extend(left_map.keys().cloned());
        all_names.extend(right_map.keys().cloned());

        for name in all_names {
            let l = left_map.get(&name).cloned();
            let r = right_map.get(&name).cloned();
            let rel_path = if rel_prefix.is_empty() {
                name.clone()
            } else {
                format!("{rel_prefix}/{name}")
            };
            let child_left_dir = join_vfs_path(left_dir, &name);
            let child_right_dir = join_vfs_path(right_dir, &name);

            if l.as_ref().is_some_and(|lm| lm.is_dir) && r.as_ref().is_some_and(|rm| rm.is_dir) {
                Self::build_recursive(
                    ctx,
                    &child_left_dir,
                    &child_right_dir,
                    &rel_path,
                    depth + 1,
                    entries,
                )?;
                continue;
            }

            let operation = match (&l, &r) {
                (Some(_), None) => match ctx.strategy {
                    SyncStrategy::LeftToRight | SyncStrategy::Bidirectional => {
                        SyncOperation::CopyLeftToRight
                    }
                    SyncStrategy::RightToLeft => SyncOperation::DeleteLeft,
                },
                (None, Some(_)) => match ctx.strategy {
                    SyncStrategy::LeftToRight => SyncOperation::DeleteRight,
                    SyncStrategy::RightToLeft | SyncStrategy::Bidirectional => {
                        SyncOperation::CopyRightToLeft
                    }
                },
                (Some(lm), Some(rm)) => {
                    let same = Self::files_equal(ctx.left_vfs, lm, ctx.right_vfs, rm, ctx.mode)?;
                    if same {
                        SyncOperation::Identical
                    } else {
                        match ctx.strategy {
                            SyncStrategy::LeftToRight => SyncOperation::CopyLeftToRight,
                            SyncStrategy::RightToLeft => SyncOperation::CopyRightToLeft,
                            SyncStrategy::Bidirectional => match (lm.modified, rm.modified) {
                                (Some(lt), Some(rt)) if lt > rt => SyncOperation::CopyLeftToRight,
                                (Some(lt), Some(rt)) if rt > lt => SyncOperation::CopyRightToLeft,
                                _ => SyncOperation::Conflict,
                            },
                        }
                    }
                }
                (None, None) => unreachable!(),
            };

            let is_noop = matches!(
                operation,
                SyncOperation::Identical | SyncOperation::Conflict
            );
            let approved = !is_noop;
            let recurse_left_only = l.as_ref().is_some_and(|m| m.is_dir)
                && !r.as_ref().is_some_and(|m| m.is_dir)
                && operation == SyncOperation::CopyLeftToRight;
            let recurse_right_only = r.as_ref().is_some_and(|m| m.is_dir)
                && !l.as_ref().is_some_and(|m| m.is_dir)
                && operation == SyncOperation::CopyRightToLeft;

            entries.push(SyncChangesetEntry {
                relative_path: rel_path.clone(),
                left_meta: l,
                right_meta: r,
                operation,
                approved,
            });

            if recurse_left_only || recurse_right_only {
                Self::build_recursive(
                    ctx,
                    &child_left_dir,
                    &child_right_dir,
                    &rel_path,
                    depth + 1,
                    entries,
                )?;
            }
        }

        Ok(())
    }

    fn files_equal(
        left_vfs: &dyn FileSystemBackend,
        lm: &FileMetadata,
        right_vfs: &dyn FileSystemBackend,
        rm: &FileMetadata,
        mode: ComparisonMode,
    ) -> Result<bool, VfsError> {
        if lm.is_dir && rm.is_dir {
            return Ok(true);
        }
        if lm.is_dir != rm.is_dir {
            return Ok(false);
        }
        match mode {
            ComparisonMode::Metadata => Ok(lm.size == rm.size && lm.modified == rm.modified),
            ComparisonMode::ContentHash => {
                if lm.size != rm.size {
                    return Ok(false);
                }
                let lb = left_vfs.read_bytes(&lm.path)?;
                let rb = right_vfs.read_bytes(&rm.path)?;
                Ok(Sha256::digest(&lb) == Sha256::digest(&rb))
            }
            ComparisonMode::BinaryDiff => {
                if lm.size != rm.size {
                    return Ok(false);
                }
                let lb = left_vfs.read_bytes(&lm.path)?;
                let rb = right_vfs.read_bytes(&rm.path)?;
                Ok(lb == rb)
            }
        }
    }

    /// Executes all approved changeset entries across `left_vfs` and
    /// `right_vfs`, handling nested subdirectories, file-vs-directory
    /// replacements, and bottom-up deletes (`GAP-03`).
    ///
    /// Stops at the first failure and reports how many entries were applied
    /// before it (R01); a failed replacement never destroys the previous
    /// destination (see [`publish_staged_file`] / [`replace_with_directory`]).
    pub fn execute(
        &self,
        left_vfs: &dyn FileSystemBackend,
        right_vfs: &dyn FileSystemBackend,
    ) -> SyncExecutionOutcome {
        let mut outcome = SyncExecutionOutcome::default();
        let mut pending_deletes: Vec<&SyncChangesetEntry> = Vec::new();

        macro_rules! bail {
            ($e:expr) => {{
                outcome.error = Some($e);
                return outcome;
            }};
        }

        for entry in &self.entries {
            if !entry.approved {
                continue;
            }
            if matches!(
                entry.operation,
                SyncOperation::DeleteLeft | SyncOperation::DeleteRight
            ) {
                pending_deletes.push(entry);
                continue;
            }
            let l_path = join_vfs_path(&self.left_root, &entry.relative_path);
            let r_path = join_vfs_path(&self.right_root, &entry.relative_path);

            match entry.operation {
                SyncOperation::CopyLeftToRight => {
                    let is_dir = entry
                        .left_meta
                        .as_ref()
                        .map(|m| m.is_dir)
                        .unwrap_or_else(|| left_vfs.metadata(&l_path).is_ok_and(|m| m.is_dir));
                    let dst_plan = DstAtPlan::from_meta(entry.right_meta.as_ref());
                    if is_dir {
                        match replace_with_directory(
                            right_vfs,
                            &r_path,
                            &entry.relative_path,
                            dst_plan,
                        ) {
                            Ok(w) => outcome.warnings.extend(w),
                            Err(e) => bail!(e),
                        }
                    } else {
                        if let Some((parent, _)) =
                            r_path.rsplit_once('/').filter(|(p, _)| !p.is_empty())
                        {
                            if let Err(e) = right_vfs.create_dir(parent) {
                                bail!(err_for(&entry.relative_path, e));
                            }
                        }
                        match copy_file_safely(
                            left_vfs,
                            right_vfs,
                            &l_path,
                            &r_path,
                            &entry.relative_path,
                            dst_plan,
                        ) {
                            Ok(w) => outcome.warnings.extend(w),
                            Err(e) => bail!(e),
                        }
                    }
                    outcome.applied += 1;
                }
                SyncOperation::CopyRightToLeft => {
                    let is_dir = entry
                        .right_meta
                        .as_ref()
                        .map(|m| m.is_dir)
                        .unwrap_or_else(|| right_vfs.metadata(&r_path).is_ok_and(|m| m.is_dir));
                    let dst_plan = DstAtPlan::from_meta(entry.left_meta.as_ref());
                    if is_dir {
                        match replace_with_directory(
                            left_vfs,
                            &l_path,
                            &entry.relative_path,
                            dst_plan,
                        ) {
                            Ok(w) => outcome.warnings.extend(w),
                            Err(e) => bail!(e),
                        }
                    } else {
                        if let Some((parent, _)) =
                            l_path.rsplit_once('/').filter(|(p, _)| !p.is_empty())
                        {
                            if let Err(e) = left_vfs.create_dir(parent) {
                                bail!(err_for(&entry.relative_path, e));
                            }
                        }
                        match copy_file_safely(
                            right_vfs,
                            left_vfs,
                            &r_path,
                            &l_path,
                            &entry.relative_path,
                            dst_plan,
                        ) {
                            Ok(w) => outcome.warnings.extend(w),
                            Err(e) => bail!(e),
                        }
                    }
                    outcome.applied += 1;
                }
                SyncOperation::DeleteLeft
                | SyncOperation::DeleteRight
                | SyncOperation::Conflict
                | SyncOperation::Identical => {}
            }
        }

        // Execute deletions deepest-path-first so child entries are removed before parent folders.
        pending_deletes.sort_by_key(|e| std::cmp::Reverse(e.relative_path.matches('/').count()));
        for entry in pending_deletes {
            let l_path = join_vfs_path(&self.left_root, &entry.relative_path);
            let r_path = join_vfs_path(&self.right_root, &entry.relative_path);
            match entry.operation {
                SyncOperation::DeleteLeft => {
                    match left_vfs.remove(&l_path, true) {
                        Ok(()) | Err(VfsError::NotFound(_)) => {}
                        Err(e) => bail!(err_for(&entry.relative_path, e)),
                    }
                    outcome.applied += 1;
                }
                SyncOperation::DeleteRight => {
                    match right_vfs.remove(&r_path, true) {
                        Ok(()) | Err(VfsError::NotFound(_)) => {}
                        Err(e) => bail!(err_for(&entry.relative_path, e)),
                    }
                    outcome.applied += 1;
                }
                _ => {}
            }
        }
        outcome
    }
}

/// Wraps an underlying error with the relative changeset path it occurred
/// for, so partial failures stay traceable (F-21).
fn err_for(relative: &str, e: VfsError) -> VfsError {
    VfsError::OperationFailed(relative.to_string(), e.to_string())
}

/// Result of applying a [`SyncExecutionPlan`]: how many entries were
/// applied before completion or the first failure, non-fatal warnings
/// (e.g. retired backups that could not be deleted), and the first error
/// if execution stopped (R01: partial completion stays reportable).
#[derive(Debug, Default)]
pub struct SyncExecutionOutcome {
    pub applied: usize,
    pub warnings: Vec<String>,
    pub error: Option<VfsError>,
}

/// Visible retire name for a destination being replaced:
/// `<name>.manifold-old-<pid>-<seq>` in the same parent directory.
fn retired_sibling_path(dst_path: &str) -> String {
    static RETIRE_SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = RETIRE_SEQ.fetch_add(1, Ordering::Relaxed);
    let (parent, name) = match dst_path.rsplit_once('/') {
        Some((p, n)) => (p, n),
        None => ("", dst_path),
    };
    format!("{parent}/{name}.manifold-old-{}-{seq}", std::process::id())
}

/// What the plan believed existed at the destination when it was built.
/// `None` = absent, `Some(true)` = directory, `Some(false)` = file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DstAtPlan {
    Absent,
    WasFile,
    WasDir,
}

impl DstAtPlan {
    fn from_meta(meta: Option<&FileMetadata>) -> Self {
        match meta {
            None => DstAtPlan::Absent,
            Some(m) if m.is_dir => DstAtPlan::WasDir,
            Some(_) => DstAtPlan::WasFile,
        }
    }
}

/// Current destination state classified for replacement decisions.
enum DstNow {
    Absent,
    Dir,
    File,
}

fn classify_dst(dst: &dyn FileSystemBackend, dst_path: &str) -> Result<DstNow, VfsError> {
    match dst.metadata(dst_path) {
        Ok(m) => Ok(if m.is_dir { DstNow::Dir } else { DstNow::File }),
        Err(VfsError::NotFound(_)) => Ok(DstNow::Absent),
        Err(e) => Err(e),
    }
}

/// Publishes the staged file `part_path` onto `dst_path` without ever
/// destroying the existing target before the replacement is live (R01):
///
/// - destination absent: plain rename;
/// - destination file: atomic rename replace (only when the plan approved
///   replacing a file);
/// - destination directory: move it aside to a visible retired name,
///   publish, then delete the retired copy; a failed publish rolls the
///   original directory back into place;
/// - destination appeared or changed type since planning: refuse and keep
///   both the staged content and the foreign destination.
///
/// Returns non-fatal warnings (e.g. a retired backup that could not be
/// deleted after a successful publish).
fn publish_staged_file(
    dst: &dyn FileSystemBackend,
    part_path: &str,
    dst_path: &str,
    relative: &str,
    plan: DstAtPlan,
) -> Result<Vec<String>, VfsError> {
    let mut warnings = Vec::new();
    match classify_dst(dst, dst_path).map_err(|e| err_for(relative, e))? {
        DstNow::Absent => {
            dst.rename(part_path, dst_path)
                .map_err(|e| err_for(relative, e))?;
        }
        DstNow::File => match plan {
            DstAtPlan::WasFile => {
                dst.rename(part_path, dst_path)
                    .map_err(|e| err_for(relative, e))?;
            }
            _ => {
                return Err(VfsError::OperationFailed(
                    relative.to_string(),
                    format!(
                        "destination {dst_path} appeared or changed type since the plan \
                         was built; refusing to overwrite it. New content kept at {part_path}"
                    ),
                ));
            }
        },
        DstNow::Dir => match plan {
            DstAtPlan::WasDir => {
                let bak = retired_sibling_path(dst_path);
                dst.rename(dst_path, &bak)
                    .map_err(|e| err_for(relative, e))?;
                match dst.rename(part_path, dst_path) {
                    Ok(()) => {
                        // Approved destructive step: the replaced directory
                        // is no longer needed once the new file is published.
                        if let Err(e) = dst.remove(&bak, true) {
                            warnings.push(format!(
                                "replacement of {dst_path} published, but retiring the old \
                                 directory failed ({e}); old content kept at {bak}"
                            ));
                        }
                    }
                    Err(e) => match dst.rename(&bak, dst_path) {
                        Ok(()) => {
                            return Err(VfsError::OperationFailed(
                                relative.to_string(),
                                format!(
                                    "publishing the replacement for {dst_path} failed ({e}); \
                                     the original directory was restored, new content kept \
                                     at {part_path}"
                                ),
                            ));
                        }
                        Err(re) => {
                            return Err(VfsError::OperationFailed(
                                relative.to_string(),
                                format!(
                                    "publishing the replacement for {dst_path} failed ({e}) \
                                     AND restoring the original directory failed ({re}); \
                                     original directory kept at {bak}, new content kept at \
                                     {part_path}"
                                ),
                            ));
                        }
                    },
                }
            }
            _ => {
                return Err(VfsError::OperationFailed(
                    relative.to_string(),
                    format!(
                        "destination {dst_path} is a directory but the plan expected \
                         {plan:?}; refusing to replace it. New content kept at {part_path}"
                    ),
                ));
            }
        },
    }
    Ok(warnings)
}

/// Makes `dst_path` a directory, preserving an existing approved file
/// target until the new directory is live (R01). Mirrors
/// [`publish_staged_file`] for the directory-replaces-file case.
fn replace_with_directory(
    dst: &dyn FileSystemBackend,
    dst_path: &str,
    relative: &str,
    plan: DstAtPlan,
) -> Result<Vec<String>, VfsError> {
    let mut warnings = Vec::new();
    match classify_dst(dst, dst_path).map_err(|e| err_for(relative, e))? {
        DstNow::Dir => {
            // Already a directory (approved or concurrently created as one):
            // ensure the path exists; contents merge per the sync plan.
            dst.create_dir(dst_path).map_err(|e| err_for(relative, e))?;
        }
        DstNow::Absent => {
            dst.create_dir(dst_path).map_err(|e| err_for(relative, e))?;
        }
        DstNow::File => {
            if plan != DstAtPlan::WasFile {
                return Err(VfsError::OperationFailed(
                    relative.to_string(),
                    format!(
                        "destination {dst_path} is a file but the plan expected \
                         {plan:?}; refusing to replace it with a directory"
                    ),
                ));
            }
            let bak = retired_sibling_path(dst_path);
            dst.rename(dst_path, &bak)
                .map_err(|e| err_for(relative, e))?;
            match dst.create_dir(dst_path) {
                Ok(()) => {
                    if let Err(e) = dst.remove(&bak, false) {
                        warnings.push(format!(
                            "replacement of {dst_path} with a directory published, but \
                             retiring the old file failed ({e}); old content kept at {bak}"
                        ));
                    }
                }
                Err(e) => match dst.rename(&bak, dst_path) {
                    Ok(()) => {
                        return Err(VfsError::OperationFailed(
                            relative.to_string(),
                            format!(
                                "creating the directory {dst_path} failed ({e}); the \
                                 original file was restored"
                            ),
                        ));
                    }
                    Err(re) => {
                        return Err(VfsError::OperationFailed(
                            relative.to_string(),
                            format!(
                                "creating the directory {dst_path} failed ({e}) AND \
                                 restoring the original file failed ({re}); original file \
                                 kept at {bak}"
                            ),
                        ));
                    }
                },
            }
        }
    }
    Ok(warnings)
}

/// Copies one file entry from `src` to `dst` safely (F-21):
/// - streams via `read_range`/`append_bytes` when the destination supports
///   efficient chunked I/O (local filesystem), otherwise buffers once;
/// - stages into a part path and validates the size before publishing;
/// - publishes via [`publish_staged_file`], which never removes an
///   existing target before the replacement is live (R01).
fn copy_file_safely(
    src: &dyn FileSystemBackend,
    dst: &dyn FileSystemBackend,
    src_path: &str,
    dst_path: &str,
    relative: &str,
    plan: DstAtPlan,
) -> Result<Vec<String>, VfsError> {
    const CHUNK: usize = 4 * 1024 * 1024;
    static PART_SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = PART_SEQ.fetch_add(1, Ordering::Relaxed);
    let part_path = format!("{dst_path}.manifold-sync-part-{}-{seq}", std::process::id());

    // The source must be readable to copy it; a metadata error here means
    // the file vanished or is unreadable. Treating it as size 0 would skip
    // staged-size validation and let a truncated copy publish unnoticed.
    let src_meta = src.metadata(src_path).map_err(|e| err_for(relative, e))?;
    let total = src_meta.size;

    // Stream only when BOTH sides actually benefit: the default
    // read_range/append_bytes implementations buffer whole files, so
    // checking only the destination turned a remote source into a full
    // re-read per chunk (quadratic traffic) and a remote destination into
    // read-modify-write appends.
    if src.supports_chunked_io() && dst.supports_chunked_io() {
        let mut offset = 0u64;
        let mut wrote_any = false;
        loop {
            let chunk = src
                .read_range(src_path, offset, CHUNK)
                .map_err(|e| err_for(relative, e))?;
            if chunk.is_empty() {
                break;
            }
            dst.append_bytes(&part_path, &chunk)
                .map_err(|e| err_for(relative, e))?;
            wrote_any = true;
            offset += chunk.len() as u64;
            if total.is_some_and(|t| offset >= t) {
                break;
            }
        }
        if !wrote_any {
            // Empty source: the loop never appended, so stage an empty
            // part file explicitly; otherwise publishing has nothing to
            // rename and the copy of a 0-byte file fails (R05).
            dst.append_bytes(&part_path, &[])
                .map_err(|e| err_for(relative, e))?;
        }
    } else {
        let bytes = src.read_bytes(src_path).map_err(|e| err_for(relative, e))?;
        dst.write_bytes(&part_path, &bytes)
            .map_err(|e| err_for(relative, e))?;
    }

    // Validate the staged copy against the known source size before
    // publishing; size 0 is a real size and must match too.
    if let Some(total) = total {
        let staged = dst
            .metadata(&part_path)
            .map_err(|e| err_for(relative, e))
            .and_then(|m| {
                if m.size == Some(total) {
                    Ok(())
                } else {
                    let _ = dst.remove(&part_path, false);
                    Err(VfsError::OperationFailed(
                        relative.to_string(),
                        format!("staged size mismatch ({:?} != {total})", m.size),
                    ))
                }
            });
        staged?;
    }

    // Publish without ever removing the existing target first (R01).
    publish_staged_file(dst, &part_path, dst_path, relative, plan)
}

fn join_vfs_path(root: &str, child: &str) -> String {
    let trimmed_root = root.trim_end_matches('/');
    let trimmed_child = child.trim_start_matches('/');
    if trimmed_root.is_empty() {
        format!("/{trimmed_child}")
    } else {
        format!("{trimmed_root}/{trimmed_child}")
    }
}

/// Case conversion styles supported by the Multi-Rename tool (`Section 3.6` of `BRIEF.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaseConversionStyle {
    UpperCase,
    LowerCase,
    TitleCase,
    CamelCase,
    KebabCase,
    SnakeCase,
}

/// Portion of the filename targeted by a [`RenameRule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RenameTargetScope {
    Name,
    NameWithExtension,
    Extension,
}

/// Occurrence matching mode for [`RenameRule::ScopedReplaceText`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplaceOccurrences {
    All,
    First,
    Last,
    RegularExpression,
}

/// Insertion position for [`RenameRule::ScopedAddSequence`], [`RenameRule::ScopedAddText`],
/// and [`RenameRule::ScopedAddDate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TextInsertionPosition {
    AfterName,
    BeforeName,
    ReplaceName,
}

/// Rule-based transformation pipeline steps for Multi-Rename (`Section 3.6` of `BRIEF.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RenameRule {
    TextReplace {
        find: String,
        replace: String,
        case_sensitive: bool,
    },
    /// Matches a prefix + digits capture group (e.g. `IMG_(\d+)` -> `Vacation_$1`).
    DigitCaptureReplace {
        prefix: String,
        replacement_template: String,
    },
    CaseConversion(CaseConversionStyle),
    IncrementalCounter {
        prefix: String,
        suffix: String,
        start: usize,
        step: usize,
        padding: usize,
    },
    DateTimeInjection {
        prefix: String,
        formatted_timestamp: String,
    },
    ScopedReplaceText {
        scope: RenameTargetScope,
        occurrences: ReplaceOccurrences,
        find: String,
        replace: String,
        case_sensitive: bool,
    },
    ScopedChangeCase {
        scope: RenameTargetScope,
        style: CaseConversionStyle,
    },
    ScopedAddSequence {
        scope: RenameTargetScope,
        position: TextInsertionPosition,
        prefix: String,
        start: usize,
        step: usize,
        padding: usize,
    },
    ScopedAddText {
        scope: RenameTargetScope,
        position: TextInsertionPosition,
        text: String,
    },
    ScopedAddDate {
        scope: RenameTargetScope,
        position: TextInsertionPosition,
        formatted_timestamp: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenamePreviewItem {
    pub original_name: String,
    pub proposed_name: String,
    pub has_collision: bool,
}

/// Per-item metadata supplied to [`BatchRenamer::preview_with_metadata`] (`BUG-06`, `UI-07`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchRenameInputItem {
    pub name: String,
    pub is_dir: bool,
    pub modified_timestamp: Option<String>,
}

/// Prefix token used in [`RenameRule::ScopedAddDate`] to inject each file's own modified timestamp (`UI-07`).
pub const FILE_MODIFIED_TOKEN_PREFIX: &str = "__FILE_MODIFIED__:";

/// Maximum regular expression pattern length accepted by [`BatchRenamer`] (`2,048` chars).
pub const MAX_RENAME_REGEX_PATTERN_LEN: usize = 2048;

const REGEX_COMPILE_LIMIT_BYTES: usize = 2 * 1024 * 1024;

/// Multi-Rename engine applying a pipeline of [`RenameRule`]s with live collision validation (`BUG-06`).
pub struct BatchRenamer {
    pub rules: Vec<RenameRule>,
    pub case_insensitive_fs: bool,
}

impl BatchRenamer {
    pub fn new(rules: Vec<RenameRule>) -> Self {
        Self {
            rules,
            case_insensitive_fs: cfg!(any(target_os = "macos", target_os = "windows")),
        }
    }

    pub const fn with_case_insensitive(mut self, case_insensitive: bool) -> Self {
        self.case_insensitive_fs = case_insensitive;
        self
    }

    /// Evaluates the transformation pipeline over `original_names` and checks for collisions
    /// both within the batch and against `existing_directory_names`.
    pub fn preview(
        &self,
        original_names: &[String],
        existing_directory_names: &HashSet<String>,
    ) -> Vec<RenamePreviewItem> {
        let items: Vec<BatchRenameInputItem> = original_names
            .iter()
            .map(|n| BatchRenameInputItem {
                name: n.clone(),
                is_dir: false,
                modified_timestamp: None,
            })
            .collect();
        self.preview_with_metadata(&items, existing_directory_names)
    }

    /// Evaluates the transformation pipeline with directory awareness (`is_dir` skips extension splitting)
    /// and case-insensitive / Windows-safe collision validation (`BUG-06`).
    pub fn preview_with_dirs(
        &self,
        items: &[(String, bool)],
        existing_directory_names: &HashSet<String>,
    ) -> Vec<RenamePreviewItem> {
        let rich: Vec<BatchRenameInputItem> = items
            .iter()
            .map(|(n, is_dir)| BatchRenameInputItem {
                name: n.clone(),
                is_dir: *is_dir,
                modified_timestamp: None,
            })
            .collect();
        self.preview_with_metadata(&rich, existing_directory_names)
    }

    /// Evaluates the transformation pipeline with directory awareness and per-item modified timestamps (`UI-07`).
    pub fn preview_with_metadata(
        &self,
        items: &[BatchRenameInputItem],
        existing_directory_names: &HashSet<String>,
    ) -> Vec<RenamePreviewItem> {
        let norm_key = |s: &str| -> String {
            if self.case_insensitive_fs {
                s.to_lowercase()
            } else {
                s.to_string()
            }
        };
        let original_set: HashSet<String> = items.iter().map(|it| norm_key(&it.name)).collect();
        let existing_set: HashSet<String> = existing_directory_names
            .iter()
            .map(|n| norm_key(n))
            .collect();
        let mut proposed_list = Vec::with_capacity(items.len());
        let mut counts: HashMap<String, usize> = HashMap::new();

        for (index, item) in items.iter().enumerate() {
            let proposed = self.apply_to_entry_with_date(
                &item.name,
                index,
                item.is_dir,
                item.modified_timestamp.as_deref(),
            );
            *counts.entry(norm_key(&proposed)).or_insert(0) += 1;
            proposed_list.push((item.name.clone(), proposed));
        }

        proposed_list
            .into_iter()
            .map(|(original_name, proposed_name)| {
                let is_invalid = is_invalid_proposed_filename(&proposed_name);
                let prop_key = norm_key(&proposed_name);
                let orig_key = norm_key(&original_name);
                let duplicate_in_batch = counts.get(&prop_key).copied().unwrap_or(0) > 1;
                let collides_with_unselected = prop_key != orig_key
                    && existing_set.contains(&prop_key)
                    && !original_set.contains(&prop_key);
                RenamePreviewItem {
                    original_name,
                    proposed_name,
                    has_collision: is_invalid || duplicate_in_batch || collides_with_unselected,
                }
            })
            .collect()
    }

    pub fn apply_to_single_entry(&self, filename: &str, index: usize, is_dir: bool) -> String {
        self.apply_to_entry_with_date(filename, index, is_dir, None)
    }

    pub fn apply_to_entry_with_date(
        &self,
        filename: &str,
        index: usize,
        is_dir: bool,
        item_modified_timestamp: Option<&str>,
    ) -> String {
        let mut current = filename.to_string();

        for rule in &self.rules {
            let effective_scope = |s: RenameTargetScope| -> Option<RenameTargetScope> {
                if is_dir {
                    match s {
                        RenameTargetScope::Extension => None,
                        RenameTargetScope::Name | RenameTargetScope::NameWithExtension => {
                            Some(RenameTargetScope::NameWithExtension)
                        }
                    }
                } else {
                    Some(s)
                }
            };
            match rule {
                RenameRule::TextReplace {
                    find,
                    replace,
                    case_sensitive,
                } => {
                    if let Some(sc) = effective_scope(RenameTargetScope::Name) {
                        current = apply_scoped_transform(&current, sc, |part| {
                            apply_text_replace(
                                part,
                                ReplaceOccurrences::All,
                                find,
                                replace,
                                *case_sensitive,
                            )
                        });
                    }
                }
                RenameRule::DigitCaptureReplace {
                    prefix,
                    replacement_template,
                } => {
                    if let Some(sc) = effective_scope(RenameTargetScope::Name) {
                        current = apply_scoped_transform(&current, sc, |stem| {
                            if let Some(rest) = stem.strip_prefix(prefix) {
                                let digits: String =
                                    rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                                let tail: String =
                                    rest.chars().skip_while(|c| c.is_ascii_digit()).collect();
                                if !digits.is_empty() {
                                    let expanded = replacement_template.replace("$1", &digits);
                                    return format!("{expanded}{tail}");
                                }
                            }
                            stem.to_string()
                        });
                    }
                }
                RenameRule::CaseConversion(style) => {
                    if let Some(sc) = effective_scope(RenameTargetScope::Name) {
                        current = apply_scoped_transform(&current, sc, |part| {
                            apply_case_style(part, *style)
                        });
                    }
                }
                RenameRule::IncrementalCounter {
                    prefix,
                    suffix,
                    start,
                    step,
                    padding,
                } => {
                    if let Some(sc) = effective_scope(RenameTargetScope::Name) {
                        let num = start + index * step;
                        let formatted_num = format!("{num:0width$}", width = *padding);
                        current = apply_scoped_transform(&current, sc, |stem| {
                            format!("{prefix}{stem}_{formatted_num}{suffix}")
                        });
                    }
                }
                RenameRule::DateTimeInjection {
                    prefix,
                    formatted_timestamp,
                } => {
                    if let Some(sc) = effective_scope(RenameTargetScope::Name) {
                        let ts = resolve_date_token(formatted_timestamp, item_modified_timestamp);
                        current = apply_scoped_transform(&current, sc, |stem| {
                            format!("{prefix}{stem}_{ts}")
                        });
                    }
                }
                RenameRule::ScopedReplaceText {
                    scope,
                    occurrences,
                    find,
                    replace,
                    case_sensitive,
                } => {
                    if let Some(sc) = effective_scope(*scope) {
                        current = apply_scoped_transform(&current, sc, |part| {
                            apply_text_replace(part, *occurrences, find, replace, *case_sensitive)
                        });
                    }
                }
                RenameRule::ScopedChangeCase { scope, style } => {
                    if let Some(sc) = effective_scope(*scope) {
                        current = apply_scoped_transform(&current, sc, |part| {
                            apply_case_style(part, *style)
                        });
                    }
                }
                RenameRule::ScopedAddSequence {
                    scope,
                    position,
                    prefix,
                    start,
                    step,
                    padding,
                } => {
                    if let Some(sc) = effective_scope(*scope) {
                        let num = start + index * step;
                        let formatted_num = format!("{num:0width$}", width = (*padding).max(1));
                        let token = format!("{prefix}{formatted_num}");
                        current = apply_scoped_transform(&current, sc, |part| match position {
                            TextInsertionPosition::AfterName => format!("{part}{token}"),
                            TextInsertionPosition::BeforeName => format!("{token}{part}"),
                            TextInsertionPosition::ReplaceName => token,
                        });
                    }
                }
                RenameRule::ScopedAddText {
                    scope,
                    position,
                    text,
                } => {
                    if let Some(sc) = effective_scope(*scope) {
                        current = apply_scoped_transform(&current, sc, |part| match position {
                            TextInsertionPosition::AfterName => format!("{part}{text}"),
                            TextInsertionPosition::BeforeName => format!("{text}{part}"),
                            TextInsertionPosition::ReplaceName => text.clone(),
                        });
                    }
                }
                RenameRule::ScopedAddDate {
                    scope,
                    position,
                    formatted_timestamp,
                } => {
                    if let Some(sc) = effective_scope(*scope) {
                        let ts = resolve_date_token(formatted_timestamp, item_modified_timestamp);
                        current = apply_scoped_transform(&current, sc, |part| match position {
                            TextInsertionPosition::AfterName => {
                                if part.is_empty() {
                                    ts.to_string()
                                } else {
                                    format!("{part}_{ts}")
                                }
                            }
                            TextInsertionPosition::BeforeName => {
                                if part.is_empty() {
                                    ts.to_string()
                                } else {
                                    format!("{ts}_{part}")
                                }
                            }
                            TextInsertionPosition::ReplaceName => ts.to_string(),
                        });
                    }
                }
            }
        }

        current
    }
}

fn resolve_date_token<'a>(rule_ts: &'a str, item_modified_ts: Option<&'a str>) -> &'a str {
    if let Some(fallback) = rule_ts.strip_prefix(FILE_MODIFIED_TOKEN_PREFIX) {
        if let Some(ts) = item_modified_ts.filter(|s| !s.is_empty()) {
            if fallback.len() == 10 && ts.len() >= 10 {
                return &ts[..10];
            }
            return ts;
        }
        fallback
    } else {
        rule_ts
    }
}

fn is_invalid_proposed_filename(name: &str) -> bool {
    if name.trim().is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\0')
    {
        return true;
    }
    if cfg!(windows) {
        let has_win_invalid = name
            .chars()
            .any(|c| matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || c.is_control());
        if name.ends_with(' ') || name.ends_with('.') || has_win_invalid {
            return true;
        }
        let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
        if matches!(
            stem.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        ) {
            return true;
        }
    }
    false
}

fn split_stem_and_ext(filename: &str) -> (&str, Option<&str>) {
    let path = Path::new(filename);
    let ext = path.extension().and_then(|e| e.to_str());
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(filename);
    (stem, ext)
}

fn apply_scoped_transform<F>(filename: &str, scope: RenameTargetScope, transform: F) -> String
where
    F: FnOnce(&str) -> String,
{
    match scope {
        RenameTargetScope::NameWithExtension => transform(filename),
        RenameTargetScope::Name => {
            let (stem, ext) = split_stem_and_ext(filename);
            let new_stem = transform(stem);
            match ext {
                Some(e) if !e.is_empty() => format!("{new_stem}.{e}"),
                _ => new_stem,
            }
        }
        RenameTargetScope::Extension => {
            let (stem, ext) = split_stem_and_ext(filename);
            let new_ext = transform(ext.unwrap_or(""));
            let trimmed_ext = new_ext.trim_start_matches('.');
            if trimmed_ext.is_empty() {
                stem.to_string()
            } else {
                format!("{stem}.{trimmed_ext}")
            }
        }
    }
}

fn apply_case_style(input: &str, style: CaseConversionStyle) -> String {
    match style {
        CaseConversionStyle::UpperCase => input.to_uppercase(),
        CaseConversionStyle::LowerCase => input.to_lowercase(),
        CaseConversionStyle::TitleCase => input.to_title_case(),
        CaseConversionStyle::CamelCase => input.to_lower_camel_case(),
        CaseConversionStyle::KebabCase => input.to_kebab_case(),
        CaseConversionStyle::SnakeCase => input.to_snake_case(),
    }
}

fn build_bounded_regex(pattern: &str, case_insensitive: bool) -> Option<regex::Regex> {
    if pattern.is_empty() || pattern.len() > MAX_RENAME_REGEX_PATTERN_LEN {
        return None;
    }
    RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .size_limit(REGEX_COMPILE_LIMIT_BYTES)
        .dfa_size_limit(REGEX_COMPILE_LIMIT_BYTES)
        .build()
        .ok()
}

fn apply_text_replace(
    target: &str,
    occurrences: ReplaceOccurrences,
    find: &str,
    replace: &str,
    case_sensitive: bool,
) -> String {
    if find.is_empty() {
        return target.to_string();
    }
    match occurrences {
        ReplaceOccurrences::All => {
            if case_sensitive {
                target.replace(find, replace)
            } else {
                replace_case_insensitive(target, find, replace)
            }
        }
        ReplaceOccurrences::First => {
            if case_sensitive {
                target.replacen(find, replace, 1)
            } else {
                replace_first_case_insensitive(target, find, replace)
            }
        }
        ReplaceOccurrences::Last => replace_last(target, find, replace, case_sensitive),
        ReplaceOccurrences::RegularExpression => {
            let norm_rep = normalize_regex_replacement(replace);
            build_bounded_regex(find, !case_sensitive)
                .map(|re| re.replace_all(target, norm_rep.as_str()).into_owned())
                .unwrap_or_else(|| target.to_string())
        }
    }
}

fn normalize_regex_replacement(replace: &str) -> String {
    let mut out = String::with_capacity(replace.len() + 8);
    let mut chars = replace.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '$' {
            if let Some(&next_ch) = chars.peek() {
                if next_ch.is_ascii_digit() {
                    let digit = chars.next().unwrap();
                    out.push_str("${");
                    out.push(digit);
                    out.push('}');
                    continue;
                }
            }
        }
        out.push(ch);
    }
    out
}

fn replace_case_insensitive(haystack: &str, needle: &str, replacement: &str) -> String {
    let lower_h = haystack.to_lowercase();
    let lower_n = needle.to_lowercase();
    if lower_n.is_empty() || lower_h.len() != haystack.len() || lower_n.len() != needle.len() {
        return build_bounded_regex(&regex::escape(needle), true)
            .map(|re| {
                re.replace_all(haystack, regex::NoExpand(replacement))
                    .into_owned()
            })
            .unwrap_or_else(|| haystack.to_string());
    }
    let mut result = String::new();
    let mut last_end = 0;
    for (idx, _) in lower_h.match_indices(&lower_n) {
        result.push_str(&haystack[last_end..idx]);
        result.push_str(replacement);
        last_end = idx + needle.len();
    }
    result.push_str(&haystack[last_end..]);
    result
}

fn replace_first_case_insensitive(haystack: &str, needle: &str, replacement: &str) -> String {
    build_bounded_regex(&regex::escape(needle), true)
        .map(|re| {
            re.replace(haystack, regex::NoExpand(replacement))
                .into_owned()
        })
        .unwrap_or_else(|| haystack.to_string())
}

fn replace_last(haystack: &str, needle: &str, replacement: &str, case_sensitive: bool) -> String {
    if case_sensitive {
        if let Some(pos) = haystack.rfind(needle) {
            let mut out = String::with_capacity(haystack.len() + replacement.len());
            out.push_str(&haystack[..pos]);
            out.push_str(replacement);
            out.push_str(&haystack[pos + needle.len()..]);
            return out;
        }
        return haystack.to_string();
    }
    let Some(re) = build_bounded_regex(&regex::escape(needle), true) else {
        return haystack.to_string();
    };
    if let Some(m) = re.find_iter(haystack).last() {
        let mut out = String::with_capacity(haystack.len() + replacement.len());
        out.push_str(&haystack[..m.start()]);
        out.push_str(replacement);
        out.push_str(&haystack[m.end()..]);
        out
    } else {
        haystack.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use manifold_vfs::{ArchiveBackend, ArchiveFormat, ColorLabel, VolumeStats};

    #[test]
    fn test_directory_sync_sha256_changeset_and_execution() {
        let left = ArchiveBackend::new("left.zip", ArchiveFormat::Zip);
        let right = ArchiveBackend::new("right.zip", ArchiveFormat::Zip);

        left.write_bytes("/activate.php", b"v2").unwrap();
        left.write_bytes("/new_left.php", b"new").unwrap();
        right.write_bytes("/activate.php", b"v1").unwrap();
        right.write_bytes("/stale_right.php", b"old").unwrap();

        let plan = SyncExecutionPlan::build(
            &left,
            "/",
            &right,
            "/",
            SyncStrategy::LeftToRight,
            ComparisonMode::ContentHash,
        );
        let plan = plan.unwrap();

        assert_eq!(plan.entries.len(), 3);
        let outcome = plan.execute(&left, &right);
        assert!(outcome.error.is_none(), "sync failed: {:?}", outcome.error);
        let applied = outcome.applied;
        assert_eq!(applied, 3);

        assert_eq!(right.read_bytes("/activate.php").unwrap(), b"v2");
        assert_eq!(right.read_bytes("/new_left.php").unwrap(), b"new");
        assert!(right.metadata("/stale_right.php").is_err());
    }

    #[test]
    fn test_batch_renamer_capture_groups_case_and_collision_detection() {
        let renamer = BatchRenamer::new(vec![
            RenameRule::DigitCaptureReplace {
                prefix: "IMG_".to_string(),
                replacement_template: "Vacation_$1".to_string(),
            },
            RenameRule::CaseConversion(CaseConversionStyle::SnakeCase),
        ]);

        let names = ["IMG_0042.jpg".to_string(), "IMG_0043.jpg".to_string()];
        let existing = HashSet::from(["vacation_0043.jpg".to_string()]);

        let preview = renamer.preview(&names, &existing);
        assert_eq!(preview[0].proposed_name, "vacation_0042.jpg");
        assert!(!preview[0].has_collision);
        assert_eq!(preview[1].proposed_name, "vacation_0043.jpg");
        assert!(preview[1].has_collision);
    }

    #[test]
    fn test_scoped_regex_replace_and_multi_rule_pipeline() {
        let renamer = BatchRenamer::new(vec![RenameRule::ScopedReplaceText {
            scope: RenameTargetScope::NameWithExtension,
            occurrences: ReplaceOccurrences::RegularExpression,
            find: "100.*".to_string(),
            replace: "image".to_string(),
            case_sensitive: false,
        }]);
        let names = [
            "manifold_fig3.png".to_string(),
            "100baset hub.jpg".to_string(),
            "100baset hub copy.jpg".to_string(),
            "10700.jpg".to_string(),
        ];
        let existing = HashSet::new();
        let preview = renamer.preview(&names, &existing);
        assert_eq!(preview[0].proposed_name, "manifold_fig3.png");
        assert!(!preview[0].has_collision);
        assert_eq!(preview[1].proposed_name, "image");
        assert!(preview[1].has_collision);
        assert_eq!(preview[2].proposed_name, "image");
        assert!(preview[2].has_collision);
        assert_eq!(preview[3].proposed_name, "10700.jpg");
        assert!(!preview[3].has_collision);

        let seq_renamer = BatchRenamer::new(vec![
            RenameRule::ScopedReplaceText {
                scope: RenameTargetScope::Name,
                occurrences: ReplaceOccurrences::RegularExpression,
                find: r"^(\d+)\s+(.*)".to_string(),
                replace: "$2_$1".to_string(),
                case_sensitive: false,
            },
            RenameRule::ScopedAddSequence {
                scope: RenameTargetScope::Name,
                position: TextInsertionPosition::AfterName,
                prefix: "_v".to_string(),
                start: 1,
                step: 1,
                padding: 2,
            },
        ]);
        let seq_names = [
            "3174 cluster.jpg".to_string(),
            "3200 router.jpg".to_string(),
        ];
        let seq_preview = seq_renamer.preview(&seq_names, &existing);
        assert_eq!(seq_preview[0].proposed_name, "cluster_3174_v01.jpg");
        assert!(!seq_preview[0].has_collision);
        assert_eq!(seq_preview[1].proposed_name, "router_3200_v02.jpg");
        assert!(!seq_preview[1].has_collision);

        // Verify case-insensitive collision detection & directory dot preservation (BUG-06)
        let ci_renamer = BatchRenamer::new(vec![RenameRule::ScopedAddText {
            scope: RenameTargetScope::Name,
            position: TextInsertionPosition::AfterName,
            text: "_tag".to_string(),
        }])
        .with_case_insensitive(true);
        let dir_items = [
            ("v1.2.release".to_string(), true),
            ("Photo.jpg".to_string(), false),
        ];
        let existing_ci = HashSet::from(["PHOTO_TAG.JPG".to_string()]);
        let ci_prev = ci_renamer.preview_with_dirs(&dir_items, &existing_ci);
        assert_eq!(ci_prev[0].proposed_name, "v1.2.release_tag");
        assert!(!ci_prev[0].has_collision);
        assert_eq!(ci_prev[1].proposed_name, "Photo_tag.jpg");
        assert!(ci_prev[1].has_collision);
    }

    #[test]
    fn test_recursive_directory_sync_subfolders() {
        let left = ArchiveBackend::new("left.zip", ArchiveFormat::Zip);
        let right = ArchiveBackend::new("right.zip", ArchiveFormat::Zip);

        left.write_bytes("/sub/nested/app.rs", b"fn main() {}")
            .unwrap();
        right.write_bytes("/sub/old.txt", b"remove_me").unwrap();

        let plan = SyncExecutionPlan::build(
            &left,
            "/",
            &right,
            "/",
            SyncStrategy::LeftToRight,
            ComparisonMode::ContentHash,
        )
        .unwrap();
        let outcome = plan.execute(&left, &right);
        assert!(outcome.error.is_none(), "sync failed: {:?}", outcome.error);
        let applied = outcome.applied;
        assert!(applied >= 2);
        assert_eq!(
            right.read_bytes("/sub/nested/app.rs").unwrap(),
            b"fn main() {}"
        );
        assert!(right.metadata("/sub/old.txt").is_err());

        // Verify directory replacing a conflicting regular file + per-item modified dates + regex cap
        let left2 = ArchiveBackend::new("l2.zip", ArchiveFormat::Zip);
        let right2 = ArchiveBackend::new("r2.zip", ArchiveFormat::Zip);
        left2.write_bytes("/swap/inner.txt", b"hello").unwrap();
        right2.write_bytes("/swap", b"was_a_file").unwrap();
        let plan2 = SyncExecutionPlan::build(
            &left2,
            "/",
            &right2,
            "/",
            SyncStrategy::LeftToRight,
            ComparisonMode::Metadata,
        )
        .unwrap();
        assert!(plan2.execute(&left2, &right2).error.is_none());
        assert_eq!(right2.read_bytes("/swap/inner.txt").unwrap(), b"hello");

        let mod_renamer = BatchRenamer::new(vec![
            RenameRule::ScopedChangeCase {
                scope: RenameTargetScope::Extension,
                style: CaseConversionStyle::LowerCase,
            },
            RenameRule::ScopedAddDate {
                scope: RenameTargetScope::Name,
                position: TextInsertionPosition::AfterName,
                formatted_timestamp: format!("{FILE_MODIFIED_TOKEN_PREFIX}2026-01-01_00-00"),
            },
        ]);
        let meta_items = [
            BatchRenameInputItem {
                name: "Release.V2".to_string(),
                is_dir: true,
                modified_timestamp: Some("2025-07-04_14-30".to_string()),
            },
            BatchRenameInputItem {
                name: "Report.PDF".to_string(),
                is_dir: false,
                modified_timestamp: Some("2026-11-10_09-15".to_string()),
            },
        ];
        let meta_prev = mod_renamer.preview_with_metadata(&meta_items, &HashSet::new());
        assert_eq!(meta_prev[0].proposed_name, "Release.V2_2025-07-04_14-30");
        assert_eq!(meta_prev[1].proposed_name, "Report_2026-11-10_09-15.pdf");

        let huge_pat = "a".repeat(MAX_RENAME_REGEX_PATTERN_LEN + 10);
        let huge_renamer = BatchRenamer::new(vec![RenameRule::ScopedReplaceText {
            scope: RenameTargetScope::Name,
            occurrences: ReplaceOccurrences::RegularExpression,
            find: huge_pat,
            replace: "x".to_string(),
            case_sensitive: false,
        }]);
        assert_eq!(
            huge_renamer.apply_to_single_entry("aaa.txt", 0, false),
            "aaa.txt"
        );
    }

    #[test]
    fn sync_execute_streams_local_files_and_leaves_no_part_artifacts() {
        use manifold_vfs::LocalFsBackend;
        let ltmp = tempfile::tempdir().unwrap();
        let rtmp = tempfile::tempdir().unwrap();
        let left = LocalFsBackend::with_sandbox_root(ltmp.path()).unwrap();
        let right = LocalFsBackend::with_sandbox_root(rtmp.path()).unwrap();

        // 5 MiB payload crosses the 4 MiB chunk boundary.
        let payload: Vec<u8> = (0..5 * 1024 * 1024).map(|i| (i % 253) as u8).collect();
        left.write_bytes("big.bin", &payload).unwrap();
        left.write_bytes("small.txt", b"hi").unwrap();

        let plan = SyncExecutionPlan::build(
            &left,
            "/",
            &right,
            "/",
            SyncStrategy::LeftToRight,
            ComparisonMode::ContentHash,
        )
        .unwrap();
        let outcome = plan.execute(&left, &right);
        assert!(outcome.error.is_none(), "sync failed: {:?}", outcome.error);
        let applied = outcome.applied;
        assert!(applied >= 2);
        assert_eq!(right.read_bytes("big.bin").unwrap(), payload);
        assert_eq!(right.read_bytes("small.txt").unwrap(), b"hi");

        let parts: Vec<_> = std::fs::read_dir(rtmp.path())
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .contains("manifold-sync-part")
            })
            .collect();
        assert!(parts.is_empty(), "part artifacts left behind: {parts:?}");
    }

    #[test]
    fn sync_execute_replaces_target_directory_only_after_staging() {
        use manifold_vfs::LocalFsBackend;
        let ltmp = tempfile::tempdir().unwrap();
        let rtmp = tempfile::tempdir().unwrap();
        let left = LocalFsBackend::with_sandbox_root(ltmp.path()).unwrap();
        let right = LocalFsBackend::with_sandbox_root(rtmp.path()).unwrap();

        left.write_bytes("swap.txt", b"new-file-content").unwrap();
        right
            .write_bytes("swap.txt/old_inner.txt", b"old-dir-content")
            .unwrap();

        let plan = SyncExecutionPlan::build(
            &left,
            "/",
            &right,
            "/",
            SyncStrategy::LeftToRight,
            ComparisonMode::Metadata,
        )
        .unwrap();
        assert!(plan.execute(&left, &right).error.is_none());

        let meta = right.metadata("swap.txt").unwrap();
        assert!(!meta.is_dir, "target directory must have been replaced");
        assert_eq!(right.read_bytes("swap.txt").unwrap(), b"new-file-content");
    }

    #[cfg(unix)]
    #[test]
    fn sync_execute_reports_delete_failures_with_relative_path() {
        use manifold_vfs::LocalFsBackend;
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: permission bits ineffective as root");
            return;
        }
        let ltmp = tempfile::tempdir().unwrap();
        let rtmp = tempfile::tempdir().unwrap();
        let left = LocalFsBackend::with_sandbox_root(ltmp.path()).unwrap();
        let right = LocalFsBackend::with_sandbox_root(rtmp.path()).unwrap();

        // Right-only entry that must be deleted for mirroring; make the
        // deletion fail via a read-only parent directory.
        right.write_bytes("locked_dir/victim.txt", b"x").unwrap();
        std::fs::set_permissions(rtmp.path(), std::fs::Permissions::from_mode(0o500)).unwrap();

        let plan = SyncExecutionPlan::build(
            &left,
            "/",
            &right,
            "/",
            SyncStrategy::LeftToRight,
            ComparisonMode::Metadata,
        )
        .unwrap();
        let res = plan.execute(&left, &right);

        std::fs::set_permissions(rtmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let err = match res.error {
            None => {
                // Some filesystems/names may still allow the delete; then
                // there is nothing to assert beyond success.
                return;
            }
            Some(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("locked_dir"),
            "error must carry the relative path, got: {msg}"
        );
    }

    // ---- R01: destructive sync operations must never lose the target ----

    /// Wraps a `LocalFsBackend` and fails the Nth (1-based) call of the
    /// named operation with a synthetic I/O error (deterministic fault
    /// injection for the publish/rollback paths).
    struct FaultBackend {
        inner: manifold_vfs::LocalFsBackend,
        fail_create_dir: std::sync::Mutex<Vec<usize>>,
        fail_rename: std::sync::Mutex<Vec<usize>>,
        fail_remove: std::sync::Mutex<Vec<usize>>,
        fail_metadata: std::sync::atomic::AtomicBool,
        n_create_dir: std::sync::atomic::AtomicUsize,
        n_rename: std::sync::atomic::AtomicUsize,
        n_remove: std::sync::atomic::AtomicUsize,
    }

    impl FaultBackend {
        fn new(inner: manifold_vfs::LocalFsBackend) -> Self {
            Self {
                inner,
                fail_create_dir: std::sync::Mutex::new(Vec::new()),
                fail_rename: std::sync::Mutex::new(Vec::new()),
                fail_remove: std::sync::Mutex::new(Vec::new()),
                fail_metadata: std::sync::atomic::AtomicBool::new(false),
                n_create_dir: std::sync::atomic::AtomicUsize::new(0),
                n_rename: std::sync::atomic::AtomicUsize::new(0),
                n_remove: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn injected() -> manifold_vfs::VfsError {
            manifold_vfs::VfsError::IoError(std::io::Error::other("injected fault"))
        }
        fn route<T>(
            counter: &std::sync::atomic::AtomicUsize,
            failures: &std::sync::Mutex<Vec<usize>>,
            run: impl FnOnce() -> Result<T, manifold_vfs::VfsError>,
        ) -> Result<T, manifold_vfs::VfsError> {
            let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            if failures.lock().unwrap().contains(&n) {
                return Err(Self::injected());
            }
            run()
        }
    }

    impl manifold_vfs::FileSystemBackend for FaultBackend {
        fn scheme(&self) -> &str {
            "fault"
        }
        fn list_directory(&self, path: &str) -> Result<Vec<FileMetadata>, VfsError> {
            self.inner.list_directory(path)
        }
        fn metadata(&self, path: &str) -> Result<FileMetadata, VfsError> {
            if self.fail_metadata.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Self::injected());
            }
            self.inner.metadata(path)
        }
        fn volume_stats(&self, path: &str) -> Result<VolumeStats, VfsError> {
            self.inner.volume_stats(path)
        }
        fn create_dir(&self, path: &str) -> Result<(), VfsError> {
            Self::route(&self.n_create_dir, &self.fail_create_dir, || {
                self.inner.create_dir(path)
            })
        }
        fn remove(&self, path: &str, recursive: bool) -> Result<(), VfsError> {
            Self::route(&self.n_remove, &self.fail_remove, || {
                self.inner.remove(path, recursive)
            })
        }
        fn rename(&self, from: &str, to: &str) -> Result<(), VfsError> {
            Self::route(&self.n_rename, &self.fail_rename, || {
                self.inner.rename(from, to)
            })
        }
        fn copy_file(&self, from: &str, to: &str) -> Result<(), VfsError> {
            self.inner.copy_file(from, to)
        }
        fn read_bytes(&self, path: &str) -> Result<Vec<u8>, VfsError> {
            self.inner.read_bytes(path)
        }
        fn read_range(&self, path: &str, offset: u64, length: usize) -> Result<Vec<u8>, VfsError> {
            self.inner.read_range(path, offset, length)
        }
        fn supports_chunked_io(&self) -> bool {
            self.inner.supports_chunked_io()
        }
        fn write_bytes(&self, path: &str, data: &[u8]) -> Result<(), VfsError> {
            self.inner.write_bytes(path, data)
        }
        fn append_bytes(&self, path: &str, data: &[u8]) -> Result<(), VfsError> {
            self.inner.append_bytes(path, data)
        }
        fn set_permissions(&self, path: &str, mode: u32) -> Result<(), VfsError> {
            self.inner.set_permissions(path, mode)
        }
        fn set_color_label(&self, path: &str, label: ColorLabel) -> Result<(), VfsError> {
            self.inner.set_color_label(path, label)
        }
        fn set_hide_extension(&self, path: &str, hide: bool) -> Result<(), VfsError> {
            self.inner.set_hide_extension(path, hide)
        }
        fn set_locked(&self, path: &str, locked: bool) -> Result<(), VfsError> {
            self.inner.set_locked(path, locked)
        }
    }

    fn plan_l2r(left: &dyn FileSystemBackend, right: &dyn FileSystemBackend) -> SyncExecutionPlan {
        SyncExecutionPlan::build(
            left,
            "/",
            right,
            "/",
            SyncStrategy::LeftToRight,
            ComparisonMode::Metadata,
        )
        .unwrap()
    }

    #[test]
    fn sync_preserves_directory_when_file_publish_fails() {
        let ltmp = tempfile::tempdir().unwrap();
        let rtmp = tempfile::tempdir().unwrap();
        let left = manifold_vfs::LocalFsBackend::with_sandbox_root(ltmp.path()).unwrap();
        let right = manifold_vfs::LocalFsBackend::with_sandbox_root(rtmp.path()).unwrap();
        left.write_bytes("victim.txt", b"new-file-content").unwrap();
        right
            .write_bytes("victim.txt/old.txt", b"old-content")
            .unwrap();

        let plan = plan_l2r(&left, &right);
        let fault = FaultBackend::new(
            manifold_vfs::LocalFsBackend::with_sandbox_root(rtmp.path()).unwrap(),
        );
        // rename #1 = move-aside (ok), #2 = publish (fail), #3 = rollback (ok).
        *fault.fail_rename.lock().unwrap() = vec![2];

        let outcome = plan.execute(&left, &fault);
        let err = outcome.error.expect("publish failure must be reported");
        assert!(
            err.to_string().contains("original directory was restored"),
            "got: {err}"
        );
        // The directory and its content survived the failed replacement.
        assert_eq!(
            right.read_bytes("victim.txt/old.txt").unwrap(),
            b"old-content",
            "directory content must survive a failed publish"
        );
        // Rollback left no retired backup behind.
        let leftovers: Vec<_> = std::fs::read_dir(rtmp.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".manifold-old-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "rollback must not leave backups: {leftovers:?}"
        );
    }

    #[test]
    fn sync_preserves_file_when_directory_creation_fails() {
        let ltmp = tempfile::tempdir().unwrap();
        let rtmp = tempfile::tempdir().unwrap();
        let left = manifold_vfs::LocalFsBackend::with_sandbox_root(ltmp.path()).unwrap();
        let right = manifold_vfs::LocalFsBackend::with_sandbox_root(rtmp.path()).unwrap();
        left.create_dir("swap").unwrap();
        left.write_bytes("swap/inner.txt", b"hello").unwrap();
        right.write_bytes("swap", b"was_a_file").unwrap();

        let plan = plan_l2r(&left, &right);
        let fault = FaultBackend::new(
            manifold_vfs::LocalFsBackend::with_sandbox_root(rtmp.path()).unwrap(),
        );
        *fault.fail_create_dir.lock().unwrap() = vec![1];

        let outcome = plan.execute(&left, &fault);
        let err = outcome.error.expect("create_dir failure must be reported");
        assert!(
            err.to_string().contains("original file was restored"),
            "got: {err}"
        );
        let meta = right.metadata("swap").unwrap();
        assert!(!meta.is_dir, "the original file must be back in place");
        assert_eq!(right.read_bytes("swap").unwrap(), b"was_a_file");
    }

    #[test]
    fn sync_restores_original_after_failed_replacement() {
        // Same scenario as the publish-failure test but verifies the
        // restored directory stays fully usable afterwards.
        let ltmp = tempfile::tempdir().unwrap();
        let rtmp = tempfile::tempdir().unwrap();
        let left = manifold_vfs::LocalFsBackend::with_sandbox_root(ltmp.path()).unwrap();
        let right = manifold_vfs::LocalFsBackend::with_sandbox_root(rtmp.path()).unwrap();
        left.write_bytes("victim.txt", b"new").unwrap();
        right.write_bytes("victim.txt/a.txt", b"AA").unwrap();
        right.write_bytes("victim.txt/b.txt", b"BB").unwrap();

        let plan = plan_l2r(&left, &right);
        let fault = FaultBackend::new(
            manifold_vfs::LocalFsBackend::with_sandbox_root(rtmp.path()).unwrap(),
        );
        *fault.fail_rename.lock().unwrap() = vec![2];
        assert!(plan.execute(&left, &fault).error.is_some());

        assert_eq!(right.read_bytes("victim.txt/a.txt").unwrap(), b"AA");
        assert_eq!(right.read_bytes("victim.txt/b.txt").unwrap(), b"BB");
        // A second, working attempt now succeeds with the same plan.
        let ok = plan.execute(&left, &right);
        assert!(ok.error.is_none(), "{:?}", ok.error);
        assert_eq!(right.read_bytes("victim.txt").unwrap(), b"new");
    }

    #[test]
    fn sync_reports_rollback_failure_without_deleting_backup() {
        let ltmp = tempfile::tempdir().unwrap();
        let rtmp = tempfile::tempdir().unwrap();
        let left = manifold_vfs::LocalFsBackend::with_sandbox_root(ltmp.path()).unwrap();
        let right = manifold_vfs::LocalFsBackend::with_sandbox_root(rtmp.path()).unwrap();
        left.write_bytes("victim.txt", b"new").unwrap();
        right
            .write_bytes("victim.txt/old.txt", b"old-content")
            .unwrap();

        let plan = plan_l2r(&left, &right);
        let fault = FaultBackend::new(
            manifold_vfs::LocalFsBackend::with_sandbox_root(rtmp.path()).unwrap(),
        );
        // Publish (#2) AND rollback (#3) both fail.
        *fault.fail_rename.lock().unwrap() = vec![2, 3];

        let outcome = plan.execute(&left, &fault);
        let err = outcome.error.expect("double failure must be reported");
        let msg = err.to_string();
        assert!(
            msg.contains("restoring the original directory failed"),
            "got: {msg}"
        );
        assert!(
            msg.contains("manifold-old"),
            "error must name the backup: {msg}"
        );
        // The retired backup directory still holds the original content.
        let backups: Vec<_> = std::fs::read_dir(rtmp.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".manifold-old-"))
            .collect();
        assert_eq!(backups.len(), 1, "exactly one backup must remain");
        let bak = backups[0].path().join("old.txt");
        assert_eq!(std::fs::read(&bak).unwrap(), b"old-content");
    }

    #[test]
    fn sync_does_not_overwrite_concurrently_created_destination() {
        let ltmp = tempfile::tempdir().unwrap();
        let rtmp = tempfile::tempdir().unwrap();
        let left = manifold_vfs::LocalFsBackend::with_sandbox_root(ltmp.path()).unwrap();
        let right = manifold_vfs::LocalFsBackend::with_sandbox_root(rtmp.path()).unwrap();
        left.write_bytes("c.txt", b"planned-new").unwrap();

        let mut plan = plan_l2r(&left, &right);
        for e in &mut plan.entries {
            e.approved = true;
        }
        assert!(
            plan.entries
                .iter()
                .any(|e| e.relative_path == "c.txt" && e.right_meta.is_none()),
            "plan must expect c.txt to be absent"
        );
        // A different process creates the destination after planning.
        right.write_bytes("c.txt", b"foreign-content").unwrap();

        let outcome = plan.execute(&left, &right);
        let err = outcome.error.expect("concurrent creation must be refused");
        assert!(err.to_string().contains("appeared"), "got: {err}");
        assert_eq!(
            right.read_bytes("c.txt").unwrap(),
            b"foreign-content",
            "the foreign destination must not be touched"
        );
    }

    #[test]
    fn sync_reports_partial_completion_accurately() {
        let ltmp = tempfile::tempdir().unwrap();
        let rtmp = tempfile::tempdir().unwrap();
        let left = manifold_vfs::LocalFsBackend::with_sandbox_root(ltmp.path()).unwrap();
        let right = manifold_vfs::LocalFsBackend::with_sandbox_root(rtmp.path()).unwrap();
        left.write_bytes("a.txt", b"1").unwrap();
        left.write_bytes("b.txt", b"2").unwrap();

        let plan = plan_l2r(&left, &right);
        let fault = FaultBackend::new(
            manifold_vfs::LocalFsBackend::with_sandbox_root(rtmp.path()).unwrap(),
        );
        // Entry a publishes via rename #1 (ok); entry b fails on rename #2.
        *fault.fail_rename.lock().unwrap() = vec![2];

        let outcome = plan.execute(&left, &fault);
        assert_eq!(
            outcome.applied, 1,
            "exactly one entry applied before failure"
        );
        let err = outcome.error.expect("failure must be reported");
        assert!(
            err.to_string().contains("b.txt"),
            "error names the entry: {err}"
        );
        assert_eq!(fault.read_bytes("a.txt").unwrap(), b"1");
        assert!(
            right.metadata("b.txt").is_err(),
            "b.txt must not be published"
        );
    }

    // ---- R05: streaming must check the right capability and size 0 ----

    /// Wraps a local backend but reports chunked I/O as unsupported and
    /// counts whole-file reads, simulating a remote source whose default
    /// `read_range` implementation re-reads the entire file.
    struct CountingSrcBackend {
        inner: manifold_vfs::LocalFsBackend,
        n_read_bytes: std::sync::atomic::AtomicUsize,
    }

    impl CountingSrcBackend {
        fn new(inner: manifold_vfs::LocalFsBackend) -> Self {
            Self {
                inner,
                n_read_bytes: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    impl manifold_vfs::FileSystemBackend for CountingSrcBackend {
        fn scheme(&self) -> &str {
            "counting"
        }
        fn list_directory(&self, path: &str) -> Result<Vec<FileMetadata>, VfsError> {
            self.inner.list_directory(path)
        }
        fn metadata(&self, path: &str) -> Result<FileMetadata, VfsError> {
            self.inner.metadata(path)
        }
        fn volume_stats(&self, path: &str) -> Result<VolumeStats, VfsError> {
            self.inner.volume_stats(path)
        }
        fn create_dir(&self, path: &str) -> Result<(), VfsError> {
            self.inner.create_dir(path)
        }
        fn remove(&self, path: &str, recursive: bool) -> Result<(), VfsError> {
            self.inner.remove(path, recursive)
        }
        fn rename(&self, from: &str, to: &str) -> Result<(), VfsError> {
            self.inner.rename(from, to)
        }
        fn copy_file(&self, from: &str, to: &str) -> Result<(), VfsError> {
            self.inner.copy_file(from, to)
        }
        fn read_bytes(&self, path: &str) -> Result<Vec<u8>, VfsError> {
            self.n_read_bytes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.read_bytes(path)
        }
        fn supports_chunked_io(&self) -> bool {
            false
        }
        fn write_bytes(&self, path: &str, data: &[u8]) -> Result<(), VfsError> {
            self.inner.write_bytes(path, data)
        }
        fn set_permissions(&self, path: &str, mode: u32) -> Result<(), VfsError> {
            self.inner.set_permissions(path, mode)
        }
        fn set_color_label(&self, path: &str, label: ColorLabel) -> Result<(), VfsError> {
            self.inner.set_color_label(path, label)
        }
        fn set_hide_extension(&self, path: &str, hide: bool) -> Result<(), VfsError> {
            self.inner.set_hide_extension(path, hide)
        }
        fn set_locked(&self, path: &str, locked: bool) -> Result<(), VfsError> {
            self.inner.set_locked(path, locked)
        }
    }

    #[test]
    fn sync_buffers_once_when_source_lacks_chunked_io() {
        let ltmp = tempfile::tempdir().unwrap();
        let rtmp = tempfile::tempdir().unwrap();
        let left = manifold_vfs::LocalFsBackend::with_sandbox_root(ltmp.path()).unwrap();
        let right = manifold_vfs::LocalFsBackend::with_sandbox_root(rtmp.path()).unwrap();
        // Larger than the 4 MiB chunk size: the old code streamed from the
        // non-chunked source and re-read the whole file once per chunk.
        let payload = vec![7u8; 4 * 1024 * 1024 + 1];
        left.write_bytes("big.bin", &payload).unwrap();

        let plan = plan_l2r(&left, &right);
        let counting = CountingSrcBackend::new(
            manifold_vfs::LocalFsBackend::with_sandbox_root(ltmp.path()).unwrap(),
        );
        let outcome = plan.execute(&counting, &right);
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        assert_eq!(
            counting
                .n_read_bytes
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a source without chunked I/O must be buffered exactly once"
        );
        assert_eq!(right.read_bytes("big.bin").unwrap(), payload);
    }

    #[test]
    fn sync_fails_when_source_metadata_unavailable() {
        let ltmp = tempfile::tempdir().unwrap();
        let rtmp = tempfile::tempdir().unwrap();
        let left = manifold_vfs::LocalFsBackend::with_sandbox_root(ltmp.path()).unwrap();
        let right = manifold_vfs::LocalFsBackend::with_sandbox_root(rtmp.path()).unwrap();
        left.write_bytes("x.txt", b"content").unwrap();

        let plan = plan_l2r(&left, &right);
        let fault_src = FaultBackend::new(
            manifold_vfs::LocalFsBackend::with_sandbox_root(ltmp.path()).unwrap(),
        );
        fault_src
            .fail_metadata
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let outcome = plan.execute(&fault_src, &right);
        assert!(
            outcome.error.is_some(),
            "an unreadable source must fail, not publish unvalidated"
        );
        assert!(
            right.metadata("x.txt").is_err(),
            "nothing may be published when the source size is unknown"
        );
    }

    #[test]
    fn sync_handles_empty_file() {
        let ltmp = tempfile::tempdir().unwrap();
        let rtmp = tempfile::tempdir().unwrap();
        let left = manifold_vfs::LocalFsBackend::with_sandbox_root(ltmp.path()).unwrap();
        let right = manifold_vfs::LocalFsBackend::with_sandbox_root(rtmp.path()).unwrap();
        left.write_bytes("empty.txt", b"").unwrap();

        let plan = plan_l2r(&left, &right);
        let outcome = plan.execute(&left, &right);
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        let meta = right.metadata("empty.txt").unwrap();
        assert_eq!(meta.size, Some(0), "the empty file must be copied as such");
    }
}
