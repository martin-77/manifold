use super::*;

pub(super) fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut star_ti) = (None::<usize>, 0usize);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

pub(super) fn matches_search_query_str(file_name: &str, q_low: &str) -> bool {
    if q_low.is_empty() {
        return true;
    }
    let name = file_name.to_lowercase();
    if q_low.contains('*') || q_low.contains('?') {
        let anchored = format!("*{q_low}*");
        wildcard_match(q_low, &name) || wildcard_match(&anchored, &name)
    } else if q_low.contains(' ') {
        q_low.split_whitespace().all(|tok| name.contains(tok))
    } else {
        name.contains(q_low)
    }
}

pub(super) fn matches_search_query_lower(meta: &FileMetadata, q_low: &str) -> bool {
    matches_search_query_str(&meta.name, q_low)
}

#[cfg(test)]
pub(super) fn matches_search_query(meta: &FileMetadata, query: &str) -> bool {
    let q_low = query.trim().to_lowercase();
    matches_search_query_lower(meta, &q_low)
}

#[cfg(unix)]
pub(super) fn record_visited_dir(path: &Path, visited: &mut HashSet<(u64, u64)>) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    visited.insert((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
pub(super) fn record_visited_dir(_path: &Path, _visited: &mut HashSet<(u64, u64)>) -> bool {
    true
}

pub(super) struct LocalBfsSearchParams<'a> {
    pub(super) is_right: bool,
    pub(super) my_gen: u64,
    pub(super) gen_arc: &'a Arc<AtomicU64>,
    pub(super) root_dir: &'a str,
    pub(super) q_low: &'a str,
    pub(super) show_hidden: bool,
    pub(super) color_labels: &'a HashMap<String, ColorLabel>,
    pub(super) tx: &'a mpsc::Sender<BgSearchEvent>,
}

pub(super) fn run_local_recursive_bfs_search(params: LocalBfsSearchParams<'_>) {
    const MAX_SEARCH_DEPTH: usize = 16;
    const MAX_SEARCH_RESULTS: usize = 2500;
    const BATCH_LIMIT: usize = 64;

    let LocalBfsSearchParams {
        is_right,
        my_gen,
        gen_arc,
        root_dir,
        q_low,
        show_hidden,
        color_labels,
        tx,
    } = params;

    if q_low.is_empty() || gen_arc.load(Ordering::Relaxed) != my_gen {
        return;
    }

    let local_vfs = LocalFsBackend::new();
    local_vfs.restore_color_labels(color_labels);
    let mut visited: HashSet<(u64, u64)> = HashSet::new();
    let root_pb = PathBuf::from(root_dir);
    let _ = record_visited_dir(&root_pb, &mut visited);

    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
    if let Ok(rd) = std::fs::read_dir(&root_pb) {
        for entry in rd.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if !ft.is_dir() || ft.is_symlink() {
                continue;
            }
            let name_os = entry.file_name();
            let name_str = name_os.to_string_lossy();
            if !show_hidden && name_str.starts_with('.') {
                continue;
            }
            let sub_path = entry.path();
            if record_visited_dir(&sub_path, &mut visited) {
                queue.push_back((sub_path, 1));
            }
        }
    }

    let mut total_found = 0usize;
    let mut batch: Vec<FileMetadata> = Vec::with_capacity(BATCH_LIMIT);
    let mut last_flush = Instant::now();
    let mut step_counter = 0usize;

    while let Some((dir_pb, depth)) = queue.pop_front() {
        if gen_arc.load(Ordering::Relaxed) != my_gen {
            return;
        }
        let Ok(rd) = std::fs::read_dir(&dir_pb) else {
            continue;
        };

        for entry in rd.flatten() {
            step_counter = step_counter.wrapping_add(1);
            if step_counter.is_multiple_of(64) && gen_arc.load(Ordering::Relaxed) != my_gen {
                return;
            }

            let name_os = entry.file_name();
            let name_str = name_os.to_string_lossy();
            if !show_hidden && name_str.starts_with('.') {
                continue;
            }

            let Ok(ft) = entry.file_type() else {
                continue;
            };
            let entry_path = entry.path();

            if matches_search_query_str(&name_str, q_low) {
                let p_str = entry_path.to_string_lossy().to_string();
                if let Ok(meta) = local_vfs.metadata(&p_str) {
                    batch.push(meta);
                    total_found += 1;
                    if batch.len() >= BATCH_LIMIT
                        || last_flush.elapsed() >= Duration::from_millis(45)
                    {
                        let items = std::mem::take(&mut batch);
                        if tx
                            .send(BgSearchEvent::Batch {
                                is_right,
                                gen_id: my_gen,
                                items,
                            })
                            .is_err()
                        {
                            return;
                        }
                        last_flush = Instant::now();
                    }
                    if total_found >= MAX_SEARCH_RESULTS {
                        break;
                    }
                }
            }

            let is_app_bundle =
                is_macos_app_bundle_for_os(&name_str, ft.is_dir(), cfg!(target_os = "macos"));
            if ft.is_dir()
                && !ft.is_symlink()
                && !is_app_bundle
                && depth < MAX_SEARCH_DEPTH
                && record_visited_dir(&entry_path, &mut visited)
            {
                queue.push_back((entry_path, depth + 1));
            }
        }

        if total_found >= MAX_SEARCH_RESULTS {
            break;
        }
    }

    if gen_arc.load(Ordering::Relaxed) != my_gen {
        return;
    }
    if !batch.is_empty() {
        let _ = tx.send(BgSearchEvent::Batch {
            is_right,
            gen_id: my_gen,
            items: batch,
        });
    }
    let _ = tx.send(BgSearchEvent::Finished {
        is_right,
        gen_id: my_gen,
    });
}

pub(super) fn is_macos_app_bundle_for_os(name: &str, is_dir: bool, is_macos: bool) -> bool {
    is_macos && is_dir && name.to_ascii_lowercase().ends_with(".app")
}

pub(super) fn is_macos_app_bundle(meta: &FileMetadata) -> bool {
    is_macos_app_bundle_for_os(&meta.name, meta.is_dir, cfg!(target_os = "macos"))
}

pub(super) fn is_browsable_folder(meta: &FileMetadata) -> bool {
    is_browsable_folder_with_opts(meta, false)
}

pub(super) fn is_browsable_folder_with_opts(
    meta: &FileMetadata,
    treat_packages_as_folders: bool,
) -> bool {
    meta.is_dir && (treat_packages_as_folders || !is_macos_app_bundle(meta))
}

fn cmp_case_insensitive_str(a: &str, b: &str) -> std::cmp::Ordering {
    a.chars()
        .flat_map(char::to_lowercase)
        .cmp(b.chars().flat_map(char::to_lowercase))
        .then_with(|| a.cmp(b))
}

#[cfg(test)]
pub(super) fn sort_metadata_slice(
    items: &mut [FileMetadata],
    column: SortColumn,
    direction: SortDirection,
) {
    sort_metadata_slice_with_options(items, column, direction, true, false, false);
}

pub(super) fn sort_metadata_slice_with_options(
    items: &mut [FileMetadata],
    column: SortColumn,
    direction: SortDirection,
    show_folders_on_top: bool,
    folders_always_alpha: bool,
    treat_packages_as_folders: bool,
) {
    let desc = direction == SortDirection::Descending;
    let folder_group = |a: &FileMetadata| -> bool {
        if show_folders_on_top {
            !is_browsable_folder_with_opts(a, treat_packages_as_folders)
        } else {
            false
        }
    };
    items.sort_by(|a, b| {
        let fg = folder_group(a).cmp(&folder_group(b));
        if fg != std::cmp::Ordering::Equal {
            return fg;
        }
        let primary = match column {
            SortColumn::Size => a
                .size
                .unwrap_or(0)
                .cmp(&b.size.unwrap_or(0))
                .then_with(|| cmp_case_insensitive_str(&a.name, &b.name)),
            SortColumn::Modified => a
                .modified
                .cmp(&b.modified)
                .then_with(|| cmp_case_insensitive_str(&a.name, &b.name)),
            SortColumn::Created => a
                .created
                .or(a.modified)
                .cmp(&b.created.or(b.modified))
                .then_with(|| cmp_case_insensitive_str(&a.name, &b.name)),
            SortColumn::Added => a
                .added
                .or(a.created)
                .or(a.modified)
                .cmp(&b.added.or(b.created).or(b.modified))
                .then_with(|| cmp_case_insensitive_str(&a.name, &b.name)),
            SortColumn::Kind => cmp_case_insensitive_str(&a.kind, &b.kind)
                .then_with(|| cmp_case_insensitive_str(&a.name, &b.name)),
            SortColumn::Permissions => a
                .permissions
                .cmp(&b.permissions)
                .then_with(|| cmp_case_insensitive_str(&a.name, &b.name)),
            _ => cmp_case_insensitive_str(&a.name, &b.name),
        };
        if desc {
            primary.reverse()
        } else {
            primary
        }
    });

    if show_folders_on_top && folders_always_alpha {
        let dir_count = items
            .iter()
            .take_while(|m| is_browsable_folder_with_opts(m, treat_packages_as_folders))
            .count();
        if dir_count > 1 {
            items[..dir_count].sort_by(|a, b| cmp_case_insensitive_str(&a.name, &b.name));
        }
    }
}

pub(super) fn is_image_extension(ext: Option<&str>) -> bool {
    let Some(e) = ext else {
        return false;
    };
    matches!(
        e.to_ascii_lowercase().as_str(),
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "svg" | "heic" | "bmp" | "tiff" | "ico"
    )
}

pub(super) fn format_ext_badge(ext: Option<&str>) -> String {
    let Some(e) = ext else {
        return String::new();
    };
    e.chars().take(4).collect::<String>().to_ascii_uppercase()
}

pub(super) fn color_label_to_slint_color(label: ColorLabel) -> Color {
    match label {
        ColorLabel::None => Color::from_argb_u8(0, 0, 0, 0),
        ColorLabel::Gray => Color::from_rgb_u8(0x8E, 0x8E, 0x93),
        ColorLabel::Green => Color::from_rgb_u8(0x5A, 0xC8, 0x5A),
        ColorLabel::Purple => Color::from_rgb_u8(0xAF, 0x52, 0xDE),
        ColorLabel::Blue => Color::from_rgb_u8(0x0A, 0x84, 0xFF),
        ColorLabel::Yellow => Color::from_rgb_u8(0xFF, 0xD6, 0x0A),
        ColorLabel::Red => Color::from_rgb_u8(0xFF, 0x45, 0x3A),
        ColorLabel::Orange => Color::from_rgb_u8(0xFF, 0x9F, 0x0A),
    }
}

pub(super) fn color_label_to_tint_color(label: ColorLabel) -> Color {
    match label {
        ColorLabel::None => Color::from_argb_u8(0, 0, 0, 0),
        ColorLabel::Gray => Color::from_argb_u8(0x2A, 0x8E, 0x8E, 0x93),
        ColorLabel::Green => Color::from_argb_u8(0x2A, 0x5A, 0xC8, 0x5A),
        ColorLabel::Purple => Color::from_argb_u8(0x2A, 0xAF, 0x52, 0xDE),
        ColorLabel::Blue => Color::from_argb_u8(0x2A, 0x0A, 0x84, 0xFF),
        ColorLabel::Yellow => Color::from_argb_u8(0x2A, 0xFF, 0xD6, 0x0A),
        ColorLabel::Red => Color::from_argb_u8(0x2A, 0xFF, 0x45, 0x3A),
        ColorLabel::Orange => Color::from_argb_u8(0x2A, 0xFF, 0x9F, 0x0A),
    }
}

pub(super) fn color_label_to_name(label: ColorLabel) -> &'static str {
    match label {
        ColorLabel::None => "",
        ColorLabel::Gray => "Gray",
        ColorLabel::Green => "Green",
        ColorLabel::Purple => "Purple",
        ColorLabel::Blue => "Blue",
        ColorLabel::Yellow => "Yellow",
        ColorLabel::Red => "Red",
        ColorLabel::Orange => "Orange",
    }
}

pub(super) fn color_label_to_index(label: ColorLabel) -> i32 {
    match label {
        ColorLabel::None => 0,
        ColorLabel::Gray => 1,
        ColorLabel::Green => 2,
        ColorLabel::Purple => 3,
        ColorLabel::Blue => 4,
        ColorLabel::Yellow => 5,
        ColorLabel::Red => 6,
        ColorLabel::Orange => 7,
    }
}

pub(super) fn index_to_color_label(idx: i32) -> ColorLabel {
    let swatches = ColorLabel::all_swatches();
    match swatches.get(idx as usize) {
        Some(color) => *color,
        None => ColorLabel::None,
    }
}

pub(super) fn split_archive_uri(path: &str) -> Option<(String, String)> {
    let rest = path.strip_prefix("archive://")?;
    let (arch_path, inner) = rest.split_once('#').unwrap_or((rest, "/"));
    if arch_path.is_empty() {
        return None;
    }
    let norm_inner = format!("/{}", inner.trim_start_matches('/'));
    Some((arch_path.to_string(), norm_inner))
}

pub(super) fn split_remote_uri(path: &str) -> Option<(String, String)> {
    let (scheme, rest) = path.split_once("://")?;
    if matches!(scheme, "file" | "connect" | "archive") {
        return None;
    }
    match rest.split_once('/') {
        Some((auth, sub)) => {
            let prefix = format!("{scheme}://{auth}");
            let remote_path = format!("/{}", sub.trim_start_matches('/'));
            Some((prefix, remote_path))
        }
        None => {
            let prefix = format!("{scheme}://{rest}");
            Some((prefix, "/".to_string()))
        }
    }
}

pub(super) fn vfs_display_title(path: &str) -> String {
    if let Some((arch_path, inner)) = split_archive_uri(path) {
        if inner != "/" {
            if let Some(leaf) = Path::new(&inner)
                .file_name()
                .and_then(|n| n.to_str())
                .filter(|s| !s.is_empty())
            {
                return leaf.to_string();
            }
        }
        return Path::new(&arch_path)
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("Archive")
            .to_string();
    }
    if let Some((prefix, sub)) = split_remote_uri(path) {
        let leaf = Path::new(&sub)
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|s| !s.is_empty());
        if let Some(name) = leaf {
            return name.to_string();
        }
        return prefix
            .split_once("://")
            .map(|(_, auth)| auth.to_string())
            .unwrap_or_else(|| prefix.clone());
    }
    Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("/")
        .to_string()
}

pub(super) fn vfs_file_name(path: &str) -> String {
    if let Some((arch_path, inner)) = split_archive_uri(path) {
        let target = if inner == "/" { &arch_path } else { &inner };
        return Path::new(target)
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("item")
            .to_string();
    }
    if let Some((_, sub)) = split_remote_uri(path) {
        return Path::new(&sub)
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("item")
            .to_string();
    }
    Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("item")
        .to_string()
}

pub(super) fn vfs_parent_dir(path: &str) -> Option<String> {
    if let Some((arch_path, inner)) = split_archive_uri(path) {
        if inner == "/" || inner.is_empty() {
            return vfs_parent_dir(&arch_path);
        }
        let parent = Path::new(&inner)
            .parent()
            .and_then(|p| p.to_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("/");
        if parent == "/" {
            return Some(format!("archive://{arch_path}#/"));
        }
        return Some(format!("archive://{arch_path}#{parent}"));
    }
    if let Some((prefix, sub)) = split_remote_uri(path) {
        if sub == "/" || sub.is_empty() {
            return Some(format!("{prefix}/"));
        }
        let parent = Path::new(&sub)
            .parent()
            .and_then(|p| p.to_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("/");
        if parent == "/" {
            return Some(format!("{prefix}/"));
        }
        return Some(format!("{prefix}{parent}"));
    }
    Path::new(path)
        .parent()
        .and_then(|p| p.to_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| Some("/".to_string()))
}

pub(super) fn join_vfs_path(dir: &str, name: &str) -> String {
    let trimmed_name = name.trim_start_matches('/');
    if let Some((arch_path, inner)) = split_archive_uri(dir) {
        let trimmed_inner = inner.trim_end_matches('/');
        if trimmed_inner.is_empty() {
            return format!("archive://{arch_path}#/{trimmed_name}");
        }
        return format!("archive://{arch_path}#{trimmed_inner}/{trimmed_name}");
    }
    let trimmed_dir = dir.trim_end_matches('/');
    if trimmed_dir.is_empty() {
        format!("/{trimmed_name}")
    } else {
        format!("{trimmed_dir}/{trimmed_name}")
    }
}

pub(super) fn split_name_stem_ext(name: &str) -> (String, String) {
    if let Some((stem, ext)) = name.rsplit_once('.') {
        if !stem.is_empty() && !ext.is_empty() {
            return (stem.to_string(), format!(".{ext}"));
        }
    }
    (name.to_string(), String::new())
}

pub(super) fn sort_col_to_str(col: SortColumn) -> &'static str {
    match col {
        SortColumn::Size => "size",
        SortColumn::Modified => "modified",
        SortColumn::Created => "created",
        SortColumn::Added => "added",
        SortColumn::Kind => "kind",
        SortColumn::Permissions => "permissions",
        _ => "name",
    }
}

pub(super) fn str_to_sort_col(s: &str) -> SortColumn {
    match s {
        "size" => SortColumn::Size,
        "modified" => SortColumn::Modified,
        "created" => SortColumn::Created,
        "added" => SortColumn::Added,
        "kind" => SortColumn::Kind,
        "permissions" => SortColumn::Permissions,
        _ => SortColumn::Name,
    }
}

pub(super) fn scope_to_str(scope: ViewOptionsScope) -> &'static str {
    match scope {
        ViewOptionsScope::AllFolders => "all_folders",
        ViewOptionsScope::ThisFolder => "this_folder",
        ViewOptionsScope::ThisFolderAndSubfolders => "this_folder_and_subfolders",
    }
}

pub(super) fn view_mode_to_int(mode: PaneViewMode) -> i32 {
    match mode {
        PaneViewMode::List => 0,
        PaneViewMode::Icons => 1,
        PaneViewMode::Columns => 2,
        PaneViewMode::Tree => 3,
    }
}

pub(super) fn int_to_view_mode(v: i32) -> PaneViewMode {
    match v {
        1 => PaneViewMode::Icons,
        2 => PaneViewMode::Columns,
        3 => PaneViewMode::Tree,
        _ => PaneViewMode::List,
    }
}

static BG_PART_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub(super) fn mbps_to_rate_bps(mbps: u32) -> Option<u64> {
    if mbps > 0 {
        Some(u64::from(mbps) * 1_024 * 1_024)
    } else {
        None
    }
}

pub(super) fn next_staging_part_suffix() -> String {
    let seq = BG_PART_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!(".__manifold_part_{}_{}", std::process::id(), seq)
}

pub(super) fn local_part_sibling(dst_path: &str) -> PathBuf {
    let dst = Path::new(dst_path);
    let parent = dst.parent().unwrap_or_else(|| Path::new("."));
    let name = dst
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("transfer");
    let suffix = next_staging_part_suffix();
    parent.join(format!(".{name}{suffix}"))
}

fn open_exclusive_part_file(part_path: &Path) -> Result<std::fs::File, String> {
    if let Some(parent) = part_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(part_path).map_err(|e| e.to_string())
}

/// Best-effort durability flush of a staged part file before it is renamed
/// into place (F-34). Directory handles are skipped; the parent directory is
/// flushed separately via `manifold_vfs::sync_dir` after the rename.
fn sync_part_file_to_disk(path: &Path) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_file() {
        if let Ok(f) = std::fs::File::open(path) {
            let _ = f.sync_all();
        }
    }
}

/// Visible (non-hidden) backup name used when a replaced tree cannot be
/// deleted, so the user can always find and recover it.
fn retired_backup_path(dst: &Path) -> PathBuf {
    let parent = dst.parent().unwrap_or(Path::new("."));
    let name = dst.file_name().and_then(|n| n.to_str()).unwrap_or("item");
    static RETIRE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = RETIRE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    parent.join(format!("{name}.manifold-old-{}-{seq}", std::process::id()))
}

/// Private, user-only (0700) directory holding two-step swap journals.
/// Journals are deliberately NOT stored next to the swap destination:
/// recovery must never read files an attacker could have planted in a
/// browsed folder (R03).
fn swap_journal_dir() -> Result<PathBuf, String> {
    manifold_vfs::secure_runtime_subdir("swap-journals")
        .map_err(|e| format!("Failed to prepare swap journal directory: {e}"))
}

/// Journal file for the two-step directory swap fallback (platforms without
/// a native atomic exchange). Lives in [`swap_journal_dir`]; recovery acts
/// only on structurally validated journal contents (R03).
fn swap_journal_path(dir: &Path) -> PathBuf {
    static JOURNAL_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = JOURNAL_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    dir.join(format!(
        ".manifold-swap-journal-{}-{seq}.json",
        std::process::id()
    ))
}

/// Completes or rolls back interrupted two-step directory swaps recorded in
/// `journal_dir` (F-35 / R03). `journal_dir` must be the app's private
/// runtime directory — never a user-browsed folder — and every journal is
/// structurally validated before any rename: both paths absolute, the
/// backup a `.manifold-old` sibling of the destination. Journals failing
/// validation are reported and deleted without acting on them. Backups not
/// referenced by a journal are never touched. Returns human-readable
/// reports for the activity log.
pub(super) fn recover_swap_journals_in(journal_dir: &Path) -> Vec<String> {
    let mut reports = Vec::new();
    let Ok(entries) = std::fs::read_dir(journal_dir) else {
        return reports;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(".manifold-swap-journal-") || !name.ends_with(".json") {
            continue;
        }
        let jpath = entry.path();
        let Ok(raw) = std::fs::read_to_string(&jpath) else {
            continue;
        };
        let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) else {
            reports.push(format!(
                "Ignoring unreadable swap journal {}",
                jpath.display()
            ));
            continue;
        };
        let (Some(dst), Some(bak)) = (
            val.get("dst").and_then(|v| v.as_str()),
            val.get("bak").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let dst_p = Path::new(dst);
        let bak_p = Path::new(bak);
        // Structural contract (R03): a journal may only ever move a
        // `.manifold-old` backup back onto its own destination sibling.
        // Anything else is attacker-shaped or stale and never acted on.
        let contract_ok = dst_p.is_absolute()
            && bak_p.is_absolute()
            && bak_p.parent() == dst_p.parent()
            && dst_p
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|dn| {
                    bak_p
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|bn| bn.starts_with(&format!("{dn}.manifold-old-")))
                });
        if !contract_ok {
            reports.push(format!(
                "Ignoring invalid swap journal {} (paths violate the swap contract)",
                jpath.display()
            ));
            let _ = std::fs::remove_file(&jpath);
            continue;
        }
        let dst_exists = std::fs::symlink_metadata(dst_p).is_ok();
        let bak_exists = std::fs::symlink_metadata(bak_p).is_ok();
        if !dst_exists && bak_exists {
            // Crash between the two renames: roll the backup back into place.
            match std::fs::rename(bak_p, dst_p) {
                Ok(()) => {
                    let _ = std::fs::remove_file(&jpath);
                    reports.push(format!(
                        "Recovered interrupted swap: restored {}",
                        dst_p.display()
                    ));
                }
                Err(e) => reports.push(format!(
                    "Swap recovery FAILED for {}: {e} (previous version at {})",
                    dst_p.display(),
                    bak_p.display()
                )),
            }
        } else if dst_exists && bak_exists {
            // Swap finished but the old tree survived cleanup: keep it
            // visible, drop the journal.
            reports.push(format!(
                "Swap completed; previous version kept at {}",
                bak_p.display()
            ));
            let _ = std::fs::remove_file(&jpath);
        } else {
            // dst present (or both gone): nothing to restore.
            let _ = std::fs::remove_file(&jpath);
        }
    }
    reports
}

pub(super) fn swap_local_staged_into_place(part_path: &Path, dst_path: &str) -> Result<(), String> {
    // Persist staged contents before the rename so a crash cannot leave a
    // truncated file at the destination (F-34). This covers paths where the
    // writer's handle is no longer available (scp/curl downloads).
    sync_part_file_to_disk(part_path);
    let dst = Path::new(dst_path);
    let dst_meta = std::fs::symlink_metadata(dst).ok();
    let dst_is_real_dir = dst_meta
        .as_ref()
        .is_some_and(|m| m.is_dir() && !m.file_type().is_symlink());

    if dst_is_real_dir {
        // Native atomic exchange (macOS `renamex_np` / Linux `renameat2`):
        // replaces the destination with zero window; the old tree lands at
        // the part path afterwards and is removed, or retired to a visible
        // name if removal fails.
        if manifold_vfs::atomic_exchange(part_path, dst).is_ok() {
            if std::fs::remove_dir_all(part_path).is_err() {
                let retired = retired_backup_path(dst);
                let _ = std::fs::rename(part_path, retired);
            }
            if let Some(parent) = dst.parent() {
                manifold_vfs::sync_dir(parent);
            }
            return Ok(());
        }
        // Fallback for platforms without atomic exchange (Windows):
        // two-step rename with a visible, journaled backup. The journal
        // lives in the private runtime directory, never next to the
        // destination (R03).
        let bak_path = retired_backup_path(dst);
        let journal_dir = swap_journal_dir()?;
        let journal = swap_journal_path(&journal_dir);
        let dst_abs = std::path::absolute(dst).unwrap_or_else(|_| dst.to_path_buf());
        let body = serde_json::json!({
            "v": 2,
            "dst": dst_abs.to_string_lossy(),
            "bak": bak_path.to_string_lossy(),
        });
        // Durable, atomic journal creation so a crash cannot leave a
        // truncated (and therefore unrecoverable) journal behind (R04).
        manifold_vfs::atomic_write_bytes(&journal, body.to_string().as_bytes())
            .map_err(|e| format!("Failed to create swap journal: {e}"))?;
        if let Err(err) = std::fs::rename(dst, &bak_path) {
            let _ = std::fs::remove_file(&journal);
            return Err(err.to_string());
        }
        if let Err(err) = std::fs::rename(part_path, dst) {
            // Roll back: put the previous version back first. If even the
            // rollback fails, surface the location of the previous version
            // instead of hiding it.
            if let Err(rb_err) = std::fs::rename(&bak_path, dst) {
                return Err(format!(
                    "{err}; rollback FAILED, previous version kept at {}; {rb_err}",
                    bak_path.display()
                ));
            }
            let _ = std::fs::remove_file(&journal);
            let _ = std::fs::remove_dir_all(part_path);
            let _ = std::fs::remove_file(part_path);
            return Err(err.to_string());
        }
        // Success: best-effort cleanup. A failed backup removal leaves the
        // old tree at its visible retired name.
        let _ = std::fs::remove_dir_all(&bak_path);
        let _ = std::fs::remove_file(&journal);
        if let Some(parent) = dst.parent() {
            manifold_vfs::sync_dir(parent);
        }
        return Ok(());
    }

    // File or missing target: plain rename is already atomic (it replaces
    // an existing file on unix and via MOVEFILE_REPLACE_EXISTING on
    // Windows).
    if let Err(err) = std::fs::rename(part_path, dst) {
        let _ = std::fs::remove_file(part_path);
        let _ = std::fs::remove_dir_all(part_path);
        return Err(err.to_string());
    }
    if let Some(parent) = dst.parent() {
        manifold_vfs::sync_dir(parent);
    }
    Ok(())
}

type BgProgressCtx<'a> = (
    &'a mpsc::Sender<BgWorkerEvent>,
    &'a str,
    &'a str,
    u64,
    u64,
    &'a TransferControlHandle,
    &'a std::sync::Arc<std::sync::Mutex<TokenBucketLimiter>>,
);

fn copy_archive_dir_children(
    arch: &ArchiveBackend,
    inner: &str,
    local_vfs: &LocalFsBackend,
    dst_dir: &str,
    prog: BgProgressCtx<'_>,
) -> Result<(), String> {
    let (tx, task_id, label, base_transferred, total_bytes, ctrl, _) = prog;
    local_vfs.create_dir(dst_dir).map_err(|e| e.to_string())?;
    let children = arch.list_directory(inner).map_err(|e| e.to_string())?;
    for child in children {
        while ctrl.is_paused() && !ctrl.is_cancelled() {
            std::thread::sleep(Duration::from_millis(40));
        }
        if ctrl.is_cancelled() {
            return Err("Cancelled by user".to_string());
        }
        let child_dst = join_vfs_path(dst_dir, &child.name);
        if child.is_dir {
            let sub_prog = (
                tx,
                task_id,
                label,
                base_transferred,
                total_bytes,
                ctrl,
                prog.6,
            );
            copy_archive_dir_children(arch, &child.path, local_vfs, &child_dst, sub_prog)?;
            continue;
        }
        let data = arch.read_bytes(&child.path).map_err(|e| e.to_string())?;
        let part_dst = local_part_sibling(&child_dst);
        let part_str = part_dst.to_string_lossy().to_string();
        local_vfs
            .write_bytes(&part_str, &data)
            .map_err(|e| e.to_string())?;
        // Apply the recorded entry mode (F-36): previously only executable
        // bits were transferred, leaving regular entries at the part file's
        // 0600. Entries without mode information default to 0644.
        let mode = if child.permissions != 0 {
            child.permissions
        } else {
            0o644
        };
        let _ = local_vfs.set_permissions(&part_str, mode);
        swap_local_staged_into_place(&part_dst, &child_dst)?;
        let _ = tx.send(BgWorkerEvent::Progress {
            task_id: task_id.to_string(),
            transferred: base_transferred.saturating_add(data.len() as u64),
            total: total_bytes,
            label: label.to_string(),
        });
    }
    Ok(())
}

pub(super) fn copy_archive_dir_to_local(
    arch_ctx: (&ArchiveBackend, &str),
    inner: &str,
    local_vfs: &LocalFsBackend,
    dst_path: &str,
    prog: BgProgressCtx<'_>,
) -> Result<(), String> {
    let (arch, _) = arch_ctx;
    let is_app = dst_path.to_ascii_lowercase().ends_with(".app");
    if is_app {
        let stage_wrap = local_part_sibling(dst_path);
        let dst_name = Path::new(dst_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("App.app");
        let stage_app = stage_wrap.join(dst_name);
        let stage_str = stage_app.to_string_lossy().to_string();
        if let Err(err) = std::fs::create_dir_all(&stage_app) {
            return Err(format!("Failed to create bundle stage dir: {err}"));
        }
        if let Err(err) = copy_archive_dir_children(arch, inner, local_vfs, &stage_str, prog) {
            let _ = std::fs::remove_dir_all(&stage_wrap);
            return Err(err);
        }
        ensure_macos_bundle_executables_chmod(&stage_app);
        let swap_res = swap_local_staged_into_place(&stage_app, dst_path);
        let _ = std::fs::remove_dir_all(&stage_wrap);
        return swap_res;
    }
    copy_archive_dir_children(arch, inner, local_vfs, dst_path, prog)?;
    sanitize_macos_app_bundle(Path::new(dst_path), cfg!(target_os = "macos"));
    Ok(())
}

pub(super) fn perform_bg_single_transfer(
    local_vfs: &LocalFsBackend,
    remotes: &HashMap<String, RemoteVfsBackend>,
    src_path: &str,
    dst_path: &str,
    is_move: bool,
    prog: BgProgressCtx<'_>,
) -> Result<(), String> {
    let src_slash = format!("{}/", src_path.trim_end_matches('/'));
    if dst_path == src_path || dst_path.starts_with(&src_slash) {
        return Err("Cannot copy or move a folder into itself".to_string());
    }
    let (tx, task_id, label, base_transferred, total_bytes, ctrl, shared_limiter) = prog;
    while ctrl.is_paused() && !ctrl.is_cancelled() {
        std::thread::sleep(Duration::from_millis(40));
    }
    if ctrl.is_cancelled() {
        return Err("Cancelled by user".to_string());
    }
    if let Some((arch_path, inner)) = split_archive_uri(src_path) {
        if is_move {
            return Err("Archive virtual filesystem is read-only".to_string());
        }
        let arch = ArchiveBackend::open_from_disk(&arch_path).map_err(|e| e.to_string())?;
        let meta = arch.metadata(&inner).map_err(|e| e.to_string())?;
        if meta.is_dir {
            if let Some((p2, sub2)) = split_remote_uri(dst_path) {
                let remote = remotes
                    .get(&p2)
                    .ok_or_else(|| "Remote VFS not connected".to_string())?;
                remote.create_dir(&sub2).map_err(|e| e.to_string())?;
                let children = arch.list_directory(&inner).map_err(|e| e.to_string())?;
                for child in children {
                    let child_src = format!("archive://{arch_path}#{}", child.path);
                    let child_dst = join_vfs_path(dst_path, &child.name);
                    perform_bg_single_transfer(
                        local_vfs, remotes, &child_src, &child_dst, false, prog,
                    )?;
                }
                return Ok(());
            }
            return copy_archive_dir_to_local(
                (&arch, &arch_path),
                &inner,
                local_vfs,
                dst_path,
                prog,
            );
        }
        let data = arch.read_bytes(&inner).map_err(|e| e.to_string())?;
        if let Some((p2, sub2)) = split_remote_uri(dst_path) {
            let remote = remotes
                .get(&p2)
                .ok_or_else(|| "Remote VFS not connected".to_string())?;
            let sub2_part = format!("{sub2}{}", next_staging_part_suffix());
            remote
                .write_bytes(&sub2_part, &data)
                .map_err(|e| e.to_string())?;
            if let Err(err) = remote.rename(&sub2_part, &sub2) {
                let _ = remote.remove(&sub2_part, false);
                return Err(err.to_string());
            }
        } else {
            let part_dst = local_part_sibling(dst_path);
            let part_str = part_dst.to_string_lossy().to_string();
            local_vfs
                .write_bytes(&part_str, &data)
                .map_err(|e| e.to_string())?;
            swap_local_staged_into_place(&part_dst, dst_path)?;
        }
        let _ = tx.send(BgWorkerEvent::Progress {
            task_id: task_id.to_string(),
            transferred: base_transferred.saturating_add(data.len() as u64),
            total: total_bytes,
            label: label.to_string(),
        });
        return Ok(());
    }
    let src_rem = split_remote_uri(src_path);
    let dst_rem = split_remote_uri(dst_path);

    match (src_rem, dst_rem) {
        // 1. Same-Remote copy or move
        (Some((p1, sub1)), Some((p2, sub2))) if p1 == p2 => {
            let remote = remotes
                .get(&p1)
                .ok_or_else(|| "Remote VFS not connected".to_string())?;
            if is_move && remote.metadata(&sub2).is_err() {
                return remote.rename(&sub1, &sub2).map_err(|e| e.to_string());
            }
            let src_meta = remote.metadata(&sub1).map_err(|e| e.to_string())?;
            if src_meta.is_dir {
                remote.create_dir(&sub2).map_err(|e| e.to_string())?;
                let entries = remote.list_directory(&sub1).map_err(|e| e.to_string())?;
                for child in entries {
                    let child_src = format!("{p1}{}", child.path);
                    let child_dst = join_vfs_path(dst_path, &child.name);
                    perform_bg_single_transfer(
                        local_vfs, remotes, &child_src, &child_dst, false, prog,
                    )?;
                }
                if is_move {
                    remote.remove(&sub1, true).map_err(|e| e.to_string())?;
                }
                return Ok(());
            }
            let sub2_part = format!("{sub2}{}", next_staging_part_suffix());
            remote
                .copy_file(&sub1, &sub2_part)
                .map_err(|e| e.to_string())?;
            if let Err(err) = remote.rename(&sub2_part, &sub2) {
                let _ = remote.remove(&sub2_part, false);
                return Err(err.to_string());
            }
            if is_move {
                remote.remove(&sub1, false).map_err(|e| e.to_string())?;
            }
            return Ok(());
        }
        // 1b. Cross-Remote (Remote A -> Remote B via secure local staging file)
        (Some((p1, sub1)), Some((p2, sub2))) => {
            let remote1 = remotes
                .get(&p1)
                .ok_or_else(|| "Source Remote VFS not connected".to_string())?;
            let remote2 = remotes
                .get(&p2)
                .ok_or_else(|| "Destination Remote VFS not connected".to_string())?;
            let src_meta = remote1.metadata(&sub1).map_err(|e| e.to_string())?;
            if src_meta.is_dir {
                remote2.create_dir(&sub2).map_err(|e| e.to_string())?;
                let entries = remote1.list_directory(&sub1).map_err(|e| e.to_string())?;
                for child in entries {
                    let child_src = format!("{p1}{}", child.path);
                    let child_dst = join_vfs_path(dst_path, &child.name);
                    perform_bg_single_transfer(
                        local_vfs, remotes, &child_src, &child_dst, false, prog,
                    )?;
                }
            } else {
                let (tmp_path, tmp_file) =
                    manifold_vfs::create_secure_temp_file("cross-remote", "tx", ".part")
                        .map_err(|e| e.to_string())?;
                drop(tmp_file);
                let dl_res = remote1
                    .download_to_local_file(&sub1, &tmp_path)
                    .map_err(|e| e.to_string());
                if let Err(err) = dl_res {
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err(err);
                }
                let sub2_part = format!("{sub2}{}", next_staging_part_suffix());
                let ul_res = remote2
                    .upload_local_file(&tmp_path, &sub2_part)
                    .map_err(|e| e.to_string());
                let _ = std::fs::remove_file(&tmp_path);
                if let Err(err) = ul_res {
                    let _ = remote2.remove(&sub2_part, false);
                    return Err(err);
                }
                if let Err(err) = remote2.rename(&sub2_part, &sub2) {
                    let _ = remote2.remove(&sub2_part, false);
                    return Err(err.to_string());
                }
            }
            if is_move {
                remote1.remove(&sub1, true).map_err(|e| e.to_string())?;
            }
            return Ok(());
        }
        // 2. Local -> Remote (Direct streaming via scp without reading multi-GB ISO into RAM)
        (None, Some((p2, sub2))) => {
            let remote = remotes
                .get(&p2)
                .ok_or_else(|| "Remote VFS not connected".to_string())?;
            let src_meta = local_vfs.metadata(src_path).map_err(|e| e.to_string())?;
            if src_meta.is_dir {
                remote.create_dir(&sub2).map_err(|e| e.to_string())?;
                let entries = local_vfs
                    .list_directory(src_path)
                    .map_err(|e| e.to_string())?;
                for child in entries {
                    let child_dst = join_vfs_path(dst_path, &child.name);
                    perform_bg_single_transfer(
                        local_vfs,
                        remotes,
                        &child.path,
                        &child_dst,
                        false,
                        prog,
                    )?;
                }
            } else {
                let sub2_part = format!("{sub2}{}", next_staging_part_suffix());
                if let Err(err) = remote.upload_local_file(Path::new(src_path), &sub2_part) {
                    let _ = remote.remove(&sub2_part, false);
                    return Err(err.to_string());
                }
                if let Err(err) = remote.rename(&sub2_part, &sub2) {
                    let _ = remote.remove(&sub2_part, false);
                    return Err(err.to_string());
                }
            }
            if is_move {
                let rm = local_vfs.remove(src_path, true);
                rm.map_err(|e| e.to_string())?;
            }
            return Ok(());
        }
        // 3. Remote -> Local (Direct streaming via scp without buffering multi-GB ISO in RAM)
        (Some((p1, sub1)), None) => {
            let remote = remotes
                .get(&p1)
                .ok_or_else(|| "Remote VFS not connected".to_string())?;
            let src_meta = remote.metadata(&sub1).map_err(|e| e.to_string())?;
            if src_meta.is_dir {
                local_vfs.create_dir(dst_path).map_err(|e| e.to_string())?;
                let entries = remote.list_directory(&sub1).map_err(|e| e.to_string())?;
                for child in entries {
                    let child_src = format!("{p1}{}", child.path);
                    let child_dst = join_vfs_path(dst_path, &child.name);
                    perform_bg_single_transfer(
                        local_vfs, remotes, &child_src, &child_dst, false, prog,
                    )?;
                }
            } else {
                let part_path = local_part_sibling(dst_path);
                let part_file = open_exclusive_part_file(&part_path)?;
                drop(part_file);
                if let Err(err) = remote.download_to_local_file(&sub1, &part_path) {
                    let _ = std::fs::remove_file(&part_path);
                    return Err(err.to_string());
                }
                swap_local_staged_into_place(&part_path, dst_path)?;
            }
            if is_move {
                remote.remove(&sub1, true).map_err(|e| e.to_string())?;
            }
            return Ok(());
        }
        _ => {}
    }

    // 4. Local -> Local (4 MB chunked streaming into sibling .part file with atomic commit)
    let dst_meta_opt = std::fs::symlink_metadata(dst_path).ok();
    let dst_is_dir = dst_meta_opt.as_ref().is_some_and(|m| m.is_dir());
    if is_move && !dst_is_dir && local_vfs.rename(src_path, dst_path).is_ok() {
        sanitize_macos_app_bundle(Path::new(dst_path), cfg!(target_os = "macos"));
        return Ok(());
    }
    let src_sym_meta = std::fs::symlink_metadata(src_path).map_err(|e| e.to_string())?;
    if src_sym_meta.is_dir() && !src_sym_meta.file_type().is_symlink() {
        if dst_meta_opt.is_some() {
            let part_dir = local_part_sibling(dst_path);
            let part_dir_str = part_dir.to_string_lossy().to_string();
            if let Err(err) = copy_local_dir_preserving_bundle(src_path, &part_dir_str) {
                let _ = std::fs::remove_dir_all(&part_dir);
                return Err(err);
            }
            swap_local_staged_into_place(&part_dir, dst_path)?;
        } else {
            copy_local_dir_preserving_bundle(src_path, dst_path)?;
        }
        if is_move {
            let rm = local_vfs.remove(src_path, true);
            rm.map_err(|e| e.to_string())?;
        }
        return Ok(());
    }
    let mut reader = std::fs::File::open(src_path).map_err(|e| e.to_string())?;
    let part_path = local_part_sibling(dst_path);
    let mut writer = open_exclusive_part_file(&part_path)?;
    let mut buf = vec![0u8; DEFAULT_TRANSFER_CHUNK_SIZE];
    let mut copied = 0u64;
    loop {
        while ctrl.is_paused() && !ctrl.is_cancelled() {
            std::thread::sleep(Duration::from_millis(40));
        }
        if ctrl.is_cancelled() {
            drop(writer);
            let _ = std::fs::remove_file(&part_path);
            return Err("Cancelled by user".to_string());
        }
        let n = match reader.read(&mut buf) {
            Ok(bytes_read) => bytes_read,
            Err(err) => {
                drop(writer);
                let _ = std::fs::remove_file(&part_path);
                return Err(err.to_string());
            }
        };
        if n == 0 {
            break;
        }
        let wait = shared_limiter
            .lock()
            .map(|mut lim| lim.consume(n))
            .unwrap_or(Duration::ZERO);
        if !wait.is_zero() {
            std::thread::sleep(wait);
        }
        if let Err(err) = writer.write_all(&buf[..n]) {
            drop(writer);
            let _ = std::fs::remove_file(&part_path);
            return Err(err.to_string());
        }
        copied += n as u64;
        let _ = tx.send(BgWorkerEvent::Progress {
            task_id: task_id.to_string(),
            transferred: base_transferred.saturating_add(copied),
            total: total_bytes,
            label: label.to_string(),
        });
    }
    if let Err(err) = writer.flush().and_then(|()| writer.sync_all()) {
        drop(writer);
        let _ = std::fs::remove_file(&part_path);
        return Err(err.to_string());
    }
    drop(writer);
    if let Ok(src_meta) = std::fs::metadata(src_path) {
        let _ = std::fs::set_permissions(&part_path, src_meta.permissions());
    }
    swap_local_staged_into_place(&part_path, dst_path)?;
    if is_move {
        local_vfs
            .remove(src_path, false)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub(super) fn apply_preferences_to_window(w: &ManifoldWindow, prefs: &AppPreferences) {
    let norm_family = match prefs.font_family.trim() {
        "" | "sans-serif" | "System Sans" => "sans-serif",
        "Inter" | "Inter / UI" => "Inter",
        "monospace" | "Monospace" => "monospace",
        "serif" | "Serif" => "serif",
        other => other,
    };
    let resolved_family = match norm_family {
        "Inter" => {
            if cfg!(target_os = "macos") {
                "Avenir Next"
            } else if cfg!(target_os = "windows") {
                "Segoe UI"
            } else {
                "DejaVu Sans"
            }
        }
        "monospace" => {
            if cfg!(target_os = "macos") {
                "Menlo"
            } else if cfg!(target_os = "windows") {
                "Consolas"
            } else {
                "DejaVu Sans Mono"
            }
        }
        "serif" => {
            if cfg!(target_os = "macos") || cfg!(target_os = "windows") {
                "Georgia"
            } else {
                "DejaVu Serif"
            }
        }
        _ => "",
    };
    let resolved_mono = if cfg!(target_os = "macos") {
        "Menlo"
    } else if cfg!(target_os = "windows") {
        "Consolas"
    } else {
        "DejaVu Sans Mono"
    };
    let norm_theme = match prefs.theme_preset.trim() {
        "midnight_ocean" | "Midnight Ocean" => "midnight_ocean",
        "dracula_pro" | "Dracula Pro" => "dracula_pro",
        "nordic_slate" | "Nordic Slate" => "nordic_slate",
        "solarized_dark" | "Solarized Dark" => "solarized_dark",
        "high_contrast" | "High Contrast" => "high_contrast",
        _ => "dark_zinc",
    };

    w.set_ui_font_size_delta(prefs.font_size_delta);
    w.set_ui_font_family(norm_family.into());
    w.set_resolved_font_family(resolved_family.into());
    w.set_resolved_mono_font_family(resolved_mono.into());
    w.set_ui_font_bold(prefs.font_bold);
    w.set_ui_theme_preset(norm_theme.into());
    w.set_pref_max_bandwidth_mbps(prefs.max_bandwidth_mbps as i32);

    let (canvas, toolbar, sidebar, surface, border, accent, hover, text_pri, text_sec) =
        match norm_theme {
            "midnight_ocean" => (
                Color::from_rgb_u8(0x0B, 0x11, 0x20),
                Color::from_rgb_u8(0x13, 0x1B, 0x2E),
                Color::from_rgb_u8(0x0F, 0x17, 0x2A),
                Color::from_rgb_u8(0x16, 0x20, 0x35),
                Color::from_rgb_u8(0x23, 0x32, 0x4E),
                Color::from_rgb_u8(0x02, 0x84, 0xC7),
                Color::from_rgb_u8(0x1E, 0x2D, 0x47),
                Color::from_rgb_u8(0xF1, 0xF5, 0xF9),
                Color::from_rgb_u8(0x94, 0xA3, 0xB8),
            ),
            "dracula_pro" => (
                Color::from_rgb_u8(0x19, 0x1A, 0x21),
                Color::from_rgb_u8(0x21, 0x22, 0x2C),
                Color::from_rgb_u8(0x1E, 0x1F, 0x29),
                Color::from_rgb_u8(0x28, 0x2A, 0x36),
                Color::from_rgb_u8(0x3B, 0x3E, 0x52),
                Color::from_rgb_u8(0x8B, 0x5C, 0xF6),
                Color::from_rgb_u8(0x34, 0x37, 0x46),
                Color::from_rgb_u8(0xF8, 0xF8, 0xF2),
                Color::from_rgb_u8(0xA4, 0xA8, 0xC4),
            ),
            "nordic_slate" => (
                Color::from_rgb_u8(0x1D, 0x21, 0x2A),
                Color::from_rgb_u8(0x24, 0x29, 0x33),
                Color::from_rgb_u8(0x21, 0x26, 0x30),
                Color::from_rgb_u8(0x2E, 0x34, 0x40),
                Color::from_rgb_u8(0x3B, 0x42, 0x52),
                Color::from_rgb_u8(0x5E, 0x81, 0xAC),
                Color::from_rgb_u8(0x3B, 0x42, 0x52),
                Color::from_rgb_u8(0xEC, 0xEF, 0xF4),
                Color::from_rgb_u8(0x9C, 0xA6, 0xB8),
            ),
            "solarized_dark" => (
                Color::from_rgb_u8(0x00, 0x1E, 0x26),
                Color::from_rgb_u8(0x00, 0x2B, 0x36),
                Color::from_rgb_u8(0x00, 0x24, 0x2E),
                Color::from_rgb_u8(0x07, 0x36, 0x42),
                Color::from_rgb_u8(0x16, 0x4B, 0x58),
                Color::from_rgb_u8(0x26, 0x8B, 0xD2),
                Color::from_rgb_u8(0x0D, 0x42, 0x50),
                Color::from_rgb_u8(0xEE, 0xE8, 0xD5),
                Color::from_rgb_u8(0x93, 0xA1, 0xA1),
            ),
            "high_contrast" => (
                Color::from_rgb_u8(0x05, 0x05, 0x07),
                Color::from_rgb_u8(0x11, 0x11, 0x15),
                Color::from_rgb_u8(0x09, 0x09, 0x0B),
                Color::from_rgb_u8(0x0C, 0x0C, 0x0F),
                Color::from_rgb_u8(0x3F, 0x3F, 0x48),
                Color::from_rgb_u8(0x25, 0x63, 0xEB),
                Color::from_rgb_u8(0x22, 0x22, 0x2A),
                Color::from_rgb_u8(0xFF, 0xFF, 0xFF),
                Color::from_rgb_u8(0xC4, 0xC4, 0xCE),
            ),
            _ => (
                Color::from_rgb_u8(0x12, 0x12, 0x14),
                Color::from_rgb_u8(0x1E, 0x1E, 0x22),
                Color::from_rgb_u8(0x16, 0x16, 0x18),
                Color::from_rgb_u8(0x1A, 0x1A, 0x1E),
                Color::from_rgb_u8(0x28, 0x28, 0x2D),
                Color::from_rgb_u8(0x0D, 0x52, 0xBF),
                Color::from_rgb_u8(0x26, 0x26, 0x2B),
                Color::from_rgb_u8(0xE1, 0xE1, 0xE6),
                Color::from_rgb_u8(0x88, 0x88, 0x92),
            ),
        };
    let row_alt = match norm_theme {
        "midnight_ocean" => Color::from_rgb_u8(0x1A, 0x26, 0x3E),
        "dracula_pro" => Color::from_rgb_u8(0x2D, 0x30, 0x3E),
        "nordic_slate" => Color::from_rgb_u8(0x33, 0x3A, 0x47),
        "solarized_dark" => Color::from_rgb_u8(0x0A, 0x3D, 0x4A),
        "high_contrast" => Color::from_rgb_u8(0x14, 0x14, 0x19),
        _ => Color::from_rgb_u8(0x1E, 0x1E, 0x24),
    };
    w.set_theme_bg_canvas(canvas.into());
    w.set_theme_bg_toolbar(toolbar.into());
    w.set_theme_bg_sidebar(sidebar.into());
    w.set_theme_bg_surface(surface.into());
    w.set_theme_border(border.into());
    w.set_theme_accent(accent.into());
    w.set_theme_row_hover(hover.into());
    w.set_theme_row_alt(row_alt.into());
    w.set_theme_text_primary(text_pri.into());
    w.set_theme_text_secondary(text_sec.into());
}

pub(super) fn argb_to_slint_color(argb: u32) -> Color {
    let a = ((argb >> 24) & 0xFF) as u8;
    let r = ((argb >> 16) & 0xFF) as u8;
    let g = ((argb >> 8) & 0xFF) as u8;
    let b = (argb & 0xFF) as u8;
    Color::from_argb_u8(a, r, g, b)
}

pub(super) fn styled_span_to_slint(span: Option<&StyledSpan>) -> TerminalSpanSlint {
    let Some(s) = span else {
        return TerminalSpanSlint::default();
    };
    TerminalSpanSlint {
        text: SharedString::from(&s.text),
        char_count: s.char_count as i32,
        fg: argb_to_slint_color(s.fg).into(),
        bg: argb_to_slint_color(s.bg).into(),
        has_bg: s.bg != 0,
        bold: s.bold,
        underline: s.underline,
    }
}

pub(super) fn sync_terminal_to_window(window: &ManifoldWindow, rt: &mut GuiRuntime) {
    let _ = rt.sync_terminal_dimensions(window);
    window.set_terminal_cwd(rt.terminal_cwd.clone().into());
    window.set_terminal_scroll_offset(rt.term_emulator.scroll_offset() as i32);
    window.set_terminal_max_scroll(rt.term_emulator.max_scroll_offset() as i32);
    window.set_terminal_alt_screen(rt.term_emulator.using_alt_screen());

    let (rows, cols) = rt.term_last_size;
    let shell_name = rt
        .shell_session
        .as_ref()
        .map(NativeShellSession::shell_name)
        .unwrap_or("shell");
    let term_session_lbl = if split_remote_uri(&rt.terminal_cwd).is_some() {
        let conn_title = rt.format_tab_title(&rt.terminal_cwd);
        format!("{shell_name} ({cols}×{rows}) — {conn_title}")
    } else {
        format!("{shell_name} ({cols}×{rows})")
    };
    window.set_terminal_session_label(term_session_lbl.into());

    let focused = window.get_terminal_focused();
    let rendered = rt.term_emulator.render_visible_lines(focused);
    let slint_lines: Vec<TerminalLineSlint> = rendered
        .iter()
        .map(|line| {
            let sp = &line.spans;
            TerminalLineSlint {
                s0: styled_span_to_slint(sp.first()),
                s1: styled_span_to_slint(sp.get(1)),
                s2: styled_span_to_slint(sp.get(2)),
                s3: styled_span_to_slint(sp.get(3)),
                s4: styled_span_to_slint(sp.get(4)),
                s5: styled_span_to_slint(sp.get(5)),
                s6: styled_span_to_slint(sp.get(6)),
                s7: styled_span_to_slint(sp.get(7)),
                s8: styled_span_to_slint(sp.get(8)),
                s9: styled_span_to_slint(sp.get(9)),
                s10: styled_span_to_slint(sp.get(10)),
                s11: styled_span_to_slint(sp.get(11)),
                s12: styled_span_to_slint(sp.get(12)),
                s13: styled_span_to_slint(sp.get(13)),
                s14: styled_span_to_slint(sp.get(14)),
                s15: styled_span_to_slint(sp.get(15)),
            }
        })
        .collect();
    window.set_terminal_lines(ModelRc::new(VecModel::from(slint_lines)));
}

#[cfg(test)]
mod staging_tests {
    use super::*;

    #[test]
    fn swap_file_replaces_existing_and_leaves_no_part() {
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("target.bin");
        std::fs::write(&dst, b"OLD").unwrap();
        let dst_str = dst.to_string_lossy().to_string();

        let part = local_part_sibling(&dst_str);
        std::fs::write(&part, b"NEW").unwrap();
        swap_local_staged_into_place(&part, &dst_str).unwrap();

        assert_eq!(std::fs::read(&dst).unwrap(), b"NEW");
        assert!(!part.exists(), "part file must be consumed");
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".target"))
            .collect();
        assert!(leftovers.is_empty(), "staging leftovers: {leftovers:?}");
    }

    #[test]
    fn swap_new_file_without_existing_target_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("fresh.bin");
        let dst_str = dst.to_string_lossy().to_string();
        let part = local_part_sibling(&dst_str);
        std::fs::write(&part, b"DATA").unwrap();
        swap_local_staged_into_place(&part, &dst_str).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"DATA");
    }

    #[test]
    fn swap_directory_replaces_target_dir_and_removes_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("folder");
        std::fs::create_dir(&dst).unwrap();
        std::fs::write(dst.join("old.txt"), b"old").unwrap();
        let dst_str = dst.to_string_lossy().to_string();

        let part = local_part_sibling(&dst_str);
        std::fs::create_dir_all(&part).unwrap();
        std::fs::write(part.join("new.txt"), b"new").unwrap();

        swap_local_staged_into_place(&part, &dst_str).unwrap();
        assert!(dst.join("new.txt").exists());
        assert!(!dst.join("old.txt").exists());
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".folder"))
            .collect();
        assert!(leftovers.is_empty(), "backup leftovers: {leftovers:?}");
    }

    #[test]
    fn exclusive_part_file_is_unique_and_not_preexisting() {
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("x.bin");
        let dst_str = dst.to_string_lossy().to_string();
        let p1 = local_part_sibling(&dst_str);
        let p2 = local_part_sibling(&dst_str);
        assert_ne!(p1, p2, "part suffixes must be unique per call");
        let f = open_exclusive_part_file(&p1).unwrap();
        drop(f);
        assert!(p1.exists());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_exchange_swaps_two_directories_atomically() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        std::fs::write(a.join("a.txt"), b"A").unwrap();
        std::fs::write(b.join("b.txt"), b"B").unwrap();

        manifold_vfs::atomic_exchange(&b, &a).unwrap();

        assert!(a.join("b.txt").exists(), "b content moved to a");
        assert!(b.join("a.txt").exists(), "a content moved to b");
        assert!(!a.join("a.txt").exists());
    }

    #[test]
    fn swap_dir_existing_keeps_no_journal_and_replaces_content() {
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("folder");
        std::fs::create_dir(&dst).unwrap();
        std::fs::write(dst.join("old.txt"), b"old").unwrap();
        let dst_str = dst.to_string_lossy().to_string();
        let part = local_part_sibling(&dst_str);
        std::fs::create_dir_all(&part).unwrap();
        std::fs::write(part.join("new.txt"), b"new").unwrap();

        swap_local_staged_into_place(&part, &dst_str).unwrap();

        assert_eq!(std::fs::read(dst.join("new.txt")).unwrap(), b"new");
        assert!(!dst.join("old.txt").exists());
        let journals: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .contains("manifold-swap-journal")
            })
            .collect();
        assert!(journals.is_empty(), "journal must be removed on success");
    }

    #[test]
    fn recover_rolls_back_interrupted_swap_from_journal() {
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("folder");
        let bak = tmp.path().join("folder.manifold-old-1");
        std::fs::create_dir(&bak).unwrap();
        std::fs::write(bak.join("data.txt"), b"precious").unwrap();
        // Simulated crash between the two renames: dst missing, bak present.
        let journal = tmp.path().join(".manifold-swap-journal-999-0.json");
        let body = format!(
            "{{\"v\":1,\"dst\":\"{}\",\"bak\":\"{}\"}}",
            dst.display(),
            bak.display()
        );
        std::fs::write(&journal, body).unwrap();

        let reports = recover_swap_journals_in(tmp.path());
        assert!(!reports.is_empty());
        assert_eq!(
            std::fs::read(dst.join("data.txt")).unwrap(),
            b"precious",
            "backup must be restored to the destination"
        );
        assert!(!journal.exists(), "journal must be consumed");
        assert!(!bak.exists());
    }

    #[test]
    fn recover_keeps_backup_when_dst_already_present() {
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("folder");
        let bak = tmp.path().join("folder.manifold-old-1");
        std::fs::create_dir(&dst).unwrap();
        std::fs::create_dir(&bak).unwrap();
        let journal = tmp.path().join(".manifold-swap-journal-999-1.json");
        let body = format!(
            "{{\"v\":1,\"dst\":\"{}\",\"bak\":\"{}\"}}",
            dst.display(),
            bak.display()
        );
        std::fs::write(&journal, body).unwrap();

        let reports = recover_swap_journals_in(tmp.path());
        assert!(reports.iter().any(|r| r.contains("kept")));
        assert!(bak.exists(), "old tree must stay visible, not be deleted");
        assert!(!journal.exists());
    }

    #[test]
    fn recover_never_touches_unreferenced_backups() {
        let tmp = tempfile::tempdir().unwrap();
        let orphan = tmp.path().join("stuff.manifold-old-7");
        std::fs::create_dir(&orphan).unwrap();
        std::fs::write(orphan.join("keep.txt"), b"keep").unwrap();

        let reports = recover_swap_journals_in(tmp.path());
        assert!(reports.is_empty());
        assert!(orphan.join("keep.txt").exists());
    }

    // ---- R03: journals must never be trusted by name alone ----

    fn planted_journal(journal_dir: &Path, name: &str, dst: &str, bak: &str) {
        let body = format!("{{\"v\":2,\"dst\":\"{dst}\",\"bak\":\"{bak}\"}}");
        std::fs::write(journal_dir.join(name), body).unwrap();
    }

    #[test]
    fn recover_rejects_journal_with_backup_outside_destination_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("folder");
        let foreign_bak = other.path().join("folder.manifold-old-1");
        std::fs::create_dir(&foreign_bak).unwrap();
        std::fs::write(foreign_bak.join("data.txt"), b"precious").unwrap();

        planted_journal(
            tmp.path(),
            ".manifold-swap-journal-999-0.json",
            &dst.to_string_lossy(),
            &foreign_bak.to_string_lossy(),
        );
        let reports = recover_swap_journals_in(tmp.path());
        assert!(
            reports.iter().any(|r| r.contains("invalid")),
            "foreign backup must be reported as invalid: {reports:?}"
        );
        assert!(
            !dst.exists(),
            "an attacker journal must not create the destination"
        );
        assert!(
            foreign_bak.exists(),
            "an attacker journal must not move a foreign tree"
        );
    }

    #[test]
    fn recover_rejects_journal_pointing_at_unrelated_sibling() {
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("folder");
        let unrelated = tmp.path().join("unrelated.txt");
        std::fs::write(&unrelated, b"do not touch").unwrap();

        planted_journal(
            tmp.path(),
            ".manifold-swap-journal-999-1.json",
            &dst.to_string_lossy(),
            &unrelated.to_string_lossy(),
        );
        let reports = recover_swap_journals_in(tmp.path());
        assert!(reports.iter().any(|r| r.contains("invalid")));
        assert_eq!(std::fs::read(&unrelated).unwrap(), b"do not touch");
        assert!(!dst.exists());
    }

    #[test]
    fn recover_rejects_journal_with_relative_paths() {
        let tmp = tempfile::tempdir().unwrap();
        planted_journal(
            tmp.path(),
            ".manifold-swap-journal-999-2.json",
            "relative/folder",
            "relative/folder.manifold-old-1",
        );
        let reports = recover_swap_journals_in(tmp.path());
        assert!(reports.iter().any(|r| r.contains("invalid")));
        assert!(!Path::new("relative/folder").exists());
    }

    #[test]
    fn recover_still_restores_wellformed_journal() {
        // The validation must not break legitimate recovery: a journal
        // whose backup is a proper `.manifold-old` sibling is honoured.
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("folder");
        let bak = tmp.path().join("folder.manifold-old-42-1");
        std::fs::create_dir(&bak).unwrap();
        std::fs::write(bak.join("data.txt"), b"precious").unwrap();
        planted_journal(
            tmp.path(),
            ".manifold-swap-journal-999-3.json",
            &dst.to_string_lossy(),
            &bak.to_string_lossy(),
        );

        let reports = recover_swap_journals_in(tmp.path());
        assert!(reports.iter().any(|r| r.contains("Recovered")));
        assert_eq!(std::fs::read(dst.join("data.txt")).unwrap(), b"precious");
    }
}
