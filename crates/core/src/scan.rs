use std::collections::{BTreeMap, HashSet};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, SystemTime};

use file_tidy_platform::{LocationKind, MountTable, NodeKind};
use rayon::prelude::*;

use crate::content::{ContentReadPermit, ReadCounters, hash_file, read_prefix};
use crate::policy::Policy;
use crate::*;

#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);
impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ScanPhase {
    Discover,
    Magic,
    PrefixHash,
    FullHash,
    Complete,
}

#[derive(Clone, Copy, Debug)]
pub struct Progress {
    pub discovered: u64,
    pub processed: u64,
    pub bytes_read: u64,
    pub phase: ScanPhase,
}

pub struct ScanOptions {
    pub roots: Vec<PathBuf>,
    pub all_volumes: bool,
    pub metadata_only: bool,
    pub detect_duplicates: bool,
    pub threads: usize,
    pub max_entries: usize,
    pub top_n: usize,
    pub stale_days: u64,
    pub rules: Rules,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            all_volumes: false,
            metadata_only: false,
            detect_duplicates: true,
            threads: std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(2)
                .min(8),
            max_entries: 250_000,
            top_n: 20,
            stale_days: 365,
            rules: Rules::default(),
        }
    }
}

fn skipped(path: PathBuf, reason: SkipReason, detail: &str, incomplete: bool) -> SkippedEntry {
    SkippedEntry {
        path,
        reason,
        detail: detail.to_owned(),
        os_error: None,
        incomplete,
    }
}

fn io_skip(path: PathBuf, error: &io::Error) -> SkippedEntry {
    let (reason, detail) = match error.kind() {
        io::ErrorKind::PermissionDenied => (
            SkipReason::PermissionDenied,
            "读取被拒绝；可检查用户权限，macOS 可手动检查隐私设置",
        ),
        io::ErrorKind::InvalidData => (
            SkipReason::ChangedDuringRead,
            "对象在读取期间发生变化或无法验证",
        ),
        io::ErrorKind::NotFound => (SkipReason::Io, "路径已不存在或扫描期间被移走"),
        io::ErrorKind::InvalidInput => (SkipReason::InvalidRoot, "路径或节点参数无效"),
        io::ErrorKind::Unsupported => (
            SkipReason::IdentityUnavailable,
            "无法取得可靠对象身份，未读取内容",
        ),
        _ => (SkipReason::Io, "读取失败、文件已消失、被占用或不再可访问"),
    };
    let mut entry = skipped(path, reason, detail, true);
    entry.os_error = error.raw_os_error();
    entry
}

fn location_skip(path: PathBuf, kind: LocationKind) -> SkippedEntry {
    match kind {
        LocationKind::Remote => skipped(
            path,
            SkipReason::RemoteFilesystem,
            "远程文件系统不在本地扫描范围",
            true,
        ),
        LocationKind::Virtual => skipped(
            path,
            SkipReason::VirtualFilesystem,
            "虚拟文件系统不读取内容",
            false,
        ),
        _ => skipped(
            path,
            SkipReason::UnknownFilesystem,
            "不能确认文件系统为本地，未遍历",
            true,
        ),
    }
}

fn node_skip(path: PathBuf, kind: NodeKind) -> SkippedEntry {
    match kind {
        NodeKind::Symlink => skipped(path, SkipReason::Symlink, "不跟随符号链接（含断链）", false),
        NodeKind::Reparse => skipped(
            path,
            SkipReason::ReparsePoint,
            "不跟随重解析点、junction 或云占位",
            false,
        ),
        _ => skipped(
            path,
            SkipReason::SpecialNode,
            "不处理设备、socket、FIFO 等特殊节点",
            false,
        ),
    }
}

/// Validate each original component before resolving '..', never traversing a link.
pub(crate) fn resolve_root(path: &Path, mounts: &MountTable) -> Result<PathBuf, SkippedEntry> {
    let absolute = std::path::absolute(path).map_err(|e| io_skip(path.to_owned(), &e))?;
    let mut resolved = PathBuf::new();
    let mut components = absolute.components().peekable();
    while let Some(component) = components.next() {
        match component {
            Component::Prefix(_) | Component::RootDir => resolved.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(part) => {
                resolved.push(part);
                let location = mounts.classify(&resolved);
                if location.kind != LocationKind::Local {
                    return Err(location_skip(resolved, location.kind));
                }
                let node = file_tidy_platform::inspect(&resolved)
                    .map_err(|e| io_skip(resolved.clone(), &e))?;
                if !matches!(node.kind, NodeKind::Directory | NodeKind::Regular) {
                    return Err(node_skip(resolved, node.kind));
                }
                if node.kind == NodeKind::Regular && components.peek().is_some() {
                    return Err(skipped(
                        resolved,
                        SkipReason::InvalidRoot,
                        "普通文件不能作为路径中间目录",
                        true,
                    ));
                }
            }
        }
    }
    let location = mounts.classify(&resolved);
    if location.kind != LocationKind::Local {
        return Err(location_skip(resolved, location.kind));
    }
    Ok(resolved)
}

struct Scanner<'a, F> {
    options: &'a ScanOptions,
    cancel: &'a CancellationToken,
    progress: &'a F,
    policy: Policy,
    mounts: MountTable,
    counters: ReadCounters,
    discovered: AtomicU64,
    processed: AtomicU64,
}

impl<F: Fn(Progress) + Sync> Scanner<'_, F> {
    fn notify(&self, phase: ScanPhase) {
        (self.progress)(Progress {
            discovered: self.discovered.load(Ordering::Relaxed),
            processed: self.processed.load(Ordering::Relaxed),
            bytes_read: self.counters.bytes.load(Ordering::Relaxed),
            phase,
        });
    }

    fn entry(&self, path: &Path, volume: Option<u64>) -> Result<Option<FileEntry>, SkippedEntry> {
        if self.cancel.is_cancelled() {
            return Ok(None);
        }
        let info = file_tidy_platform::inspect(path).map_err(|e| io_skip(path.to_owned(), &e))?;
        if !matches!(info.kind, NodeKind::Regular | NodeKind::Directory) {
            return Err(node_skip(path.to_owned(), info.kind));
        }
        if info.identity.map(|id| id.volume) != volume {
            return Err(skipped(
                path.to_owned(),
                SkipReason::MountBoundary,
                "对象不在扫描根的卷上，不跨卷读取",
                false,
            ));
        }
        let labels = self.policy.labels(path);
        let classification = (info.kind == NodeKind::Regular)
            .then(|| self.options.rules.classify(path, None, info.modified));
        self.processed.fetch_add(1, Ordering::Relaxed);
        Ok(Some(FileEntry {
            id: 0,
            path: path.to_owned(),
            kind: if info.kind == NodeKind::Regular {
                EntryKind::File
            } else {
                EntryKind::Directory
            },
            size_bytes: if info.kind == NodeKind::Regular {
                info.len
            } else {
                0
            },
            allocated_bytes: if info.kind == NodeKind::Regular {
                info.allocated
            } else {
                None
            },
            modified: info.modified.map(Timestamp::from_system),
            hidden: info.hidden,
            policy: labels,
            classification,
            content_inspected: false,
            snapshot: info,
        }))
    }

    fn process_batch(
        &self,
        paths: &[(PathBuf, Option<u64>)],
        pool: &rayon::ThreadPool,
        report: &mut ScanReport,
    ) -> Vec<(PathBuf, file_tidy_platform::NodeInfo)> {
        let outcomes: Vec<_> = pool.install(|| {
            paths
                .par_iter()
                .map(|(p, volume)| self.entry(p, *volume))
                .collect()
        });
        let mut directories = Vec::new();
        for outcome in outcomes {
            match outcome {
                Ok(Some(entry)) => {
                    if entry.kind == EntryKind::Directory {
                        directories.push((entry.path.clone(), entry.snapshot.clone()));
                    }
                    report.entries.push(entry);
                }
                Ok(None) => {}
                Err(skip) => report.skipped.push(skip),
            }
        }
        self.notify(ScanPhase::Discover);
        directories
    }

    fn enrich_contents(&self, report: &mut ScanReport, pool: &rayon::ThreadPool) {
        // Discover every sensitive identity before the first content open.
        let sensitive: HashSet<_> = report
            .entries
            .iter()
            .filter(|e| e.policy.sensitive)
            .filter_map(|e| e.snapshot.identity)
            .collect();
        for entry in &mut report.entries {
            if entry
                .snapshot
                .identity
                .is_some_and(|id| sensitive.contains(&id))
            {
                entry.policy.sensitive = true;
            }
        }
        for batch in report.entries.chunks_mut(256) {
            let notices: Vec<_> = pool.install(|| {
                batch
                    .par_iter_mut()
                    .filter_map(|entry| {
                        if entry.kind != EntryKind::File {
                            return None;
                        }
                        if entry.policy.sensitive {
                            return Some(skipped(
                                entry.path.clone(),
                                SkipReason::SensitiveContent,
                                "敏感项及其已知硬链接别名仅采集元数据，不读取魔数或哈希",
                                false,
                            ));
                        }
                        if self.options.metadata_only || self.cancel.is_cancelled() {
                            return None;
                        }
                        let result = ContentReadPermit::issue(
                            &entry.path,
                            &entry.snapshot,
                            &self.policy,
                            &self.mounts,
                        )
                        .and_then(|permit| {
                            read_prefix(&permit, 16 * 1024, self.cancel, &self.counters)
                        });
                        match result {
                            Ok(prefix) => {
                                entry.content_inspected = true;
                                let mime = infer::get(&prefix).map(|kind| kind.mime_type());
                                entry.classification = Some(self.options.rules.classify(
                                    &entry.path,
                                    mime,
                                    entry.snapshot.modified,
                                ));
                                None
                            }
                            Err(error)
                                if error.kind() == io::ErrorKind::Interrupted
                                    && self.cancel.is_cancelled() =>
                            {
                                None
                            }
                            Err(error) => Some(io_skip(entry.path.clone(), &error)),
                        }
                    })
                    .collect()
            });
            report.skipped.extend(notices);
            self.notify(ScanPhase::Magic);
        }
    }

    fn hash_indices(
        &self,
        indices: &[usize],
        entries: &[FileEntry],
        prefix: bool,
        pool: &rayon::ThreadPool,
        report_skips: &mut Vec<SkippedEntry>,
    ) -> BTreeMap<[u8; 32], Vec<usize>> {
        let phase = if prefix {
            ScanPhase::PrefixHash
        } else {
            ScanPhase::FullHash
        };
        self.notify(phase);
        let hashes: Vec<_> = pool.install(|| {
            indices
                .par_iter()
                .map(|&index| {
                    let entry = &entries[index];
                    if self.cancel.is_cancelled() {
                        return (index, None);
                    }
                    let result = ContentReadPermit::issue(
                        &entry.path,
                        &entry.snapshot,
                        &self.policy,
                        &self.mounts,
                    )
                    .and_then(|permit| {
                        hash_file(
                            &permit,
                            prefix.then_some(64 * 1024),
                            self.cancel,
                            &self.counters,
                            &|| self.notify(phase),
                        )
                    });
                    (index, Some(result))
                })
                .collect()
        });
        let mut groups: BTreeMap<[u8; 32], Vec<usize>> = BTreeMap::new();
        for (index, result) in hashes {
            match result {
                Some(Ok(hash)) => groups.entry(*hash.as_bytes()).or_default().push(index),
                Some(Err(e))
                    if !(e.kind() == io::ErrorKind::Interrupted && self.cancel.is_cancelled()) =>
                {
                    report_skips.push(io_skip(entries[index].path.clone(), &e))
                }
                _ => {}
            }
        }
        groups
    }

    fn duplicates(&self, report: &mut ScanReport, pool: &rayon::ThreadPool) -> Result<(), Error> {
        let mut sizes: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        let mut identities = HashSet::new();
        for (index, entry) in report.entries.iter().enumerate() {
            if entry.kind != EntryKind::File || entry.policy.sensitive || !entry.content_inspected {
                continue;
            }
            if let Some(identity) = entry.snapshot.identity
                && identities.insert(identity)
            {
                sizes.entry(entry.size_bytes).or_default().push(index);
            }
        }
        for indices in sizes.values().filter(|indices| indices.len() > 1) {
            if self.cancel.is_cancelled() {
                break;
            }
            let prefixes =
                self.hash_indices(indices, &report.entries, true, pool, &mut report.skipped);
            for candidates in prefixes.values().filter(|indices| indices.len() > 1) {
                if self.cancel.is_cancelled() {
                    break;
                }
                let full = self.hash_indices(
                    candidates,
                    &report.entries,
                    false,
                    pool,
                    &mut report.skipped,
                );
                for (hash, indices) in full {
                    let mut stable = Vec::new();
                    for i in indices {
                        let entry = &report.entries[i];
                        match file_tidy_platform::inspect(&entry.path) {
                            Ok(info) if entry.snapshot.matches(&info) => stable.push(i),
                            Ok(_) => report.skipped.push(skipped(
                                entry.path.clone(),
                                SkipReason::ChangedDuringRead,
                                "完整哈希后对象发生变化，已排除重复组",
                                true,
                            )),
                            Err(error) => report.skipped.push(io_skip(entry.path.clone(), &error)),
                        }
                    }
                    if stable.len() < 2 {
                        continue;
                    }
                    let size = report.entries[stable[0]].size_bytes;
                    report.duplicates.push(DuplicateGroup {
                        entry_ids: stable.iter().map(|&i| report.entries[i].id).collect(),
                        size_bytes: size,
                        duplicate_logical_bytes: size
                            .checked_mul((stable.len() - 1) as u64)
                            .ok_or(Error::SizeOverflow)?,
                        blake3: blake3::Hash::from_bytes(hash).to_hex().to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

pub fn scan(
    options: ScanOptions,
    cancel: &CancellationToken,
    progress: impl Fn(Progress) + Sync,
) -> Result<ScanReport, Error> {
    if options.threads == 0
        || options.threads > 64
        || options.max_entries == 0
        || options.max_entries > 1_000_000
    {
        return Err(Error::InvalidOptions(
            "threads must be 1..=64 and max_entries 1..=1000000".to_owned(),
        ));
    }
    if options.roots.is_empty() != options.all_volumes {
        return Err(Error::InvalidOptions(
            "provide roots or --all, exclusively".to_owned(),
        ));
    }
    let stale_seconds = options
        .stale_days
        .checked_mul(86400)
        .ok_or_else(|| Error::InvalidOptions("stale-days overflow".to_owned()))?;
    let mounts = MountTable::read().map_err(Error::Inventory)?;
    let roots = if options.all_volumes {
        mounts.roots()
    } else {
        options.roots.clone()
    };
    let now = SystemTime::now();
    let scanner = Scanner {
        options: &options,
        cancel,
        progress: &progress,
        policy: Policy::new(),
        mounts,
        counters: ReadCounters::default(),
        discovered: AtomicU64::new(0),
        processed: AtomicU64::new(0),
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(options.threads)
        .build()
        .map_err(Error::WorkerPool)?;
    let mut report = ScanReport {
        schema_version: 1,
        scanned_at: Timestamp::from_system(now),
        summary: Summary::default(),
        entries: Vec::new(),
        directory_usage: Vec::new(),
        top_entry_ids: Vec::new(),
        stale_entry_ids: Vec::new(),
        duplicates: Vec::new(),
        skipped: Vec::new(),
        suggested_directories: Vec::new(),
        notices: vec![
            "只读模式；无授权、计划或文件修改。大小为逻辑字节；重复字节不等于可释放物理空间。"
                .to_owned(),
        ],
    };
    if options.metadata_only {
        report
            .notices
            .push("仅元数据模式：未读取魔数或哈希。".to_owned());
    }
    if options.all_volumes && roots.is_empty() {
        report
            .notices
            .push("未找到可确认的本地卷；扫描不完整。".to_owned());
        report.summary.complete = false;
    }
    report
        .notices
        .extend(scanner.policy.warnings().iter().cloned());
    if options.all_volumes {
        report.skipped.extend(
            scanner
                .mounts
                .entries()
                .iter()
                .filter(|location| location.kind != LocationKind::Local)
                .map(|location| location_skip(location.mount_root.clone(), location.kind)),
        );
    }
    let mut seen = HashSet::new();
    'roots: for requested in &roots {
        if cancel.is_cancelled() {
            break;
        }
        let root = match resolve_root(requested, &scanner.mounts) {
            Ok(root) => root,
            Err(mut skip) => {
                skip.incomplete = true;
                report.skipped.push(skip);
                continue;
            }
        };
        let root_volume = file_tidy_platform::inspect(&root)
            .ok()
            .and_then(|node| node.identity.map(|id| id.volume));
        if root_volume.is_none() {
            report.skipped.push(skipped(
                root.clone(),
                SkipReason::IdentityUnavailable,
                "无法确定扫描根的卷身份，未递归遍历",
                true,
            ));
            continue;
        }
        let mut frontier = vec![root.clone()];
        while !frontier.is_empty() {
            if cancel.is_cancelled() {
                break 'roots;
            }
            let mut batch = Vec::with_capacity(256);
            while batch.len() < 256 {
                let Some(path) = frontier.pop() else {
                    break;
                };
                let location = scanner.mounts.classify(&path);
                if location.kind != LocationKind::Local || scanner.mounts.is_boundary(&root, &path)
                {
                    report
                        .skipped
                        .push(if location.kind != LocationKind::Local {
                            location_skip(path, location.kind)
                        } else {
                            skipped(
                                path,
                                SkipReason::MountBoundary,
                                "不跨挂载点（包括普通文件bind mount）；全盘模式逐本地卷扫描",
                                false,
                            )
                        });
                    continue;
                }
                if !seen.insert(path.clone()) {
                    continue;
                }
                if scanner.discovered.load(Ordering::Relaxed) >= options.max_entries as u64 {
                    report.summary.limit_reached = true;
                    break;
                }
                scanner.discovered.fetch_add(1, Ordering::Relaxed);
                batch.push((path, root_volume));
            }
            let directories = scanner.process_batch(&batch, &pool, &mut report);
            for (path, expected) in directories {
                if cancel.is_cancelled() {
                    break 'roots;
                }
                let remaining = options.max_entries.saturating_sub(
                    scanner.discovered.load(Ordering::Relaxed) as usize + frontier.len(),
                );
                // Unlike walkdir, no directory is opened before policy, mount,
                // node type and volume checks. The platform opens by no-follow handles.
                match file_tidy_platform::read_directory_verified(&path, &expected, remaining) {
                    Ok(listing) => {
                        if listing.truncated {
                            report.summary.limit_reached = true;
                        }
                        frontier.extend(listing.names.into_iter().map(|name| path.join(name)));
                    }
                    Err(error) => report.skipped.push(io_skip(path, &error)),
                }
            }
            if frontier.is_empty() && report.summary.limit_reached {
                break 'roots;
            }
        }
    }
    report.entries.sort_by(|a, b| a.path.cmp(&b.path));
    for (index, entry) in report.entries.iter_mut().enumerate() {
        entry.id = index as u64 + 1;
    }
    scanner.enrich_contents(&mut report, &pool);
    if options.detect_duplicates && !options.metadata_only && !cancel.is_cancelled() {
        scanner.duplicates(&mut report, &pool)?;
    }
    summarize(&mut report, &options, now, stale_seconds)?;
    report.summary.cancelled = cancel.is_cancelled();
    report.summary.complete = !report.summary.cancelled
        && !report.summary.limit_reached
        && !report.skipped.iter().any(|s| s.incomplete)
        && !roots.is_empty();
    report.summary.content_bytes_read = scanner.counters.bytes.load(Ordering::Relaxed);
    report.summary.content_open_operations = scanner.counters.opens.load(Ordering::Relaxed);
    scanner.notify(ScanPhase::Complete);
    Ok(report)
}

fn summarize(
    report: &mut ScanReport,
    options: &ScanOptions,
    now: SystemTime,
    stale_seconds: u64,
) -> Result<(), Error> {
    let mut directories: BTreeMap<PathBuf, (u64, u64)> = report
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::Directory)
        .map(|e| (e.path.clone(), (0, 0)))
        .collect();
    let mut identities = HashSet::new();
    let mut allocated = Some(0_u64);
    for entry in &report.entries {
        report.summary.entries += 1;
        if entry.kind == EntryKind::Directory {
            report.summary.directories += 1;
            continue;
        }
        report.summary.files += 1;
        report.summary.logical_bytes = report
            .summary
            .logical_bytes
            .checked_add(entry.size_bytes)
            .ok_or(Error::SizeOverflow)?;
        if entry
            .snapshot
            .identity
            .is_none_or(|id| identities.insert(id))
        {
            report.summary.unique_file_logical_bytes = report
                .summary
                .unique_file_logical_bytes
                .checked_add(entry.size_bytes)
                .ok_or(Error::SizeOverflow)?;
            allocated = match (allocated, entry.allocated_bytes) {
                (Some(sum), Some(n)) => Some(sum.checked_add(n).ok_or(Error::SizeOverflow)?),
                _ => None,
            };
        }
        let mut ancestor = entry.path.parent();
        while let Some(path) = ancestor {
            if let Some((files, size)) = directories.get_mut(path) {
                *files += 1;
                *size = size
                    .checked_add(entry.size_bytes)
                    .ok_or(Error::SizeOverflow)?;
            }
            ancestor = path.parent();
        }
        if entry
            .snapshot
            .modified
            .and_then(|m| now.duration_since(m).ok())
            .is_some_and(|age| age > Duration::from_secs(stale_seconds))
        {
            report.stale_entry_ids.push(entry.id);
        }
    }
    let mut top: Vec<_> = report
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::File)
        .collect();
    top.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes).then(a.path.cmp(&b.path)));
    report.top_entry_ids = top.iter().take(options.top_n).map(|e| e.id).collect();
    report.directory_usage = directories
        .into_iter()
        .map(|(path, (files, logical_bytes))| DirectoryUsage {
            path,
            files,
            logical_bytes,
        })
        .collect();
    report.summary.unique_allocated_bytes = allocated;
    report.summary.skipped = report.skipped.len() as u64;
    Ok(())
}
