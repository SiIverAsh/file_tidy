use std::collections::HashMap;
use std::io;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocationKind {
    Local,
    Remote,
    Virtual,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct LocationInfo {
    pub kind: LocationKind,
    pub mount_root: PathBuf,
    pub filesystem: String,
}

#[derive(Clone, Debug)]
pub struct MountTable {
    entries: Vec<LocationInfo>,
    // Linux mountinfo coordinates describe the underlying filesystem subtree,
    // including bind mounts whose visible names omit a sensitive ancestor.
    coordinates: HashMap<PathBuf, MountCoordinate>,
}

#[derive(Clone, Debug)]
struct MountCoordinate {
    device: (u64, u64),
    fs_root: PathBuf,
}

impl MountTable {
    pub fn read() -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        let mut table = Self {
            entries: macos::read()?,
            coordinates: HashMap::new(),
        };
        #[cfg(target_os = "linux")]
        let mut table = linux::read()?;
        #[cfg(windows)]
        let mut table = Self {
            entries: crate::windows::mounts()?,
            coordinates: HashMap::new(),
        };
        table
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.mount_root.components().count()));
        Ok(table)
    }

    /// Compare locations inside the same underlying Linux filesystem, without
    /// following a path or reading any content. This supplements lexical policy
    /// prefixes for bind aliases such as /alias -> ~/.ssh/subdirectory.
    /// Returns false where coordinates cannot be proven (including macOS and
    /// Windows, whose policy aliases use native directory identities instead).
    pub fn is_alias_beneath(&self, path: &Path, root: &Path) -> bool {
        if !root.is_absolute()
            || root
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return false;
        }
        let Some((device, path)) = self.physical_coordinate(path) else {
            return false;
        };
        if self
            .physical_coordinate(root)
            .is_some_and(|(root_device, root_path)| {
                device == root_device && path.starts_with(root_path)
            })
        {
            return true;
        }
        // A protected/sensitive namespace subtree can include mounted children
        // from other devices. Their active filesystem roots belong to that
        // subtree too, even though the namespace root's own device differs.
        // Hidden mounts were removed before this coordinate map was built.
        self.coordinates.iter().any(|(mount_root, coordinate)| {
            mount_root.starts_with(root)
                && coordinate.device == device
                && path.starts_with(&coordinate.fs_root)
        })
    }

    /// Linux filesystem-internal path for policy-name checks. This is metadata,
    /// not an operation path: callers must never open it as a process path.
    pub fn filesystem_relative_path(&self, path: &Path) -> Option<PathBuf> {
        self.physical_coordinate(path).map(|(_, path)| path)
    }

    fn physical_coordinate(&self, path: &Path) -> Option<((u64, u64), PathBuf)> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return None;
        }
        let location = self
            .entries
            .iter()
            .find(|entry| has_prefix(path, &entry.mount_root))?;
        let mount = self.coordinates.get(&location.mount_root)?;
        let relative = path.strip_prefix(&location.mount_root).ok()?;
        Some((mount.device, mount.fs_root.join(relative)))
    }

    pub fn entries(&self) -> &[LocationInfo] {
        &self.entries
    }

    /// Longest component-prefix lookup in this immutable snapshot. Callers must
    /// also compare volume identities to detect firmlinks and refresh the table
    /// before content reads. A mount table is not an atomic filesystem snapshot.
    pub fn classify(&self, path: &Path) -> LocationInfo {
        self.entries
            .iter()
            .find(|entry| has_prefix(path, &entry.mount_root))
            .cloned()
            .unwrap_or_else(|| LocationInfo {
                kind: LocationKind::Unknown,
                mount_root: PathBuf::new(),
                filesystem: "unknown".into(),
            })
    }

    pub fn roots(&self) -> Vec<PathBuf> {
        let mut roots: Vec<_> = self
            .entries
            .iter()
            .filter(|entry| entry.kind == LocationKind::Local)
            .map(|entry| entry.mount_root.clone())
            .collect();
        #[cfg(windows)]
        {
            // FindFirstVolume supplies one canonical GUID root per volume. Drive
            // letters and mounted folders remain lookup aliases, not duplicate
            // scan tasks (mounted folder roots are themselves reparse points).
            let guid_roots: Vec<_> = roots
                .iter()
                .filter(|root| crate::windows::is_volume_guid_root(root))
                .cloned()
                .collect();
            if !guid_roots.is_empty() {
                roots = guid_roots;
            }
        }
        roots.sort();
        roots.dedup();
        roots
    }

    pub fn is_boundary(&self, root: &Path, path: &Path) -> bool {
        let a = self.classify(root);
        let b = self.classify(path);
        a.kind != LocationKind::Local
            || b.kind != LocationKind::Local
            || a.mount_root != b.mount_root
    }
}

#[cfg(not(windows))]
fn has_prefix(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

#[cfg(windows)]
fn has_prefix(path: &Path, root: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    // Comparison only; never used to reconstruct an operation path. Native
    // drive roots are ASCII. Keep non-ASCII code units unchanged and conservative.
    fn key(path: &Path) -> Vec<u16> {
        let units: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .map(|u| {
                if (b'a' as u16..=b'z' as u16).contains(&u) {
                    u - 32
                } else {
                    u
                }
            })
            .collect();
        let prefix: Vec<u16> = "\\\\?\\".encode_utf16().collect();
        if units.starts_with(&prefix) {
            units[4..].to_vec()
        } else {
            units
        }
    }
    let path_key = key(path);
    let root_key = key(root);
    path_key.starts_with(&root_key)
        && (root_key.last() == Some(&(b'\\' as u16))
            || path_key.len() == root_key.len()
            || path_key.get(root_key.len()) == Some(&(b'\\' as u16)))
}

#[cfg(any(target_os = "linux", all(test, unix)))]
mod linux {
    use super::{LocationInfo, LocationKind, MountCoordinate, MountTable};
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::ffi::OsString;
    #[cfg(target_os = "linux")]
    use std::fs;
    use std::io;
    use std::os::unix::ffi::OsStringExt;
    use std::path::{Path, PathBuf};

    #[cfg(target_os = "linux")]
    pub(super) fn read() -> io::Result<MountTable> {
        parse(&fs::read("/proc/self/mountinfo")?)
    }

    fn decode(input: &[u8]) -> io::Result<Vec<u8>> {
        let mut result = Vec::with_capacity(input.len());
        let mut i = 0;
        while i < input.len() {
            if input[i] == b'\\' {
                let octal = input
                    .get(i + 1..i + 4)
                    .ok_or_else(|| io::Error::other("invalid mount escape"))?;
                if !octal.iter().all(|b| (b'0'..=b'7').contains(b)) {
                    return Err(io::Error::other("invalid mount escape"));
                }
                let value = (u16::from(octal[0] - b'0') * 64)
                    + (u16::from(octal[1] - b'0') * 8)
                    + u16::from(octal[2] - b'0');
                result.push(
                    u8::try_from(value).map_err(|_| io::Error::other("invalid mount escape"))?,
                );
                i += 4;
            } else {
                result.push(input[i]);
                i += 1;
            }
        }
        Ok(result)
    }

    #[derive(Clone)]
    struct MountRecord {
        id: u64,
        parent: u64,
        location: LocationInfo,
        coordinate: MountCoordinate,
    }

    fn mount_id(value: Option<&&[u8]>) -> io::Result<u64> {
        value
            .and_then(|value| std::str::from_utf8(value).ok())
            .and_then(|text| text.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid mount ID"))
    }

    // A stack's top mount has the previous mount as its parent. Walk same-path
    // parents to find the containing mount to which the bottom was attached.
    fn containing_mount(id: u64, records: &HashMap<u64, MountRecord>) -> Option<Option<u64>> {
        let mut current = id;
        for _ in 0..=records.len() {
            let record = records.get(&current)?;
            if record.parent == record.id {
                return (record.location.mount_root == Path::new("/")).then_some(None);
            }
            let Some(parent) = records.get(&record.parent) else {
                return Some(if record.location.mount_root == Path::new("/") {
                    None // Root's parent may lie outside the process root.
                } else {
                    Some(record.parent)
                });
            };
            if parent.location.mount_root != record.location.mount_root {
                return Some(Some(parent.id));
            }
            current = parent.id;
        }
        None // Malformed cycle: no safe topology can be inferred.
    }

    fn visible_locations(records: HashMap<u64, MountRecord>) -> io::Result<MountTable> {
        let mut paths: BTreeMap<PathBuf, Vec<u64>> = BTreeMap::new();
        let mut covered = HashSet::new();
        for record in records.values() {
            if record.parent == record.id && record.location.mount_root != Path::new("/") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "non-root mount has itself as parent",
                ));
            }
            if let Some(parent) = records.get(&record.parent)
                && !record
                    .location
                    .mount_root
                    .starts_with(&parent.location.mount_root)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mount parent is not an ancestor",
                ));
            }
            paths
                .entry(record.location.mount_root.clone())
                .or_default()
                .push(record.id);
            if record.parent != record.id
                && records
                    .get(&record.parent)
                    .is_some_and(|parent| parent.location.mount_root == record.location.mount_root)
            {
                covered.insert(record.parent);
            }
        }
        if !paths.contains_key(Path::new("/")) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "namespace root missing from mountinfo",
            ));
        }
        let mut paths: Vec<_> = paths.into_iter().collect();
        paths.sort_by_key(|(path, _)| path.components().count());
        let mut visible: HashMap<PathBuf, (Option<u64>, LocationInfo)> = HashMap::new();
        for (path, ids) in paths {
            let ancestor = path
                .ancestors()
                .skip(1)
                .find_map(|parent| visible.get(parent));
            if ancestor.is_some_and(|(id, _)| id.is_none()) {
                // An ambiguous ancestor must never be overridden by a stale
                // longer prefix from a possibly hidden child mount.
                continue;
            }
            let expected_parent = ancestor.and_then(|(id, _)| *id);
            let mut candidates = Vec::new();
            let top_ids: Vec<_> = ids.into_iter().filter(|id| !covered.contains(id)).collect();
            let mut unresolved = top_ids.is_empty();
            for id in top_ids {
                match containing_mount(id, &records) {
                    Some(parent) if parent == expected_parent => candidates.push(id),
                    Some(Some(parent)) if !records.contains_key(&parent) => unresolved = true,
                    None => unresolved = true,
                    _ => {} // Its attachment is hidden by another visible mount.
                }
            }
            if candidates.len() == 1 && !unresolved {
                if let Some(record) = records.get(&candidates[0]) {
                    visible.insert(path, (Some(record.id), record.location.clone()));
                }
            } else if unresolved || candidates.len() > 1 || path == Path::new("/") {
                let location = LocationInfo {
                    kind: LocationKind::Unknown,
                    mount_root: path.clone(),
                    filesystem: "ambiguous-mount-topology".into(),
                };
                visible.insert(path, (None, location));
            }
            // No candidates and no ambiguity means this path belongs entirely
            // to a covered ancestor. Omit it so it cannot shadow the live mount.
        }
        let mut coordinates = HashMap::new();
        let mut locations = Vec::new();
        for (_, (id, location)) in visible {
            if let Some(record) = id.and_then(|id| records.get(&id)) {
                coordinates.insert(location.mount_root.clone(), record.coordinate.clone());
            }
            locations.push(location);
        }
        locations
            .sort_by_key(|location| std::cmp::Reverse(location.mount_root.components().count()));
        Ok(MountTable {
            entries: locations,
            coordinates,
        })
    }

    fn parse(input: &[u8]) -> io::Result<MountTable> {
        let mut records = HashMap::new();
        for line in input.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
            let fields: Vec<_> = line.split(|b| *b == b' ').collect();
            let separator = fields.iter().position(|f| *f == b"-").ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid mountinfo separator")
            })?;
            let root = fields.get(4).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid mountinfo mount path")
            })?;
            let fs = fields.get(separator + 1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid mountinfo filesystem")
            })?;
            let filesystem = std::str::from_utf8(fs)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid filesystem name"))?
                .to_owned();
            let kind = match filesystem.as_str() {
                "ext2" | "ext3" | "ext4" | "btrfs" | "xfs" | "f2fs" | "jfs" | "reiserfs"
                | "vfat" | "exfat" | "ntfs" | "ntfs3" | "iso9660" | "udf" | "zfs" | "tmpfs"
                | "ramfs" | "overlay" | "squashfs" | "erofs" => LocationKind::Local,
                "proc" | "sysfs" | "devtmpfs" | "devpts" | "cgroup" | "cgroup2" | "securityfs"
                | "debugfs" | "tracefs" | "pstore" | "configfs" | "fusectl" | "mqueue"
                | "hugetlbfs" | "autofs" | "binfmt_misc" | "bpf" | "nsfs" => LocationKind::Virtual,
                "nfs" | "nfs4" | "cifs" | "smb3" | "9p" | "ceph" | "afs" | "glusterfs" => {
                    LocationKind::Remote
                }
                _ => LocationKind::Unknown,
            };
            let path = PathBuf::from(OsString::from_vec(decode(root)?));
            if !path.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "non-absolute mount path",
                ));
            }
            let id = mount_id(fields.first())?;
            let parent = mount_id(fields.get(1))?;
            let device = fields
                .get(2)
                .and_then(|value| std::str::from_utf8(value).ok())
                .and_then(|value| value.split_once(':'))
                .and_then(|(major, minor)| Some((major.parse().ok()?, minor.parse().ok()?)))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid mount device")
                })?;
            let fs_root = fields.get(3).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing filesystem root")
            })?;
            let fs_root = PathBuf::from(OsString::from_vec(decode(fs_root)?));
            if !fs_root.is_absolute()
                || fs_root
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid filesystem root",
                ));
            }
            let coordinate = MountCoordinate { device, fs_root };
            let location = LocationInfo {
                kind,
                mount_root: path,
                filesystem,
            };
            if records
                .insert(
                    id,
                    MountRecord {
                        id,
                        parent,
                        location,
                        coordinate,
                    },
                )
                .is_some()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate mount ID",
                ));
            }
        }
        if records.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty mount table",
            ));
        }
        visible_locations(records)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::ffi::OsStrExt;

        #[test]
        fn preserves_mount_bytes_and_bind_entries() -> io::Result<()> {
            let table = parse(b"1 0 8:1 / / rw - ext4 /dev/a rw\n2 1 8:1 /src /bind\\040x\\377 rw - ext4 /dev/a rw\n3 1 0:1 / /proc rw - proc proc rw\n")?;
            assert_eq!(table.entries.len(), 3);
            assert!(
                table
                    .entries
                    .iter()
                    .any(|entry| entry.mount_root.as_os_str().as_bytes() == b"/bind x\xff")
            );
            assert_eq!(
                table.classify(Path::new("/proc/test")).kind,
                LocationKind::Virtual
            );
            Ok(())
        }

        #[test]
        fn stacked_mounts_select_visible_remote_or_local_top() -> io::Result<()> {
            let remote = parse(b"1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 0:7 / /mnt rw - tmpfs tmpfs rw\n3 2 0:8 / /mnt rw - nfs4 host:/ rw\n")?;
            assert_eq!(
                remote.classify(Path::new("/mnt/file")).kind,
                LocationKind::Remote
            );
            assert!(!remote.roots().contains(&PathBuf::from("/mnt")));
            let local = parse(b"1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 0:8 / /mnt rw - nfs4 host:/ rw\n3 2 0:7 / /mnt rw - tmpfs tmpfs rw\n")?;
            assert_eq!(
                local.classify(Path::new("/mnt/file")).kind,
                LocationKind::Local
            );
            assert!(local.roots().contains(&PathBuf::from("/mnt")));
            Ok(())
        }

        #[test]
        fn hidden_descendants_cannot_shadow_a_live_parent() -> io::Result<()> {
            let table = parse(b"1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 0:7 / /mnt rw - tmpfs tmpfs rw\n3 2 8:2 / /mnt/old rw - ext4 /dev/old rw\n4 2 0:8 / /mnt rw - nfs4 host:/ rw\n5 3 8:3 / /mnt/old/deep rw - ext4 /dev/hidden rw\n6 4 8:4 / /mnt/new rw - ext4 /dev/new rw\n")?;
            assert_eq!(
                table.classify(Path::new("/mnt/old/file")).kind,
                LocationKind::Remote
            );
            assert_eq!(
                table.classify(Path::new("/mnt/old/deep/file")).kind,
                LocationKind::Remote
            );
            assert!(!table.roots().contains(&PathBuf::from("/mnt/old")));
            assert_eq!(
                table.classify(Path::new("/mnt/new/file")).kind,
                LocationKind::Local
            );
            Ok(())
        }

        #[test]
        fn bind_coordinates_preserve_sensitive_and_protected_subtrees() -> io::Result<()> {
            let table = parse(b"1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 8:1 /home/user/.ssh/subdir /alias rw - ext4 /dev/root rw\n3 1 8:1 /usr/share /library-alias rw - ext4 /dev/root rw\n4 1 8:2 /home/user/.ssh/subdir /different-device rw - ext4 /dev/other rw\n5 1 8:1 /secrets/.env /ordinary rw - ext4 /dev/root rw\n")?;
            assert!(
                table.is_alias_beneath(Path::new("/alias/config"), Path::new("/home/user/.ssh"))
            );
            assert!(table.is_alias_beneath(Path::new("/library-alias/doc"), Path::new("/usr")));
            assert!(!table.is_alias_beneath(
                Path::new("/alias/config"),
                Path::new("/home/user/.ssh-other")
            ));
            assert!(!table.is_alias_beneath(
                Path::new("/different-device/config"),
                Path::new("/home/user/.ssh")
            ));
            assert!(table.is_boundary(Path::new("/"), Path::new("/alias/config")));
            assert_eq!(
                table
                    .filesystem_relative_path(Path::new("/ordinary"))
                    .as_deref(),
                Some(Path::new("/secrets/.env"))
            );
            Ok(())
        }

        #[test]
        fn nested_devices_belong_to_the_root_but_hidden_children_do_not() -> io::Result<()> {
            let table = parse(b"1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 8:2 /vault/secrets /home/user/.ssh/keys rw - ext4 /dev/private rw\n3 1 8:2 /vault/secrets /alias rw - ext4 /dev/private rw\n4 1 8:3 /special/resolv.conf /etc/resolv.conf rw - ext4 /dev/config rw\n5 1 8:3 /special/resolv.conf /plain-file rw - ext4 /dev/config rw\n6 1 8:2 /vault/public /unrelated rw - ext4 /dev/private rw\n")?;
            assert!(table.is_alias_beneath(Path::new("/alias/key"), Path::new("/home/user/.ssh")));
            assert!(table.is_alias_beneath(Path::new("/plain-file"), Path::new("/etc")));
            assert!(
                !table.is_alias_beneath(Path::new("/unrelated/doc"), Path::new("/home/user/.ssh"))
            );
            let hidden = parse(b"1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 8:10 / /home/user/.ssh rw - ext4 /dev/old rw\n3 2 8:2 /vault/secrets /home/user/.ssh/keys rw - ext4 /dev/private rw\n4 2 8:11 / /home/user/.ssh rw - ext4 /dev/new rw\n5 1 8:2 /vault/secrets /alias rw - ext4 /dev/private rw\n")?;
            assert!(
                !hidden.is_alias_beneath(Path::new("/alias/key"), Path::new("/home/user/.ssh"))
            );
            assert!(
                !hidden
                    .entries
                    .iter()
                    .any(|entry| entry.mount_root == Path::new("/home/user/.ssh/keys"))
            );
            Ok(())
        }

        #[test]
        fn process_root_coordinate_and_cycles_are_handled_conservatively() -> io::Result<()> {
            let table = parse(b"1 0 8:1 /container / rw - ext4 /dev/root rw\n2 1 8:1 /container/home/user/.ssh/subdir /alias rw - ext4 /dev/root rw\n")?;
            assert!(
                table.is_alias_beneath(Path::new("/alias/config"), Path::new("/home/user/.ssh"))
            );
            let cycle = parse(b"1 0 8:1 / / rw - ext4 /dev/root rw\n2 3 8:2 / /mnt rw - ext4 /dev/a rw\n3 2 0:8 / /mnt rw - nfs4 host:/ rw\n")?;
            assert_eq!(
                cycle.classify(Path::new("/mnt/file")).kind,
                LocationKind::Unknown
            );
            Ok(())
        }

        #[test]
        fn ambiguous_or_missing_parent_fails_closed() -> io::Result<()> {
            let table = parse(b"1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 8:2 / /mnt rw - ext4 /dev/a rw\n3 1 0:8 / /mnt rw - nfs4 host:/ rw\n4 99 8:3 / /unresolved rw - ext4 /dev/unknown rw\n")?;
            assert_eq!(
                table.classify(Path::new("/mnt/file")).kind,
                LocationKind::Unknown
            );
            assert_eq!(
                table.classify(Path::new("/unresolved/file")).kind,
                LocationKind::Unknown
            );
            Ok(())
        }

        #[test]
        fn malformed_escapes_are_rejected() {
            assert!(parse(b"1 0 8:1 / /bad\\777 rw - ext4 /dev/a rw\n").is_err());
            assert!(parse(b"1 0 8:1 / /bad\\xx0 rw - ext4 /dev/a rw\n").is_err());
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn detects_nested_bind_mounts_and_component_prefixes() {
        let table = MountTable {
            coordinates: HashMap::new(),
            entries: vec![
                LocationInfo {
                    kind: LocationKind::Local,
                    mount_root: PathBuf::from("/bind"),
                    filesystem: "ext4".into(),
                },
                LocationInfo {
                    kind: LocationKind::Virtual,
                    mount_root: PathBuf::from("/proc"),
                    filesystem: "proc".into(),
                },
                LocationInfo {
                    kind: LocationKind::Local,
                    mount_root: PathBuf::from("/"),
                    filesystem: "ext4".into(),
                },
            ],
        };
        assert!(table.is_boundary(Path::new("/"), Path::new("/bind/file")));
        assert!(table.is_boundary(Path::new("/"), Path::new("/proc/file")));
        assert!(!table.is_boundary(Path::new("/"), Path::new("/bind2/file")));
        assert!(!table.is_boundary(Path::new("/bind"), Path::new("/bind/file")));
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{LocationInfo, LocationKind};
    use std::ffi::OsString;
    use std::io;
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;

    pub(super) fn read() -> io::Result<Vec<LocationInfo>> {
        // SAFETY: a null buffer and zero length asks getfsstat for a count.
        // getfsstat uses caller-owned storage and avoids getmntinfo's shared buffer.
        let count = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        let capacity = usize::try_from(count)
            .map_err(|_| io::Error::other("mount count overflow"))?
            .checked_add(32)
            .ok_or_else(|| io::Error::other("mount count overflow"))?;
        // SAFETY: statfs is a C aggregate of integer fields and fixed-size arrays;
        // all-zero initialization is valid. Vec length exactly matches capacity.
        let mut buffer: Vec<libc::statfs> = (0..capacity)
            .map(|_| unsafe { std::mem::zeroed() })
            .collect();
        let byte_len = capacity
            .checked_mul(std::mem::size_of::<libc::statfs>())
            .and_then(|n| i32::try_from(n).ok())
            .ok_or_else(|| io::Error::other("mount buffer overflow"))?;
        // SAFETY: buffer has byte_len writable bytes, lives through the call, and
        // getfsstat does not retain its pointer. MNT_NOWAIT avoids server refreshes.
        let written = unsafe { libc::getfsstat(buffer.as_mut_ptr(), byte_len, libc::MNT_NOWAIT) };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        let written =
            usize::try_from(written).map_err(|_| io::Error::other("mount count overflow"))?;
        if written >= capacity {
            return Err(io::Error::other(
                "mount table changed during enumeration; retry scan",
            ));
        }
        let mut entries = Vec::new();
        for entry in buffer.into_iter().take(written) {
            let bytes = |chars: &[libc::c_char]| {
                chars
                    .iter()
                    .take_while(|c| **c != 0)
                    .map(|c| *c as u8)
                    .collect::<Vec<_>>()
            };
            let filesystem = String::from_utf8(bytes(&entry.f_fstypename))
                .map_err(|_| io::Error::other("invalid filesystem name"))?;
            let kind = if entry.f_flags & (libc::MNT_LOCAL as u32) == 0 {
                LocationKind::Remote
            } else {
                match filesystem.as_str() {
                    "apfs" | "hfs" | "msdos" | "exfat" | "ntfs" | "udf" | "cd9660" => {
                        LocationKind::Local
                    }
                    "devfs" | "autofs" => LocationKind::Virtual,
                    _ => LocationKind::Unknown,
                }
            };
            entries.push(LocationInfo {
                kind,
                mount_root: PathBuf::from(OsString::from_vec(bytes(&entry.f_mntonname))),
                filesystem,
            });
        }
        if entries.is_empty() {
            return Err(io::Error::other("empty mount table"));
        }
        Ok(entries)
    }
}
