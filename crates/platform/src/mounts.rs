use std::io;
use std::path::{Path, PathBuf};

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
}

impl MountTable {
    pub fn read() -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        let mut entries = macos::read()?;
        #[cfg(target_os = "linux")]
        let mut entries = linux::read()?;
        #[cfg(windows)]
        let mut entries = crate::windows::mounts()?;
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.mount_root.components().count()));
        Ok(Self { entries })
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
    use super::{LocationInfo, LocationKind};
    use std::ffi::OsString;
    #[cfg(target_os = "linux")]
    use std::fs;
    use std::io;
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;

    #[cfg(target_os = "linux")]
    pub(super) fn read() -> io::Result<Vec<LocationInfo>> {
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

    fn parse(input: &[u8]) -> io::Result<Vec<LocationInfo>> {
        let mut entries = Vec::new();
        for line in input.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
            let fields: Vec<_> = line.split(|b| *b == b' ').collect();
            let separator = fields
                .iter()
                .position(|f| *f == b"-")
                .ok_or_else(|| io::Error::other("invalid mountinfo separator"))?;
            let root = fields
                .get(4)
                .ok_or_else(|| io::Error::other("invalid mountinfo mount path"))?;
            let fs = fields
                .get(separator + 1)
                .ok_or_else(|| io::Error::other("invalid mountinfo filesystem"))?;
            let filesystem = std::str::from_utf8(fs)
                .map_err(|_| io::Error::other("invalid filesystem name"))?
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
            entries.push(LocationInfo {
                kind,
                mount_root: PathBuf::from(OsString::from_vec(decode(root)?)),
                filesystem,
            });
        }
        if entries.is_empty() {
            return Err(io::Error::other("empty mount table"));
        }
        Ok(entries)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::ffi::OsStrExt;

        #[test]
        fn preserves_mount_bytes_and_bind_entries() -> io::Result<()> {
            let entries = parse(b"1 0 8:1 / / rw - ext4 /dev/a rw\n2 1 8:1 /src /bind\\040x\\377 rw - ext4 /dev/a rw\n3 1 0:1 / /proc rw - proc proc rw\n")?;
            assert_eq!(entries.len(), 3);
            assert_eq!(entries[1].mount_root.as_os_str().as_bytes(), b"/bind x\xff");
            assert_eq!(entries[2].kind, LocationKind::Virtual);
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
