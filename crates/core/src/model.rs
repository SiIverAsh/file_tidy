use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use file_tidy_platform::NodeInfo;
use serde::{Serialize, Serializer};

use crate::{Classification, policy::PolicyLabels};

/// Human-readable text is escaped and is never used to reconstruct a native path.
pub fn display_path(path: &Path) -> String {
    escape_text(&path.as_os_str().to_string_lossy())
}

pub fn escape_text(value: &str) -> String {
    let mut text = String::new();
    for ch in value.chars() {
        if ch.is_control()
            || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            text.extend(ch.escape_unicode());
        } else {
            text.push(ch);
        }
    }
    text
}

fn serialize_path<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct NativePath {
        display: String,
        encoding: &'static str,
        units: Vec<u32>,
    }
    #[cfg(unix)]
    let native = {
        use std::os::unix::ffi::OsStrExt;
        NativePath {
            display: display_path(path),
            encoding: "unix_bytes",
            units: path
                .as_os_str()
                .as_bytes()
                .iter()
                .map(|b| u32::from(*b))
                .collect(),
        }
    };
    #[cfg(windows)]
    let native = {
        use std::os::windows::ffi::OsStrExt;
        NativePath {
            display: display_path(path),
            encoding: "windows_wide",
            units: path.as_os_str().encode_wide().map(u32::from).collect(),
        }
    };
    native.serialize(serializer)
}

pub(crate) fn serialize_optional_path<S: Serializer>(
    path: &Option<PathBuf>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    struct PathRef<'a>(&'a Path);
    impl Serialize for PathRef<'_> {
        fn serialize<T: Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
            serialize_path(self.0, serializer)
        }
    }
    path.as_deref().map(PathRef).serialize(serializer)
}

fn decimal<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_string())
}

fn optional_decimal<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
    value.map(|n| n.to_string()).serialize(serializer)
}

#[derive(Clone, Debug, Serialize)]
pub struct Timestamp {
    pub unix_seconds: String,
    pub nanoseconds: u32,
}

impl Timestamp {
    pub fn from_system(time: SystemTime) -> Self {
        let (seconds, nanos) = match time.duration_since(UNIX_EPOCH) {
            Ok(d) => (i128::from(d.as_secs()), d.subsec_nanos()),
            Err(e) => {
                let d = e.duration();
                if d.subsec_nanos() == 0 {
                    (-i128::from(d.as_secs()), 0)
                } else {
                    (
                        -i128::from(d.as_secs()) - 1,
                        1_000_000_000 - d.subsec_nanos(),
                    )
                }
            }
        };
        Self {
            unix_seconds: seconds.to_string(),
            nanoseconds: nanos,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Directory,
}

#[derive(Clone, Debug, Serialize)]
pub struct FileEntry {
    pub id: u64,
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
    pub kind: EntryKind,
    #[serde(serialize_with = "decimal")]
    pub size_bytes: u64,
    #[serde(serialize_with = "optional_decimal")]
    pub allocated_bytes: Option<u64>,
    pub modified: Option<Timestamp>,
    pub hidden: bool,
    pub policy: PolicyLabels,
    pub classification: Option<Classification>,
    pub content_inspected: bool,
    #[serde(skip)]
    pub(crate) snapshot: NodeInfo,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    PermissionDenied,
    Io,
    Symlink,
    ReparsePoint,
    SpecialNode,
    MountBoundary,
    RemoteFilesystem,
    VirtualFilesystem,
    UnknownFilesystem,
    SensitiveContent,
    MetadataOnly,
    ChangedDuringRead,
    IdentityUnavailable,
    InvalidRoot,
}

#[derive(Clone, Debug, Serialize)]
pub struct SkippedEntry {
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
    pub reason: SkipReason,
    pub detail: String,
    pub os_error: Option<i32>,
    pub incomplete: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct DuplicateGroup {
    pub entry_ids: Vec<u64>,
    #[serde(serialize_with = "decimal")]
    pub size_bytes: u64,
    #[serde(serialize_with = "decimal")]
    pub duplicate_logical_bytes: u64,
    pub blake3: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DirectoryUsage {
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
    pub files: u64,
    #[serde(serialize_with = "decimal")]
    pub logical_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Summary {
    pub entries: u64,
    pub files: u64,
    pub directories: u64,
    pub skipped: u64,
    #[serde(serialize_with = "decimal")]
    pub logical_bytes: u64,
    #[serde(serialize_with = "decimal")]
    pub unique_file_logical_bytes: u64,
    #[serde(serialize_with = "optional_decimal")]
    pub unique_allocated_bytes: Option<u64>,
    #[serde(serialize_with = "decimal")]
    pub content_bytes_read: u64,
    pub content_open_operations: u64,
    pub complete: bool,
    pub cancelled: bool,
    pub limit_reached: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub scanned_at: Timestamp,
    pub summary: Summary,
    pub entries: Vec<FileEntry>,
    pub directory_usage: Vec<DirectoryUsage>,
    pub top_entry_ids: Vec<u64>,
    pub stale_entry_ids: Vec<u64>,
    pub duplicates: Vec<DuplicateGroup>,
    pub skipped: Vec<SkippedEntry>,
    pub suggested_directories: Vec<SuggestedDirectory>,
    pub notices: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SuggestedDirectory {
    pub purpose: &'static str,
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn native_path_and_atomic_owner_encode_non_utf8_without_filesystem()
    -> Result<(), serde_json::Error> {
        let path = PathBuf::from(OsString::from_vec(b"/native/path-\xff".to_vec()));
        let labels = PolicyLabels {
            protected: false,
            sensitive: false,
            atomic_root: Some(path.clone()),
        };
        let encoded = serde_json::to_value(&labels)?;
        let raw: Vec<_> = b"/native/path-\xff"
            .iter()
            .map(|b| serde_json::Value::from(*b))
            .collect();
        assert_eq!(
            encoded["atomic_root"]["units"],
            serde_json::Value::Array(raw.clone())
        );
        assert_eq!(encoded["atomic_root"]["encoding"], "unix_bytes");
        let item = SuggestedDirectory {
            purpose: "test",
            path,
        };
        let encoded = serde_json::to_value(item)?;
        assert_eq!(encoded["path"]["units"], serde_json::Value::Array(raw));
        Ok(())
    }
}
