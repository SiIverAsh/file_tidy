//! Read-only policy labels. These labels never constitute a write authorization.
//!
//! Sensitive matching only examines names and metadata. In particular, discovering
//! a repository marker does not open `.git` (which may be a worktree file).

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, RwLock};

use file_tidy_platform::{FileIdentity, LocationKind, MountTable, NodeKind};
use serde::{Deserialize, Serialize};

/// Independent policy labels; granting a directory cannot clear either flag.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PolicyLabels {
    pub protected: bool,
    pub sensitive: bool,
    #[serde(serialize_with = "crate::model::serialize_optional_path")]
    pub atomic_root: Option<PathBuf>,
}

/// Built-in protection labels for a single inventory pass.
///
/// The atomic-boundary cache is scoped to this policy instance. A future write
/// planner must rebuild and revalidate its own manifest, not trust this cache.
#[derive(Clone, Debug)]
pub struct Policy {
    protected_roots: Vec<PathBuf>,
    protected_directory_ids: HashSet<FileIdentity>,
    sensitive_roots: Vec<PathBuf>,
    sensitive_directory_ids: HashSet<FileIdentity>,
    sensitivity_context_known: bool,
    mounts: Option<MountTable>,
    warnings: Vec<String>,
    atomic_cache: Arc<RwLock<HashMap<PathBuf, bool>>>,
    sensitivity_cache: Arc<RwLock<HashMap<PathBuf, bool>>>,
}

impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}

impl Policy {
    pub fn new() -> Self {
        let mut protected_roots = fixed_protected_roots();
        let mut warnings = Vec::new();
        let mounts = match MountTable::read() {
            Ok(mounts) => Some(mounts),
            Err(_) => {
                warnings.push("could not establish local policy-root locations; content scans are disabled conservatively".to_owned());
                None
            }
        };
        match file_tidy_platform::protected_system_roots() {
            Ok(roots) => protected_roots.extend(roots),
            Err(error) => warnings.push(format!(
                "could not resolve additional system protection roots: {error}; these labels must not authorize writes"
            )),
        }
        include_existing_canonical_aliases(&mut protected_roots, mounts.as_ref());
        let protected_directory_ids = mounts
            .as_ref()
            .map(|mounts| {
                protected_roots
                    .iter()
                    .filter_map(|path| canonicalize_local(path, mounts).ok())
                    .filter_map(|path| file_tidy_platform::inspect(&path).ok())
                    .filter(|node| node.kind == NodeKind::Directory)
                    .filter_map(|node| node.identity)
                    .collect()
            })
            .unwrap_or_default();

        let mut sensitive_roots = Vec::new();
        // UserDirs parses user-dirs.dirs on Linux. That is private configuration
        // content and cannot be read implicitly by a metadata-only policy pass.
        let base_dirs = directories::BaseDirs::new();
        let mut sensitivity_context_known = base_dirs.is_some() && mounts.is_some();
        if let Some(dirs) = &base_dirs {
            append_home_sensitive_roots(dirs.home_dir(), &mut sensitive_roots);
        } else {
            warnings.push(
                "could not resolve the user's home directory; content scans are disabled conservatively"
                    .to_owned(),
            );
        }
        if let Some(dirs) = &base_dirs {
            // These platform mechanisms also cover redirected XDG/AppData paths.
            sensitive_roots.extend([
                dirs.config_dir().to_path_buf(),
                dirs.data_dir().to_path_buf(),
                dirs.data_local_dir().to_path_buf(),
                dirs.cache_dir().to_path_buf(),
            ]);
        }
        include_existing_canonical_aliases(&mut sensitive_roots, mounts.as_ref());
        let mut sensitive_directory_ids = HashSet::new();
        if let Some(mounts) = &mounts {
            for path in &sensitive_roots {
                let result = canonicalize_local(path, mounts)
                    .and_then(|canonical| file_tidy_platform::inspect(&canonical));
                match result {
                    Ok(node) if node.kind == NodeKind::Directory => {
                        if let Some(identity) = node.identity {
                            sensitive_directory_ids.insert(identity);
                        } else {
                            sensitivity_context_known = false;
                        }
                    }
                    // A configured root that is a file still retains its path
                    // prefix protection; it is not a directory alias anchor.
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(_) => sensitivity_context_known = false,
                }
            }
        }
        if !sensitivity_context_known && base_dirs.is_some() && mounts.is_some() {
            warnings.push("some private directory identities could not be verified locally; content scans are disabled conservatively".to_owned());
        }
        Self {
            protected_roots,
            protected_directory_ids,
            sensitive_roots,
            sensitive_directory_ids,
            sensitivity_context_known,
            mounts,
            warnings,
            atomic_cache: Arc::new(RwLock::new(HashMap::new())),
            sensitivity_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialization issues that the caller must retain in its report.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Record sensitive directory objects discovered in the inventory, including
    /// aliases whose sensitive names were not among the startup roots.
    pub(crate) fn register_sensitive_directory(&mut self, identity: FileIdentity) -> bool {
        if !self.sensitive_directory_ids.insert(identity) {
            return false;
        }
        if let Ok(mut cache) = self.sensitivity_cache.write() {
            cache.clear();
        }
        true
    }

    /// Label a path without reading file contents.
    ///
    /// The lexical and canonical paths are both checked, so resolving an alias
    /// cannot strip a sensitive name. Failure to canonicalize conservatively
    /// disables content reads. Callers should first inspect the entry without
    /// following links and reject remote/virtual filesystems.
    pub fn labels(&self, path: &Path) -> PolicyLabels {
        let lexical = absolute_lexical(path);
        let canonical = self.canonicalize(&lexical);
        let protected = self.in_roots(&lexical, &self.protected_roots)
            || protected_volume_directory(&lexical)
            || self.protected_ancestor_identity(&lexical)
            || canonical.as_deref().is_some_and(|real| {
                self.in_roots(real, &self.protected_roots) || protected_volume_directory(real)
            });
        let sensitive = self.sensitivity(&lexical, canonical.as_deref(), true);
        PolicyLabels {
            protected,
            sensitive,
            atomic_root: if canonical.is_some() {
                self.atomic_root(&lexical)
            } else {
                Some(lexical)
            },
        }
    }

    /// Content admission rechecks directory identities rather than trusting
    /// inventory caches. A cached public path must not become an admission
    /// token if a private directory has subsequently moved into that path.
    pub(crate) fn sensitive_for_content(&self, path: &Path) -> bool {
        let lexical = absolute_lexical(path);
        let canonical = self.canonicalize(&lexical);
        self.sensitivity(&lexical, canonical.as_deref(), false)
    }

    fn canonicalize(&self, path: &Path) -> Option<PathBuf> {
        canonicalize_local(path, self.mounts.as_ref()?).ok()
    }

    fn sensitivity(&self, lexical: &Path, canonical: Option<&Path>, cached: bool) -> bool {
        !self.sensitivity_context_known
            || canonical.is_none()
            || self.sensitive_path(lexical)
            || canonical.is_some_and(|path| self.sensitive_path(path))
            || canonical.is_some_and(|path| self.sensitive_ancestor_identity(path, cached))
            || self.sensitive_ancestor_identity(lexical, cached)
    }

    fn sensitive_ancestor_identity(&self, path: &Path, cached: bool) -> bool {
        let mut visited = Vec::new();
        let mut sensitive = false;
        for ancestor in path.ancestors() {
            if cached
                && let Some(known) = self
                    .sensitivity_cache
                    .read()
                    .ok()
                    .and_then(|cache| cache.get(ancestor).copied())
            {
                sensitive = known;
                break;
            }
            let local = self
                .mounts
                .as_ref()
                .is_some_and(|mounts| mounts.classify(ancestor).kind == LocationKind::Local);
            if !local {
                sensitive = true;
                break;
            }
            match file_tidy_platform::inspect(ancestor) {
                Ok(node) if node.kind == NodeKind::Directory => {
                    let Some(identity) = node.identity else {
                        sensitive = true;
                        break;
                    };
                    visited.push(ancestor.to_path_buf());
                    if self.sensitive_directory_ids.contains(&identity) {
                        sensitive = true;
                        break;
                    }
                }
                Ok(node) if node.kind == NodeKind::Regular => {}
                Ok(_) | Err(_) => {
                    sensitive = true;
                    break;
                }
            }
        }
        if cached && let Ok(mut cache) = self.sensitivity_cache.write() {
            for ancestor in visited {
                cache.insert(ancestor, sensitive);
            }
        }
        sensitive
    }

    fn in_roots(&self, path: &Path, roots: &[PathBuf]) -> bool {
        roots.iter().any(|root| {
            component_prefix(path, root)
                || self
                    .mounts
                    .as_ref()
                    .is_some_and(|mounts| mounts.is_alias_beneath(path, root))
        })
    }

    fn protected_ancestor_identity(&self, path: &Path) -> bool {
        path.ancestors().any(|ancestor| {
            self.mounts
                .as_ref()
                .is_some_and(|mounts| mounts.classify(ancestor).kind == LocationKind::Local)
                && file_tidy_platform::inspect(ancestor)
                    .ok()
                    .filter(|node| node.kind == NodeKind::Directory)
                    .and_then(|node| node.identity)
                    .is_some_and(|identity| self.protected_directory_ids.contains(&identity))
        })
    }

    fn sensitive_path(&self, path: &Path) -> bool {
        self.in_roots(path, &self.sensitive_roots)
            || path
                .components()
                .any(|part| sensitive_name(part.as_os_str()))
            || self
                .mounts
                .as_ref()
                .and_then(|mounts| mounts.filesystem_relative_path(path))
                .is_some_and(|physical| {
                    physical
                        .components()
                        .any(|part| sensitive_name(part.as_os_str()))
                })
    }

    fn atomic_root(&self, path: &Path) -> Option<PathBuf> {
        // The outermost boundary owns the complete subtree. For example a
        // node_modules entry in a repository remains owned by the repository.
        let ancestors: Vec<_> = path.ancestors().collect();
        for ancestor in ancestors.into_iter().rev() {
            let cached = self
                .atomic_cache
                .read()
                .ok()
                .and_then(|cache| cache.get(ancestor).copied());
            let boundary = cached.unwrap_or_else(|| atomic_boundary(ancestor));
            if cached.is_none()
                && let Ok(mut cache) = self.atomic_cache.write()
            {
                cache.insert(ancestor.to_path_buf(), boundary);
            }
            if boundary {
                return Some(ancestor.to_path_buf());
            }
        }
        None
    }
}

fn append_home_sensitive_roots(home: &Path, roots: &mut Vec<PathBuf>) {
    // Protect private application data conservatively, including applications
    // that are not yet in a browser/password-manager product-name catalogue.
    for relative in [
        ".ssh",
        ".gnupg",
        ".aws",
        ".azure",
        ".kube",
        ".docker",
        ".pki",
        ".password-store",
        ".mozilla",
        ".config",
        ".cache",
        ".local/share",
        "Library",
        "AppData",
    ] {
        roots.push(home.join(relative));
    }
}

fn include_existing_canonical_aliases(roots: &mut Vec<PathBuf>, mounts: Option<&MountTable>) {
    if let Some(mounts) = mounts {
        let aliases: Vec<_> = roots
            .iter()
            .filter_map(|root| canonicalize_local(root, mounts).ok())
            .collect();
        roots.extend(aliases);
    }
    roots.sort();
    roots.dedup();
}

/// Resolve local metadata aliases without first canonicalizing into a known
/// remote mount. Each symlink target is checked component by component before
/// it can be probed. This is policy normalization, never a content open.
fn canonicalize_local(path: &Path, mounts: &MountTable) -> io::Result<PathBuf> {
    let mut candidate = std::path::absolute(path)?;
    for _ in 0..40 {
        let mut cursor = PathBuf::new();
        let mut parts = candidate.components().peekable();
        let mut restart = None;
        while let Some(part) = parts.next() {
            match part {
                Component::CurDir => continue,
                Component::ParentDir => {
                    cursor.pop();
                    continue;
                }
                other => cursor.push(other.as_os_str()),
            }
            // Verbatim drive prefixes can report is_absolute before RootDir.
            // Wait for the complete root before classifying or inspecting it.
            if matches!(part, Component::Prefix(_)) || !cursor.is_absolute() {
                continue;
            }
            if mounts.classify(&cursor).kind != LocationKind::Local {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "policy metadata is not on a known local filesystem",
                ));
            }
            let node = file_tidy_platform::inspect(&cursor)?;
            if node.kind == NodeKind::Symlink {
                let target = std::fs::read_link(&cursor)?;
                let mut replacement = if target.is_absolute() {
                    target
                } else if let Some(parent) = cursor.parent() {
                    parent.join(target)
                } else {
                    return Err(io::Error::other("link has no parent"));
                };
                replacement.extend(parts.map(|part| part.as_os_str()));
                restart = Some(replacement);
                break;
            }
            if !matches!(node.kind, NodeKind::Directory | NodeKind::Regular)
                || (node.kind != NodeKind::Directory && parts.peek().is_some())
            {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported node in policy metadata path",
                ));
            }
        }
        if let Some(replacement) = restart {
            candidate = replacement;
            continue;
        }
        let canonical = std::fs::canonicalize(&cursor)?;
        if mounts.classify(&canonical).kind != LocationKind::Local {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "canonical policy metadata is not local",
            ));
        }
        return Ok(canonical);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "too many links in policy metadata path",
    ))
}

fn fixed_protected_roots() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    let names = [
        r"C:\Windows",
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        r"C:\ProgramData",
    ];
    #[cfg(target_os = "macos")]
    let names = [
        "/System",
        "/Library",
        "/Applications",
        "/usr",
        "/bin",
        "/sbin",
        "/private",
    ];
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let names = [
        "/bin", "/sbin", "/usr", "/lib", "/etc", "/boot", "/dev", "/proc", "/sys", "/var", "/opt",
        "/root",
    ];
    names.into_iter().map(PathBuf::from).collect()
}

fn component_prefix(path: &Path, root: &Path) -> bool {
    #[cfg(not(windows))]
    {
        path.starts_with(root)
    }
    #[cfg(windows)]
    {
        let path = strip_verbatim_disk_prefix(path);
        let root = strip_verbatim_disk_prefix(root);
        let mut parts = path.components();
        root.components().all(|expected| {
            parts.next().is_some_and(|actual| {
                ascii_eq(
                    actual.as_os_str().as_encoded_bytes(),
                    expected.as_os_str().as_encoded_bytes(),
                )
            })
        })
    }
}

#[cfg(windows)]
fn strip_verbatim_disk_prefix(path: &Path) -> PathBuf {
    use std::path::Prefix;
    let mut parts = path.components();
    if let Some(Component::Prefix(prefix)) = parts.next()
        && let Prefix::VerbatimDisk(disk) = prefix.kind()
    {
        let mut plain = PathBuf::from(format!("{}:", char::from(disk)));
        plain.extend(parts);
        return plain;
    }
    path.to_path_buf()
}

fn absolute_lexical(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else if let Ok(current) = std::env::current_dir() {
        current.join(path)
    } else {
        path.to_path_buf()
    };
    let mut normalized = PathBuf::new();
    for part in absolute.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[cfg(windows)]
fn ascii_eq(left: &[u8], right: &[u8]) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn protected_volume_directory(path: &Path) -> bool {
    #[cfg(windows)]
    {
        // Conservatively protect these names on every drive, including volumes
        // not present while Policy was created. Matching below the root is a
        // safe over-approximation for this read-only inventory phase.
        path.components().any(|part| {
            let lower: Vec<_> = part
                .as_os_str()
                .as_encoded_bytes()
                .iter()
                .map(u8::to_ascii_lowercase)
                .collect();
            windows_protected_special_name(&lower)
        })
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        false
    }
}

pub(crate) fn sensitive_name(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    let lower: Vec<_> = bytes.iter().map(u8::to_ascii_lowercase).collect();
    let whole = [
        b".ssh".as_slice(),
        b".gnupg",
        b".aws",
        b".azure",
        b".kube",
        b".docker",
        b".pki",
        b".password-store",
        b".mozilla",
        b"appdata",
        b"application support",
        b"group containers",
        b"keychains",
        b"google-chrome",
        b"chromium",
        b"bravesoftware",
        b"microsoft-edge",
        b"firefox",
        b"safari",
        b"bitwarden",
        b"1password",
        b".env",
        b"credentials",
        b"credentials.json",
        b"credentials.toml",
        b"secrets.json",
        b"secrets.toml",
        b"private_key",
        b"private-key",
        b"login data",
        b"cookies",
        b"key4.db",
        b"logins.json",
    ];
    whole.contains(&lower.as_slice())
        || lower.starts_with(b".env.")
        || lower.starts_with(b"id_rsa")
        || lower.starts_with(b"id_dsa")
        || lower.starts_with(b"id_ecdsa")
        || lower.starts_with(b"id_ed25519")
        || lower.starts_with(b"client_secret")
        || [
            b".pem".as_slice(),
            b".key",
            b".p12",
            b".pfx",
            b".kdbx",
            b".keychain",
            b".keychain-db",
            b".env",
        ]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
        || windows_protected_special_name(&lower)
}

// Windows system volume directories are also sensitive on other platforms when
// scanning a mounted Windows volume. Their A protection is applied separately.
fn windows_protected_special_name(lower: &[u8]) -> bool {
    lower == b"system volume information" || lower == b"$recycle.bin"
}

fn atomic_boundary(path: &Path) -> bool {
    let Some(name) = path.file_name() else {
        return false;
    };
    let name = name.as_encoded_bytes();
    let lower: Vec<_> = name.iter().map(u8::to_ascii_lowercase).collect();
    if [b".app".as_slice(), b".vmwarevm", b".pvm"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
    {
        return true;
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        // A caller must not split a subtree whose boundary cannot be inspected.
        Err(_) => return true,
    };
    if metadata.is_dir() {
        let names = [
            b"node_modules".as_slice(),
            b"venv",
            b".venv",
            b"target",
            b"__pycache__",
            b".git",
            b".hg",
            b".svn",
        ];
        if names.contains(&lower.as_slice()) {
            return true;
        }
        for marker in [".git", ".hg", ".svn"] {
            match std::fs::symlink_metadata(path.join(marker)) {
                Ok(_) => return true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return true,
            }
        }
        return false;
    }
    if !metadata.is_file() {
        return false;
    }
    [
        b".db".as_slice(),
        b".sqlite",
        b".sqlite3",
        b".db-wal",
        b".db-shm",
        b".sqlite-wal",
        b".sqlite-shm",
        b".vmdk",
        b".vdi",
        b".qcow",
        b".qcow2",
        b".vhd",
        b".vhdx",
        b".vbox",
        b".vmx",
        b".ova",
        b".ovf",
        b".docker.tar",
        b".oci.tar",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_names_are_ascii_case_insensitive_and_ancestor_safe() {
        for name in [
            ".env",
            ".env.production",
            "deploy.KEY",
            "id_ed25519.pub",
            ".ssh",
            "AppData",
            "secrets.toml",
            "Keychains",
            "Application Support",
        ] {
            assert!(sensitive_name(OsStr::new(name)), "{name}");
        }
        for name in [
            "environment.txt",
            "keyboard.rs",
            "env.example.txt",
            "photo.png",
        ] {
            assert!(!sensitive_name(OsStr::new(name)), "{name}");
        }
    }

    #[test]
    fn prefixes_compare_path_components() {
        #[cfg(not(windows))]
        {
            assert!(component_prefix(
                Path::new("/usr/bin/tool"),
                Path::new("/usr")
            ));
            assert!(!component_prefix(
                Path::new("/usr2/tool"),
                Path::new("/usr")
            ));
        }
        #[cfg(windows)]
        {
            assert!(component_prefix(
                Path::new(r"\\?\C:\WINDOWS\file"),
                Path::new(r"C:\Windows")
            ));
            assert!(!component_prefix(
                Path::new(r"C:\WindowsOld\file"),
                Path::new(r"C:\Windows")
            ));
        }
    }

    #[test]
    fn repository_marker_file_does_not_need_content_reads() -> std::io::Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = temp.path().join("repo");
        std::fs::create_dir(&repo)?;
        std::fs::write(repo.join(".git"), b"not parsed as git metadata")?;
        std::fs::create_dir(repo.join("node_modules"))?;
        let file = repo.join("node_modules/library.txt");
        std::fs::write(&file, b"library")?;
        assert_eq!(Policy::new().atomic_root(&file), Some(repo));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn canonicalization_accepts_complete_verbatim_drive_roots() -> io::Result<()> {
        let temp = tempfile::tempdir()?;
        let canonical = temp.path().canonicalize()?;
        let mounts = MountTable::read()?;
        assert_eq!(canonicalize_local(&canonical, &mounts)?, canonical);
        assert_eq!(
            canonicalize_local(&strip_verbatim_disk_prefix(&canonical), &mounts)?,
            canonical
        );
        Ok(())
    }

    #[test]
    fn content_admission_does_not_trust_stale_inventory_cache() -> io::Result<()> {
        // Windows' system temp directory is under AppData, which must remain
        // sensitive by name even when the synthetic policy roots are cleared.
        let base = std::env::var_os("FILE_TIDY_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/core-test-fixtures")
            });
        std::fs::create_dir_all(&base)?;
        let temp = tempfile::tempdir_in(base)?;
        let fixture = temp.path().canonicalize()?;
        let private = fixture.join("private-object");
        let public = fixture.join("public-location");
        let displaced = fixture.join("displaced-public");
        std::fs::create_dir(&private)?;
        std::fs::create_dir(&public)?;
        let Some(identity) = file_tidy_platform::inspect(&private)?.identity else {
            return Err(io::Error::other("test fixture has no directory identity"));
        };
        let mut policy = Policy::new();
        // A synthetic anchor tests the identity mechanism without creating or
        // changing a real user-private directory or weakening production roots.
        policy.sensitivity_context_known = true;
        policy.sensitive_roots.clear();
        policy.sensitive_directory_ids.clear();
        policy.sensitive_directory_ids.insert(identity);
        assert!(!policy.labels(&public).sensitive);
        std::fs::rename(&public, &displaced)?;
        std::fs::rename(&private, &public)?;
        assert!(policy.sensitive_for_content(&public));
        Ok(())
    }

    #[test]
    fn protected_directory_identity_survives_namespace_changes() -> io::Result<()> {
        let temp = tempfile::tempdir()?;
        let fixture = temp.path().canonicalize()?;
        let original = fixture.join("system-anchor");
        let alias = fixture.join("other-namespace");
        std::fs::create_dir(&original)?;
        std::fs::write(original.join("ordinary.txt"), b"fixture")?;
        let identity = file_tidy_platform::inspect(&original)?
            .identity
            .ok_or_else(|| io::Error::other("fixture identity unavailable"))?;
        let mut policy = Policy::new();
        // Synthetic anchors exercise alias detection without modifying any real
        // protected object or exposing configurable production protection roots.
        policy.protected_roots.clear();
        policy.protected_directory_ids.clear();
        policy.protected_directory_ids.insert(identity);
        std::fs::rename(&original, &alias)?;
        assert!(policy.labels(&alias.join("ordinary.txt")).protected);
        Ok(())
    }

    #[test]
    fn inventory_sensitive_evidence_invalidates_public_alias_cache() -> io::Result<()> {
        // This scenario starts with a public path. Windows' default temp path
        // contains AppData, whose name remains sensitive after synthetic roots
        // are cleared, so use the same independent fixture as cache admission.
        let base = std::env::var_os("FILE_TIDY_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/core-test-fixtures")
            });
        std::fs::create_dir_all(&base)?;
        let temp = tempfile::tempdir_in(base)?;
        let fixture = temp.path().canonicalize()?;
        let directory = fixture.join("plain-name");
        std::fs::create_dir(&directory)?;
        let file = directory.join("ordinary.txt");
        std::fs::write(&file, b"fixture")?;
        let identity = file_tidy_platform::inspect(&directory)?
            .identity
            .ok_or_else(|| io::Error::other("fixture identity unavailable"))?;
        let mut policy = Policy::new();
        policy.sensitivity_context_known = true;
        policy.sensitive_roots.clear();
        policy.sensitive_directory_ids.clear();
        assert!(
            !policy.labels(&file).sensitive,
            "cache fixture must start with a public path: {}",
            file.display()
        );
        assert!(policy.register_sensitive_directory(identity));
        assert!(policy.labels(&file).sensitive);
        assert!(policy.sensitive_for_content(&file));
        assert!(!policy.register_sensitive_directory(identity));
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn data_volume_alias_of_private_library_stays_sensitive() -> io::Result<()> {
        let Some(dirs) = directories::BaseDirs::new() else {
            eprintln!("skipped: no native home directory");
            return Ok(());
        };
        let Ok(relative_home) = dirs.home_dir().strip_prefix("/") else {
            eprintln!("skipped: home has no local absolute path");
            return Ok(());
        };
        let logical = dirs.home_dir().join("Library");
        let alternate = Path::new("/System/Volumes/Data")
            .join(relative_home)
            .join("Library");
        let (normal, alias) = match (
            file_tidy_platform::inspect(&logical),
            file_tidy_platform::inspect(&alternate),
        ) {
            (Ok(normal), Ok(alias))
                if normal.identity.is_some() && normal.identity == alias.identity =>
            {
                (normal, alias)
            }
            _ => {
                eprintln!("skipped: this home has no verified Data-volume Library alias");
                return Ok(());
            }
        };
        let policy = Policy::new();
        assert!(normal.kind == NodeKind::Directory && alias.kind == NodeKind::Directory);
        assert!(
            alias
                .identity
                .is_some_and(|id| policy.sensitive_directory_ids.contains(&id))
        );
        assert!(policy.sensitive_ancestor_identity(&alternate, true));
        assert!(policy.labels(&alternate).sensitive);
        assert!(policy.sensitive_for_content(&alternate));
        let preferences = alternate.join("Preferences");
        if file_tidy_platform::inspect(&preferences).is_ok() {
            assert!(policy.sensitive_ancestor_identity(&preferences, true));
            assert!(policy.sensitive_for_content(&preferences));
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_sensitive_suffix_is_recognized() {
        use std::os::unix::ffi::OsStrExt;
        assert!(sensitive_name(OsStr::from_bytes(b"name-\xff.key")));
        assert!(!sensitive_name(OsStr::from_bytes(b"name-\xff.txt")));
    }
}
