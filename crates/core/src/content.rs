use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use file_tidy_platform::{MountTable, NodeInfo, NodeKind};

use crate::policy::Policy;
use crate::{CancellationToken, Error, Rules};

#[derive(Default)]
pub(crate) struct ReadCounters {
    pub bytes: AtomicU64,
    pub opens: AtomicU64,
}

/// Cannot be forged by callers: all content reads go through these checks.
pub(crate) struct ContentReadPermit<'a> {
    path: &'a Path,
    expected: &'a NodeInfo,
    policy: &'a Policy,
    mount_root: std::path::PathBuf,
}

impl<'a> ContentReadPermit<'a> {
    pub(crate) fn issue(
        path: &'a Path,
        expected: &'a NodeInfo,
        policy: &'a Policy,
        mounts: &MountTable,
    ) -> io::Result<Self> {
        if policy.sensitive_for_content(path) || expected.kind != NodeKind::Regular {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "content policy denied",
            ));
        }
        if mounts.classify(path).kind != file_tidy_platform::LocationKind::Local {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "not a known local filesystem",
            ));
        }
        if expected.identity.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "file identity unavailable",
            ));
        }
        Ok(Self {
            path,
            expected,
            policy,
            mount_root: mounts.classify(path).mount_root,
        })
    }

    pub(crate) fn open(&self, counters: &ReadCounters) -> io::Result<File> {
        // Re-read mounts at the content boundary, so cached scan topology is not authority.
        let current_mounts = MountTable::read()?;
        let location = current_mounts.classify(self.path);
        if location.kind != file_tidy_platform::LocationKind::Local
            || location.mount_root != self.mount_root
            || self.policy.sensitive_for_content(self.path)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "mount changed",
            ));
        }
        let file = file_tidy_platform::open_verified(self.path, self.expected)?;
        counters.opens.fetch_add(1, Ordering::Relaxed);
        Ok(file)
    }

    pub(crate) fn verify_after(&self, file: &File) -> io::Result<()> {
        let opened = file_tidy_platform::inspect_file(file)?;
        let current = file_tidy_platform::inspect(self.path)?;
        if !self.expected.matches(&current) || !self.expected.matches(&opened) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file changed during read",
            ));
        }
        Ok(())
    }
}

pub(crate) fn read_prefix(
    permit: &ContentReadPermit<'_>,
    limit: usize,
    cancel: &CancellationToken,
    counters: &ReadCounters,
) -> io::Result<Vec<u8>> {
    let mut file = permit.open(counters)?;
    let mut result = Vec::with_capacity(limit);
    let mut buffer = [0; 8192];
    while result.len() < limit {
        if cancel.is_cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "scan cancelled"));
        }
        let amount = (limit - result.len()).min(buffer.len());
        let read = file.read(&mut buffer[..amount])?;
        if read == 0 {
            break;
        }
        counters.bytes.fetch_add(read as u64, Ordering::Relaxed);
        result.extend_from_slice(&buffer[..read]);
    }
    permit.verify_after(&file)?;
    Ok(result)
}

pub(crate) fn hash_file(
    permit: &ContentReadPermit<'_>,
    prefix: Option<usize>,
    cancel: &CancellationToken,
    counters: &ReadCounters,
    on_read: &(impl Fn() + Sync),
) -> io::Result<blake3::Hash> {
    if let Some(limit) = prefix {
        return read_prefix(permit, limit, cancel, counters).map(|bytes| blake3::hash(&bytes));
    }
    let mut file = permit.open(counters)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0; 65536];
    loop {
        if cancel.is_cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "scan cancelled"));
        }
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        counters.bytes.fetch_add(read as u64, Ordering::Relaxed);
        hasher.update(&buffer[..read]);
        on_read();
    }
    permit.verify_after(&file)?;
    Ok(hasher.finalize())
}

/// Reads only a bounded ordinary local non-sensitive configuration file.
pub fn load_rules(path: &Path) -> Result<Rules, Error> {
    let mounts = MountTable::read().map_err(|_| Error::ConfigurationDenied)?;
    let path = crate::scan::resolve_root(path, &mounts).map_err(|_| Error::ConfigurationDenied)?;
    let node = file_tidy_platform::inspect(&path).map_err(|_| Error::ConfigurationDenied)?;
    if node.len > 1_048_576 {
        return Err(Error::ConfigurationTooLarge);
    }
    let policy = Policy::new();
    let permit = ContentReadPermit::issue(&path, &node, &policy, &mounts)
        .map_err(|_| Error::ConfigurationDenied)?;
    let data = read_prefix(
        &permit,
        1_048_577,
        &CancellationToken::default(),
        &ReadCounters::default(),
    )
    .map_err(|_| Error::ConfigurationDenied)?;
    if data.len() > 1_048_576 {
        return Err(Error::ConfigurationTooLarge);
    }
    let text = std::str::from_utf8(&data).map_err(|_| Error::ConfigurationEncoding)?;
    Rules::from_toml(text).map_err(Error::Rules)
}

/// A copy content permit is scoped to one live confirmed operation. It does not
/// change the scan content policy and cannot be reconstructed from audit data.
pub(crate) struct OperationContentPermit {
    path: std::path::PathBuf,
    expected: NodeInfo,
    mount_root: std::path::PathBuf,
    sensitive_acknowledged: bool,
    expires_at: u64,
}
impl OperationContentPermit {
    pub(crate) fn issue(
        session: &crate::authorization::Session,
        approved: &crate::approval::ApprovedPlan,
        operation: &crate::plan::PlannedOperation,
    ) -> crate::authorization::Result<Self> {
        if operation.manifest.len() != 1 {
            return Err(crate::authorization::PlanningError::InvalidPlan);
        }
        Self::issue_entry(session, approved, operation, &operation.manifest[0])
    }
    pub(crate) fn issue_entry(
        session: &crate::authorization::Session,
        approved: &crate::approval::ApprovedPlan,
        operation: &crate::plan::PlannedOperation,
        entry: &crate::plan::ManifestEntry,
    ) -> crate::authorization::Result<Self> {
        use crate::authorization::PlanningError as E;
        session.validate_plan_context(&approved.plan)?;
        if !matches!(
            operation.kind,
            crate::plan::OperationKind::Copy | crate::plan::OperationKind::UndoCopy
        ) || !operation.manifest.iter().any(|item| item == entry)
            || !approved
                .preview()
                .operations
                .iter()
                .any(|op| op.id == operation.id)
        {
            return Err(E::InvalidPlan);
        }
        let path = entry.path.to_path()?;
        let expected = file_tidy_platform::inspect(&path)?;
        if expected.kind != NodeKind::Regular
            || crate::plan::Stamp::capture(&expected)? != entry.stamp
        {
            return Err(E::ChangedSincePlan);
        }
        let key = format!(
            "{}:{}:content",
            operation.id,
            blake3::hash(&serde_json::to_vec(&entry.path)?).to_hex()
        );
        let sensitive_acknowledged = approved.preview().sensitive_acknowledgements.contains(&key);
        let location = file_tidy_platform::classify_location(&path)?;
        if location.kind != file_tidy_platform::LocationKind::Local {
            return Err(E::UnsupportedSafetyGuarantee);
        }
        Ok(Self {
            path,
            expected,
            mount_root: location.mount_root,
            sensitive_acknowledged,
            expires_at: approved.preview().expires_at,
        })
    }
    pub(crate) fn check_live(&self) -> crate::authorization::Result<()> {
        if crate::plan::now()? >= self.expires_at {
            return Err(crate::authorization::PlanningError::InvalidPlan);
        }
        Ok(())
    }
    pub(crate) fn open(&self) -> crate::authorization::Result<File> {
        self.check_live()?;
        use crate::authorization::PlanningError as E;
        let current = file_tidy_platform::classify_location(&self.path)?;
        let policy = crate::authorization::planning_policy()?;
        if current.kind != file_tidy_platform::LocationKind::Local
            || current.mount_root != self.mount_root
            || (policy.sensitive_for_content(&self.path) && !self.sensitive_acknowledged)
        {
            return Err(E::ConfirmationRequired);
        }
        Ok(file_tidy_platform::open_verified(
            &self.path,
            &self.expected,
        )?)
    }
    pub(crate) fn verify_after(&self, file: &File) -> crate::authorization::Result<()> {
        self.check_live()?;
        use crate::authorization::PlanningError as E;
        let current = file_tidy_platform::classify_location(&self.path)?;
        let policy = crate::authorization::planning_policy()?;
        if (policy.sensitive_for_content(&self.path) && !self.sensitive_acknowledged)
            || current.mount_root != self.mount_root
            || current.kind != file_tidy_platform::LocationKind::Local
            || !self
                .expected
                .matches(&file_tidy_platform::inspect_file(file)?)
            || !self
                .expected
                .matches(&file_tidy_platform::inspect(&self.path)?)
        {
            return Err(E::ChangedSincePlan);
        }
        Ok(())
    }
}
