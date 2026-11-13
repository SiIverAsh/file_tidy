//! Explicit initialization and transactional persistence of grants and approvals.
use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};

use cap_std::fs::{Dir, OpenOptions};
use file_tidy_platform::PinnedDirectory;
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};

use crate::approval::ApprovalAudit;
use crate::authorization::{
    Grant, Id, Identity, NativePath, PlanningError as E, Result, Session, checked_existing,
    planning_policy, same_identity,
};
use crate::plan::now;

const MAX_STATE: usize = 16 * 1024 * 1024;
const MAX_DATABASE: u64 = 256 * 1024 * 1024;
const DATABASE: &str = "state.db";

#[derive(Serialize)]
pub struct StoragePreview {
    pub grant: Id,
    pub directory: NativePath,
    pub objects: Vec<&'static str>,
    pub persistent_root_authorization: bool,
    pub expires_at: u64,
}
pub struct StoragePlan {
    session: Id,
    epoch: u64,
    root: PathBuf,
    root_identity: Identity,
    preview: StoragePreview,
    digest: String,
}
impl StoragePlan {
    pub fn preview(&self) -> &StoragePreview {
        &self.preview
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredState {
    epoch: u64,
    root_grant: Id,
    storage_identity: Identity,
    grants: BTreeMap<Id, Grant>,
}

pub(crate) struct StateStore {
    connection: Connection,
    root: PathBuf,
    root_grant: Id,
    root_identity: Identity,
    storage_identity: Identity,
    _anchor: PinnedDirectory,
    _directory: PinnedDirectory,
    _directory_cap: Dir,
    _lock: File,
    database: File,
    writable: bool,
    epoch: u64,
}

impl Session {
    pub fn storage_plan(&self, grant: &Id) -> Result<StoragePlan> {
        if self.store.is_some() {
            return Err(E::InvalidRequest);
        }
        let policy = planning_policy()?;
        let grant = self.grants.get(grant).ok_or(E::OutsideGrant)?;
        let root = grant.validate(&policy)?;
        let labels = policy.labels(&root);
        if labels.protected || labels.sensitive {
            return Err(E::ProtectedZone);
        }
        if labels.atomic_root.is_some() {
            return Err(E::AtomicBoundary);
        }
        match std::fs::symlink_metadata(root.join(".file-tidy")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(E::StorageUnavailable),
        }
        let preview = StoragePreview {
            grant: grant.id.clone(),
            directory: NativePath::new(&root.join(".file-tidy")),
            objects: vec![
                "state.db",
                "state.db-journal (SQLite transaction journal)",
                "writer.lock",
            ],
            persistent_root_authorization: true,
            expires_at: now()?.checked_add(900).ok_or(E::Overflow)?,
        };
        let digest = blake3::hash(&serde_json::to_vec(&preview)?)
            .to_hex()
            .to_string();
        Ok(StoragePlan {
            session: self.id.clone(),
            epoch: self.epoch,
            root,
            root_identity: grant.identity.clone(),
            preview,
            digest,
        })
    }

    pub fn initialize_storage(&mut self, plan: StoragePlan, confirmation: &str) -> Result<()> {
        if self.store.is_some()
            || plan.session != self.id
            || plan.epoch != self.epoch
            || now()? >= plan.preview.expires_at
            || confirmation != plan.digest
        {
            return Err(E::ConfirmationRequired);
        }
        let grant = self
            .grants
            .get(&plan.preview.grant)
            .ok_or(E::OutsideGrant)?;
        let policy = planning_policy()?;
        let root = grant.validate(&policy)?;
        let labels = policy.labels(&root);
        if root != plan.root
            || grant.identity != plan.root_identity
            || labels.protected
            || labels.sensitive
            || labels.atomic_root.is_some()
        {
            return Err(E::ChangedSincePlan);
        }
        let mut grants = self.grants.clone();
        grants
            .get_mut(&plan.preview.grant)
            .ok_or(E::OutsideGrant)?
            .persistent = true;
        let epoch = self.epoch.checked_add(1).ok_or(E::Overflow)?;
        let store = StateStore::create(&root, &plan.preview.grant, &grants, epoch)?;
        self.grants = grants;
        self.epoch = epoch;
        self.store = Some(store);
        Ok(())
    }

    pub fn enable_persistence(&mut self) -> Result<()> {
        let store = self.store.take().ok_or(E::StorageRequired)?;
        if store.writable {
            self.store = Some(store);
            return Ok(());
        }
        let root = store.root.clone();
        let expected_epoch = store.epoch;
        drop(store);
        let (store, state) = StateStore::open(&root, true)?;
        if state.epoch != expected_epoch {
            return Err(E::InvalidPlan);
        }
        self.store = Some(store);
        Ok(())
    }

    /// Open existing state without creating locks, caches, journals, or databases.
    pub fn open(root: &Path) -> Result<Self> {
        Self::open_state(root, false)
    }
    /// Open existing state for explicitly requested grant changes or confirmation.
    pub fn open_writable(root: &Path) -> Result<Self> {
        Self::open_state(root, true)
    }
    fn open_state(root: &Path, writable: bool) -> Result<Self> {
        let (store, state) = StateStore::open(root, writable)?;
        let session = Self {
            id: Id::new()?,
            epoch: state.epoch,
            grants: state.grants,
            store: Some(store),
        };
        // Stale grants remain inspectable and revocable; plan admission rechecks identity.
        Ok(session)
    }
}

impl StateStore {
    pub(crate) fn journal_read<T>(&self, read: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        self.validate_anchor()?;
        let result = read(&self.connection)?;
        self.validate_anchor()?;
        Ok(result)
    }

    pub(crate) fn journal_write<T>(
        &mut self,
        write: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T>,
    ) -> Result<T> {
        if !self.writable {
            return Err(E::StorageUnavailable);
        }
        self.validate_anchor()?;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let result = write(&transaction)?;
        transaction.commit()?;
        self.sync_directory()?;
        self.validate_anchor()?;
        Ok(result)
    }

    pub(crate) fn root_grant(&self) -> &Id {
        &self.root_grant
    }

    fn create(
        root: &Path,
        root_grant: &Id,
        grants: &BTreeMap<Id, Grant>,
        epoch: u64,
    ) -> Result<Self> {
        let root_info = file_tidy_platform::inspect(root)?;
        let anchor = file_tidy_platform::open_directory_pinned(root, &root_info)?;
        let private = file_tidy_platform::create_private_directory(
            &anchor,
            std::ffi::OsStr::new(".file-tidy"),
        )?;
        let directory = Dir::from_std_file(private);
        let directory_path = root.join(".file-tidy");
        let directory_info = file_tidy_platform::inspect(&directory_path)?;
        let pinned = file_tidy_platform::open_directory_pinned(&directory_path, &directory_info)?;
        let lock =
            file_tidy_platform::create_private_file(&pinned, std::ffi::OsStr::new("writer.lock"))?;
        lock.try_lock().map_err(|_| E::StorageUnavailable)?;
        let db_file =
            file_tidy_platform::create_private_file(&pinned, std::ffi::OsStr::new(DATABASE))?;
        let db_identity = file_tidy_platform::inspect_file(&db_file)?.identity;
        let connection = open_database(&directory_path.join(DATABASE), true)?;
        if db_identity != file_tidy_platform::inspect(&directory_path.join(DATABASE))?.identity {
            return Err(E::StorageUnavailable);
        }
        connection.execute_batch(include_str!("../../../docs/journal.sql"))?;
        let mut store = Self {
            connection,
            root: root.to_path_buf(),
            root_grant: root_grant.clone(),
            root_identity: root_info.identity.ok_or(E::StorageUnavailable)?.into(),
            storage_identity: directory_info.identity.ok_or(E::StorageUnavailable)?.into(),
            _anchor: anchor,
            _directory: pinned,
            _directory_cap: directory,
            _lock: lock,
            database: db_file,
            writable: true,
            epoch,
        };
        store.save(grants, epoch, None)?;
        store.sync_directory()?;
        Ok(store)
    }

    fn open(root: &Path, writable: bool) -> Result<(Self, StoredState)> {
        let policy = planning_policy()?;
        let root = checked_existing(root, false)?;
        let labels = policy.labels(&root);
        if labels.protected || labels.sensitive || labels.atomic_root.is_some() {
            return Err(E::StorageUnavailable);
        }
        let root_info = file_tidy_platform::inspect(&root)?;
        let anchor = file_tidy_platform::open_directory_pinned(&root, &root_info)?;
        let path = checked_existing(&root.join(".file-tidy"), false)?;
        let info = file_tidy_platform::inspect(&path)?;
        let pinned = file_tidy_platform::open_directory_pinned(&path, &info)?;
        file_tidy_platform::verify_private_file(&pinned.try_clone_file()?, true)?;
        let directory = Dir::from_std_file(pinned.try_clone_file()?);
        let lock = open_file(&directory, "writer.lock", writable)?;
        if writable {
            lock.try_lock().map_err(|_| E::StorageUnavailable)?;
        } else {
            lock.try_lock_shared().map_err(|_| E::StorageUnavailable)?;
        }
        let db = open_file(&directory, DATABASE, writable)?;
        if db.metadata()?.len() > MAX_DATABASE {
            return Err(E::StorageUnavailable);
        }
        for sidecar in ["state.db-journal", "state.db-wal", "state.db-shm"] {
            match directory.symlink_metadata(sidecar) {
                Ok(meta) => {
                    if !meta.is_file() {
                        return Err(E::StorageUnavailable);
                    }
                    let _ = open_file(&directory, sidecar, false)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let db_identity = file_tidy_platform::inspect_file(&db)?.identity;
        let connection = open_database(&path.join(DATABASE), writable)?;
        if file_tidy_platform::inspect(&path.join(DATABASE))?.identity != db_identity {
            return Err(E::StorageUnavailable);
        }
        let length: i64 = connection.query_row(
            "SELECT length(payload) FROM authorization_state WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if length < 0 || length as usize > MAX_STATE {
            return Err(E::StorageUnavailable);
        }
        let payload: Vec<u8> = connection.query_row(
            "SELECT payload FROM authorization_state WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let state: StoredState = serde_json::from_slice(&payload)?;
        if state.grants.len() > 1000
            || state.epoch > i64::MAX as u64
            || info.identity.map(Identity::from).as_ref() != Some(&state.storage_identity)
        {
            return Err(E::StorageUnavailable);
        }
        let grant = state
            .grants
            .get(&state.root_grant)
            .ok_or(E::StorageUnavailable)?;
        if grant.root.to_path()? != root
            || !same_identity(&root_info, &grant.identity)
            || !grant.persistent
            || state
                .grants
                .iter()
                .any(|(id, g)| *id != g.id || !g.persistent)
        {
            return Err(E::StorageUnavailable);
        }
        if writable && grant.revoked {
            return Err(E::OutsideGrant);
        }
        let store = Self {
            connection,
            root,
            root_grant: state.root_grant.clone(),
            root_identity: root_info.identity.ok_or(E::StorageUnavailable)?.into(),
            storage_identity: state.storage_identity.clone(),
            _anchor: anchor,
            _directory: pinned,
            _directory_cap: directory,
            _lock: lock,
            database: db,
            writable,
            epoch: state.epoch,
        };
        Ok((store, state))
    }

    pub(crate) fn save(
        &mut self,
        grants: &BTreeMap<Id, Grant>,
        epoch: u64,
        audit: Option<&ApprovalAudit>,
    ) -> Result<()> {
        if !self.writable || epoch < self.epoch || epoch > i64::MAX as u64 {
            return Err(E::StorageUnavailable);
        }
        self.validate_anchor()?;
        let state = StoredState {
            epoch,
            root_grant: self.root_grant.clone(),
            storage_identity: self.storage_identity.clone(),
            grants: grants
                .iter()
                .filter(|(_, g)| g.persistent)
                .map(|(id, g)| (id.clone(), g.clone()))
                .collect(),
        };
        let payload = serde_json::to_vec(&state)?;
        let snapshot = audit
            .map(|audit| serde_json::to_vec(&audit.plan))
            .transpose()?;
        if payload.len() > MAX_STATE
            || snapshot
                .as_ref()
                .is_some_and(|s| s.len() > 64 * 1024 * 1024)
        {
            return Err(E::StorageUnavailable);
        }
        let transaction = self.connection.transaction()?;
        transaction.execute("INSERT INTO authorization_state(singleton,payload) VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET payload=excluded.payload", [&payload])?;
        if let (Some(audit), Some(snapshot)) = (audit, snapshot) {
            transaction.execute("INSERT INTO confirmation_snapshots(receipt,digest,confirmed_at,snapshot) VALUES(?1,?2,?3,?4)", params![audit.id.as_str(), audit.digest, i64::try_from(audit.confirmed_at).map_err(|_| E::Overflow)?, snapshot])?;
        }
        transaction.commit()?;
        self.epoch = epoch;
        self.sync_directory()?;
        self.validate_anchor()?;
        Ok(())
    }

    fn validate_anchor(&self) -> Result<()> {
        let policy = planning_policy()?;
        let labels = policy.labels(&self.root);
        if labels.protected
            || labels.sensitive
            || !same_identity(
                &file_tidy_platform::inspect(&checked_existing(&self.root, false)?)?,
                &self.root_identity,
            )
            || !same_identity(
                &file_tidy_platform::inspect(&checked_existing(
                    &self.root.join(".file-tidy"),
                    false,
                )?)?,
                &self.storage_identity,
            )
        {
            return Err(E::StorageUnavailable);
        }
        file_tidy_platform::verify_private_file(&self._directory.try_clone_file()?, true)?;
        file_tidy_platform::verify_private_file(&self.database, false)?;
        for (name, file) in [(DATABASE, &self.database), ("writer.lock", &self._lock)] {
            let info = file_tidy_platform::inspect(&self.root.join(".file-tidy").join(name))?;
            if info.identity != file_tidy_platform::inspect_file(file)?.identity
                || info.kind != file_tidy_platform::NodeKind::Regular
            {
                return Err(E::StorageUnavailable);
            }
        }
        Ok(())
    }
    fn sync_directory(&self) -> Result<()> {
        #[cfg(unix)]
        self._directory_cap
            .try_clone()?
            .into_std_file()
            .sync_all()?;
        Ok(())
    }
}

fn open_file(directory: &Dir, name: &str, writable: bool) -> Result<File> {
    if !directory.symlink_metadata(name)?.is_file() {
        return Err(E::StorageUnavailable);
    }
    let mut options = OpenOptions::new();
    options.read(true).write(writable);
    let file = directory.open_with(name, &options)?.into_std();
    file_tidy_platform::verify_private_file(&file, false)?;
    Ok(file)
}
fn open_database(path: &Path, writable: bool) -> Result<Connection> {
    let flags = if writable {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags(path, flags)?;
    connection.busy_timeout(std::time::Duration::ZERO)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    let foreign_keys: u32 =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    if foreign_keys != 1 {
        return Err(E::StorageUnavailable);
    }
    if writable {
        let mode: String =
            connection.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
        if !mode.eq_ignore_ascii_case("delete") {
            return Err(E::StorageUnavailable);
        }
        connection.pragma_update(None, "synchronous", "EXTRA")?;
        let sync: u32 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
        if sync != 3 {
            return Err(E::StorageUnavailable);
        }
        #[cfg(target_os = "macos")]
        {
            connection.pragma_update(None, "fullfsync", true)?;
            let fullfsync: u32 =
                connection.pragma_query_value(None, "fullfsync", |row| row.get(0))?;
            if fullfsync != 1 {
                return Err(E::StorageUnavailable);
            }
        }
    }
    Ok(connection)
}
