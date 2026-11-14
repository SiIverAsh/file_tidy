use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use file_tidy_core::authorization::{Grant, Session};
use file_tidy_core::plan::Plan;
use file_tidy_core::{CancellationToken, Rules, ScanReport, StoragePlan};

use crate::error::{GuiError, GuiResult};

pub const PERMANENT_CHALLENGE_TTL_SECS: u64 = 180;

#[derive(Default)]
pub struct ScanSlot {
    pub generation: u64,
    pub report: Option<Arc<ScanReport>>,
    pub cancel: Option<CancellationToken>,
    pub running: bool,
}

pub struct ActivePlanRecord {
    pub plan: Plan,
    pub plan_id: String,
    pub plan_digest: String,
}

pub struct PendingPermanentChallenge {
    pub plan_id: String,
    pub plan_digest: String,
    pub challenge_code: String,
    pub confirmation_count: u64,
    pub expires_at: u64,
}

#[derive(Default)]
pub struct PlanSlot {
    pub active: Option<ActivePlanRecord>,
    pub permanent_challenge: Option<PendingPermanentChallenge>,
}

pub struct AppState {
    pub scan: Arc<RwLock<ScanSlot>>,
    pub plan: Arc<Mutex<PlanSlot>>,
    pub exec_in_flight: Arc<AtomicBool>,
    pub exec_cancel: Arc<Mutex<Option<CancellationToken>>>,
    pub session: Arc<tokio::sync::Mutex<Session>>,
    pub pending_roots: Arc<Mutex<Vec<PathBuf>>>,
    pub pending_rules: Arc<Mutex<Option<(String, Rules)>>>,
    pub pending_grants: Arc<Mutex<BTreeMap<String, Grant>>>,
    pub pending_storage_plans: Arc<Mutex<BTreeMap<String, (StoragePlan, String)>>>,
    pub picked_destinations: Arc<Mutex<BTreeMap<String, PathBuf>>>,
    pub storage_root_display: Arc<Mutex<Option<String>>>,
    pub known_epoch: Arc<AtomicU64>,
}

impl AppState {
    pub fn new() -> GuiResult<Self> {
        let session = Session::new()?;
        Ok(Self {
            scan: Arc::new(RwLock::new(ScanSlot::default())),
            plan: Arc::new(Mutex::new(PlanSlot::default())),
            exec_in_flight: Arc::new(AtomicBool::new(false)),
            exec_cancel: Arc::new(Mutex::new(None)),
            session: Arc::new(tokio::sync::Mutex::new(session)),
            pending_roots: Arc::new(Mutex::new(Vec::new())),
            pending_rules: Arc::new(Mutex::new(None)),
            pending_grants: Arc::new(Mutex::new(BTreeMap::new())),
            pending_storage_plans: Arc::new(Mutex::new(BTreeMap::new())),
            picked_destinations: Arc::new(Mutex::new(BTreeMap::new())),
            storage_root_display: Arc::new(Mutex::new(None)),
            known_epoch: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn snapshot_scan(&self, requested_generation: &str) -> GuiResult<(u64, Arc<ScanReport>)> {
        let guard = self
            .scan
            .read()
            .map_err(|_| GuiError::Rejected("扫描状态锁不可用".to_owned()))?;
        let current_str = guard.generation.to_string();
        if current_str != requested_generation {
            return Err(GuiError::StaleScanGeneration {
                current: current_str,
                requested: requested_generation.to_owned(),
            });
        }
        let report = guard
            .report
            .as_ref()
            .cloned()
            .ok_or_else(|| GuiError::Rejected("尚未完成任何扫描".to_owned()))?;
        Ok((guard.generation, report))
    }
}

pub fn now_unix_secs() -> GuiResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| GuiError::Rejected("系统时钟异常".to_owned()))
}

pub fn generate_challenge_code() -> GuiResult<String> {
    let mut bytes = [0u8; 6];
    getrandom::fill(&mut bytes).map_err(|_| GuiError::Rejected("系统随机数不可用".to_owned()))?;
    Ok(bytes.iter().map(|b| format!("{b:02X}")).collect())
}
