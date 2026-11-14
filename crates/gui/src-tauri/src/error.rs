use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum GuiError {
    #[error("{0}")]
    Rejected(String),
    #[error("扫描结果已过期（当前代次 {current}，请求代次 {requested}），请使用最新扫描结果")]
    StaleScanGeneration { current: String, requested: String },
    #[error("计划已过期或摘要不匹配，请重新生成预览")]
    PlanMismatch,
    #[error("删除挑战码已过期或未生成，请重新请求挑战码")]
    ChallengeExpired,
    #[error("当前有文件操作正在执行，请等待完成或先取消")]
    ExecutionInFlight,
    #[error("核心扫描失败：{0}")]
    CoreScan(#[from] file_tidy_core::Error),
    #[error("操作规划或安全策略拒绝：{0}")]
    Planning(#[from] file_tidy_core::authorization::PlanningError),
    #[error("Tauri 运行时错误：{0}")]
    Tauri(#[from] tauri::Error),
}

#[derive(Serialize)]
struct ErrorPayload {
    code: &'static str,
    message: String,
}

impl Serialize for GuiError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let code = match self {
            Self::Rejected(_) => "rejected",
            Self::StaleScanGeneration { .. } => "stale_scan_generation",
            Self::PlanMismatch => "plan_mismatch",
            Self::ChallengeExpired => "challenge_expired",
            Self::ExecutionInFlight => "execution_in_flight",
            Self::CoreScan(_) => "core_scan",
            Self::Planning(_) => "planning",
            Self::Tauri(_) => "tauri",
        };
        ErrorPayload {
            code,
            message: self.to_string(),
        }
        .serialize(serializer)
    }
}

pub type GuiResult<T> = Result<T, GuiError>;
