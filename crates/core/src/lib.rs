#![forbid(unsafe_code)]

//! Local file inventory, directory grants, and reviewed operation plans.

pub mod approval;
pub mod authorization;
pub mod classify;
pub mod execution;
pub mod journal;
pub mod plan;
pub mod recovery;
mod storage;
mod suggestions;
pub use storage::{StoragePlan, StoragePreview};
pub use suggestions::suggested_directories;
mod content;
mod model;
pub mod policy;
mod report;
mod scan;

pub use classify::{Category, Classification, RuleError, Rules, TypeEvidence};
pub use content::load_rules;
pub use model::*;
pub use report::render_text;
pub use scan::{CancellationToken, Progress, ScanOptions, ScanPhase, scan};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid scan options: {0}")]
    InvalidOptions(String),
    #[error("cannot initialize read-only filesystem inventory")]
    Inventory(#[source] std::io::Error),
    #[error("cannot create bounded worker pool")]
    WorkerPool(#[source] rayon::ThreadPoolBuildError),
    #[error("configuration content read denied or file changed")]
    ConfigurationDenied,
    #[error("configuration exceeds the 1 MiB limit")]
    ConfigurationTooLarge,
    #[error("configuration is not valid UTF-8")]
    ConfigurationEncoding,
    #[error("invalid classification rules")]
    Rules(#[source] RuleError),
    #[error("inventory byte count exceeds supported integer range")]
    SizeOverflow,
}
