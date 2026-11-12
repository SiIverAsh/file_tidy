#![forbid(unsafe_code)]

//! Read-only file inventory, classification, and duplicate detection.

pub mod classify;
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
