//! Confirmation is bound to the exact immutable plan held by a live session.
use std::collections::BTreeSet;

use serde::Serialize;

use crate::authorization::{Id, PlanningError as E, Result, Session};
use crate::plan::{Plan, PlanPreview, now};

#[derive(Debug, Default)]
pub struct Confirmation {
    pub digest: String,
    pub item_count: Option<u64>,
    pub sensitive_acknowledgements: Vec<String>,
    pub permanent_phrase: Option<String>,
}

/// An in-memory receipt cannot be imported from JSON or reconstructed from audit.
pub struct ApprovedPlan {
    pub(crate) plan: Plan,
    pub(crate) receipt: Id,
}
impl ApprovedPlan {
    pub fn preview(&self) -> &PlanPreview {
        self.plan.preview()
    }
    pub fn digest(&self) -> &str {
        self.plan.digest()
    }
    pub fn receipt_id(&self) -> &Id {
        &self.receipt
    }
}

#[derive(Serialize)]
pub(crate) struct ApprovalAudit {
    pub id: Id,
    pub confirmed_at: u64,
    pub digest: String,
    pub plan: PlanPreview,
}

impl Session {
    pub fn confirm(&mut self, plan: Plan, confirmation: Confirmation) -> Result<ApprovedPlan> {
        self.validate_plan(&plan)?;
        let expected: BTreeSet<_> = plan.preview.sensitive_acknowledgements.iter().collect();
        let supplied: BTreeSet<_> = confirmation.sensitive_acknowledgements.iter().collect();
        let phrase =
            plan.preview.permanent_challenge.as_ref().map(|challenge| {
                format!("PERMANENT {} {challenge}", plan.preview.confirmation_count)
            });
        if confirmation.digest != plan.digest
            || (plan.preview.requires_count_confirmation
                && confirmation.item_count != Some(plan.preview.confirmation_count))
            || supplied.len() != confirmation.sensitive_acknowledgements.len()
            || supplied != expected
            || confirmation.permanent_phrase != phrase
        {
            return Err(E::ConfirmationRequired);
        }
        let receipt = Id::new()?;
        let audit = ApprovalAudit {
            id: receipt.clone(),
            confirmed_at: now()?,
            digest: plan.digest.clone(),
            plan: plan.preview.clone(),
        };
        self.store.as_mut().ok_or(E::StorageRequired)?.save(
            &self.grants,
            self.epoch,
            Some(&audit),
        )?;
        // Persisting audit can take time; it does not extend the review lifetime.
        self.validate_plan(&plan)?;
        Ok(ApprovedPlan { plan, receipt })
    }
    pub fn validate_approval(&self, approved: &ApprovedPlan) -> Result<()> {
        self.validate_plan(&approved.plan)
    }
}
