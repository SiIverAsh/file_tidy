//! Copy reconciliation uses metadata only; stored approvals do not permit hashing.
use crate::authorization::{
    PlanningError as E, Result, Session, checked_existing, planning_policy,
};
use crate::journal::BatchHistoryDetail;
use crate::plan::{PlannedOperation, Stamp};
use crate::recovery::RecoveryDisposition as D;
use file_tidy_platform as platform;
use serde_json::json;

impl Session {
    pub(crate) fn inspect_interrupted_copy(
        &self,
        op: &PlannedOperation,
        history: &BatchHistoryDetail,
    ) -> (D, String) {
        let inspect = || -> Result<(D, &'static str)> {
            let dest = op.destination.as_ref().ok_or(E::StorageUnavailable)?;
            let temporary = dest.copy_temporary.as_ref().ok_or(E::StorageUnavailable)?;
            let temp = temporary.to_path()?;
            let target = dest.path.to_path()?;
            let source = checked_existing(&op.source.to_path()?, false)?;
            let parent = checked_existing(target.parent().ok_or(E::InvalidPath)?, false)?;
            if temp.parent() != Some(parent.as_path())
                || !dest.create_directories.is_empty()
                || op.manifest.len() != 1
            {
                return Err(E::StorageUnavailable);
            }
            let policy = planning_policy()?;
            self.grant_for(&parent, &policy)?;
            if policy.labels(&parent).protected {
                return Err(E::ProtectedZone);
            }
            let parent_before = platform::inspect(&parent)?;
            if !dest.parent_stamp.same_identity(&parent_before) {
                return Ok((D::NeedsAttention, "copy_parent_changed"));
            }
            if Stamp::capture(&platform::inspect(&source)?)? != op.manifest[0].stamp {
                return Ok((D::NeedsAttention, "copy_source_changed"));
            }
            let expected = json!({"source": op.source, "destination": dest.path,
                "temporary": dest.copy_temporary, "manifest": op.manifest});
            let mut create_intent = false;
            let mut created = None;
            let mut verified = None;
            let mut publish_intent = false;
            for event in history
                .events
                .iter()
                .filter(|e| e.operation_id == op.id.as_str())
            {
                if !matches!(
                    event.step.as_str(),
                    "copy_create" | "copy_stream" | "copy_publish" | "copy_complete"
                ) || !matches!(event.phase.as_str(), "intent" | "result")
                {
                    return Err(E::StorageUnavailable);
                }
                match (event.step.as_str(), event.phase.as_str()) {
                    ("copy_create", "intent") => {
                        if create_intent || event.payload != expected {
                            return Err(E::StorageUnavailable);
                        }
                        create_intent = true;
                    }
                    ("copy_create", "result") if event.payload.get("stamp").is_some() => {
                        if !create_intent
                            || event.payload.get("temporary") != Some(&json!(temporary))
                        {
                            return Err(E::StorageUnavailable);
                        }
                        created = Some(serde_json::from_value::<Stamp>(
                            event.payload["stamp"].clone(),
                        )?);
                    }
                    ("copy_stream", "intent") => {
                        if created.is_none() || event.payload != expected {
                            return Err(E::StorageUnavailable);
                        }
                    }
                    ("copy_stream", "result") if event.payload.get("stamp").is_some() => {
                        if created.is_none()
                            || event.payload["temporary"] != json!(temporary)
                            || event.payload["length"] != op.manifest[0].size_bytes
                            || event.payload["metadata"] != json!(dest.copy_metadata)
                            || !event.payload["blake3"].as_str().is_some_and(|s| {
                                s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
                            })
                        {
                            return Err(E::StorageUnavailable);
                        }
                        let stamp: Stamp = serde_json::from_value(event.payload["stamp"].clone())?;
                        verified = Some((stamp, event.payload.clone()));
                    }
                    ("copy_publish", "intent") => {
                        if verified.as_ref().is_none_or(|(_, v)| *v != event.payload) {
                            return Err(E::StorageUnavailable);
                        }
                        publish_intent = true;
                    }
                    _ => {}
                }
            }
            let temp_info = optional(&temp)?;
            let target_info = optional(&target)?;
            let outcome = match (temp_info, target_info) {
                (None, None) if created.is_none() => (D::NotCommitted, "copy_not_created"),
                (Some(info), None) => {
                    if created.as_ref().is_none_or(|s| !s.same_identity(&info)) {
                        (D::NeedsAttention, "copy_temporary_ownership_unknown")
                    } else if verified.as_ref().is_some_and(|(s, _)| {
                        Stamp::capture(&info).is_ok_and(|actual| actual == *s)
                    }) {
                        (
                            D::VerifiedCopyObserved,
                            "verified_copy_present_recheck_required",
                        )
                    } else {
                        (D::StagedCopyObserved, "identified_copy_temporary_present")
                    }
                }
                (None, Some(info)) if publish_intent => {
                    if verified.as_ref().is_some_and(|(s, _)| {
                        Stamp::capture(&info).is_ok_and(|actual| s.matches_relocated(&actual, true))
                    }) {
                        (
                            D::CopyPublishedObserved,
                            "copy_publication_observed_recheck_required",
                        )
                    } else {
                        (D::NeedsAttention, "copy_destination_changed")
                    }
                }
                _ => (D::NeedsAttention, "copy_paths_require_review"),
            };
            if !parent_before.matches(&platform::inspect(&parent)?) {
                return Ok((D::NeedsAttention, "copy_parent_changed_during_inspection"));
            }
            Ok(outcome)
        };
        match inspect() {
            Ok((state, reason)) => (state, reason.to_owned()),
            Err(E::StorageUnavailable | E::Encoding(_)) => {
                (D::NeedsAttention, "copy_journal_inconsistent".to_owned())
            }
            Err(_) => (
                D::Unavailable,
                "copy_authorization_or_media_unavailable".to_owned(),
            ),
        }
    }
}
fn optional(path: &std::path::Path) -> Result<Option<platform::NodeInfo>> {
    match platform::inspect(path) {
        Ok(info) => Ok(Some(info)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
