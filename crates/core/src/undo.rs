//! Inverses are new reviewed plans; original plans and results remain immutable.
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::CancellationToken;
use crate::approval::ApprovedPlan;
use crate::authorization::{Id, NativePath, PlanningError as E, Result, Session};
use crate::content::OperationContentPermit;
use crate::copy::checkpoint;
use crate::journal::{BatchHistoryDetail, OperationState, id_bytes, native_path};
use crate::plan::{
    OperationKind as K, OperationRequest, Plan, PlanOptions, PlanPreview, PlannedOperation, Stamp,
};
use crate::quarantine::ManagedOperation;
use crate::tree_copy::{TreeEntryProof, tree_seal, validate_proof_shape};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InverseReference {
    pub batch: Id,
    pub operation: Id,
}
impl PlannedOperation {
    pub(crate) fn inverse_operation(&self) -> Option<&Id> {
        self.inverse
            .as_ref()
            .map(|inverse| &inverse.operation)
            .or(match &self.managed {
                Some(ManagedOperation::Restore { item, .. }) => Some(item),
                _ => None,
            })
    }
}

impl Session {
    /// An empty selection means all completed operations, in reverse batch order.
    pub fn build_undo_plan(
        &self,
        batch: &Id,
        selected: &[Id],
        options: PlanOptions,
    ) -> Result<Plan> {
        let history = self.batch_history(batch)?;
        let preview: PlanPreview = serde_json::from_value(history.snapshot.clone())?;
        let wanted: BTreeSet<_> = selected.iter().collect();
        if wanted.len() != selected.len()
            || wanted
                .iter()
                .any(|id| !preview.operations.iter().any(|op| &op.id == *id))
        {
            return Err(E::InvalidRequest);
        }
        let originals = preview
            .operations
            .iter()
            .zip(&history.operations)
            .filter(|(op, row)| {
                row.state == OperationState::Done && (wanted.is_empty() || wanted.contains(&op.id))
            })
            .map(|(op, _)| &op.id)
            .collect::<BTreeSet<_>>();
        if originals.is_empty() {
            return Err(E::InvalidRequest);
        }
        let mut operations = Vec::new();
        let mut requests = Vec::new();
        let batch_id = Id::new()?;
        let mut budget = options.max_entries;
        for (original, recorded) in preview.operations.iter().zip(&history.operations).rev() {
            if !wanted.is_empty() && !wanted.contains(&original.id) {
                continue;
            }
            if recorded.state != OperationState::Done {
                if wanted.contains(&original.id) {
                    return Err(E::InvalidRequest);
                }
                continue;
            }
            if original.kind == K::PermanentDelete {
                return Err(E::IrreversibleOperation);
            }
            match self.check_undo_dependencies(&original.id, &originals) {
                Err(E::AlreadyUndone) if wanted.is_empty() => continue,
                result => result?,
            }
            let source = original
                .destination
                .as_ref()
                .ok_or(E::InvalidRequest)?
                .path
                .to_path()?;
            let mut inverse = match original.kind {
                K::Quarantine | K::UndoCopy => self.build_restore_plan(
                    std::slice::from_ref(&original.id),
                    None,
                    options.clone(),
                )?,
                K::Move | K::Rename => self.build_plan(
                    vec![OperationRequest {
                        kind: original.kind,
                        source: source.clone(),
                        destination: Some(original.source.to_path()?),
                    }],
                    options.clone(),
                )?,
                K::Copy | K::Restore => self.build_plan(
                    vec![OperationRequest {
                        kind: K::Quarantine,
                        source: source.clone(),
                        destination: None,
                    }],
                    options.clone(),
                )?,
                K::PermanentDelete => return Err(E::InvalidRequest),
            };
            let mut op = inverse.preview.operations.remove(0);
            if let Some(proof) = crate::migration::completed_proof(original, &history)? {
                self.verify_migration_undo_metadata(&proof)?;
                self.prepare_migration_review(&mut op, &batch_id, &options, true)?;
            }
            if original.kind == K::Copy {
                op.kind = K::UndoCopy;
            }
            // Retain sensitivity learned by the original operation, even after renaming.
            let original_root = original.source.to_path()?;
            let old = original
                .manifest
                .iter()
                .map(|entry| {
                    Ok((
                        entry
                            .path
                            .to_path()?
                            .strip_prefix(&original_root)
                            .map_err(|_| E::StorageUnavailable)?
                            .to_owned(),
                        entry.sensitive,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            let inverse_root = op.source.to_path()?;
            for entry in &mut op.manifest {
                let path = entry.path.to_path()?;
                entry.sensitive |= old
                    .get(
                        path.strip_prefix(&inverse_root)
                            .map_err(|_| E::InvalidPlan)?,
                    )
                    .copied()
                    .ok_or(E::StorageUnavailable)?;
            }
            budget = budget
                .checked_sub(op.manifest.len())
                .ok_or(E::IncompleteManifest)?;
            op.inverse = Some(InverseReference {
                batch: batch.clone(),
                operation: original.id.clone(),
            });
            self.rebind_quarantine(&mut op, &batch_id)?;
            requests.push(OperationRequest {
                kind: op.kind,
                source: op.source.to_path()?,
                destination: op
                    .destination
                    .as_ref()
                    .map(|d| d.path.to_path())
                    .transpose()?,
            });
            operations.push(op);
        }
        if operations.is_empty() {
            return Err(E::AlreadyUndone);
        }
        self.seal_plan(operations, requests, options, batch_id)
    }

    pub(crate) fn select_inverse_operations(
        &self,
        plan: &Plan,
        wanted: &BTreeSet<&Id>,
    ) -> Result<Plan> {
        let batch = Id::new()?;
        let mut operations = Vec::new();
        let mut requests = Vec::new();
        for op in &plan.preview.operations {
            if wanted.contains(&op.id) {
                let mut op = op.clone();
                op.id = Id::new()?;
                self.rebind_quarantine(&mut op, &batch)?;
                requests.push(OperationRequest {
                    kind: op.kind,
                    source: op.source.to_path()?,
                    destination: op
                        .destination
                        .as_ref()
                        .map(|d| d.path.to_path())
                        .transpose()?,
                });
                operations.push(op);
            }
        }
        self.seal_plan(operations, requests, plan.preview.options.clone(), batch)
    }

    pub(crate) fn inverse_original(
        &self,
        op: &PlannedOperation,
    ) -> Result<(PlannedOperation, BatchHistoryDetail)> {
        let inverse = op.inverse.as_ref().ok_or(E::InvalidPlan)?;
        let history = self.batch_history(&inverse.batch)?;
        let preview: PlanPreview = serde_json::from_value(history.snapshot.clone())?;
        let original = preview
            .operations
            .into_iter()
            .zip(&history.operations)
            .find(|(p, _)| p.id == inverse.operation)
            .ok_or(E::StorageUnavailable)?;
        if original.1.state != OperationState::Done {
            return Err(E::InvalidRequest);
        }
        Ok((original.0, history))
    }

    pub(crate) fn validate_inverse_operation(
        &self,
        plan: &Plan,
        op: &PlannedOperation,
    ) -> Result<()> {
        if op.inverse.is_none() {
            return Ok(());
        }
        let (original, history) = self.inverse_original(op)?;
        let live_ids = plan
            .preview
            .operations
            .iter()
            .flat_map(|o| {
                std::iter::once(&o.id).chain(o.inverse.as_ref().map(|inverse| &inverse.operation))
            })
            .collect();
        self.check_undo_dependencies(&original.id, &live_ids)?;
        let target = original
            .destination
            .as_ref()
            .ok_or(E::StorageUnavailable)?
            .path
            .to_path()?;
        if op.source.to_path()? != target {
            return Err(E::InvalidPlan);
        }
        match original.kind {
            K::Copy if op.kind == K::UndoCopy => {
                let proof = copy_proof(self, &original, &history)?;
                self.verify_tree_copy(&target, &proof, true)?;
            }
            K::Move | K::Rename if op.kind == original.kind => {
                if let Some(proof) = crate::migration::completed_proof(&original, &history)? {
                    self.verify_migration_undo_metadata(&proof)?;
                } else {
                    self.verify_renamed(&original, &target)?;
                }
            }
            K::Restore if op.kind == K::Quarantine => {
                self.verify_renamed(&original, &target)?;
            }
            K::Quarantine | K::UndoCopy if op.kind == K::Restore => {
                if !matches!(&op.managed, Some(ManagedOperation::Restore {item,..}) if item == &original.id)
                {
                    return Err(E::InvalidPlan);
                }
            }
            _ => return Err(E::InvalidRequest),
        }
        Ok(())
    }

    fn check_undo_dependencies(&self, original: &Id, live: &BTreeSet<&Id>) -> Result<()> {
        struct Later {
            id: Id,
            inverse: Option<Id>,
            state: String,
            paths: Vec<PathBuf>,
            stamps: Vec<Stamp>,
        }
        let (target, stamps, rows) = self.store.as_ref().ok_or(E::StorageRequired)?.journal_read(|db| {
            let (ordinal, encoding, destination, after): (i64,String,Vec<u8>,Vec<u8>) = db.query_row("SELECT rowid,path_encoding,destination_path,after_fingerprint FROM operations WHERE op_id=?1 AND state='done'",[id_bytes(original)?],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
            let target = native_path(&encoding,&destination)?.to_path()?;
            let after: Value = serde_json::from_slice(&after)?;
            let stamps = if let Some(entries) = after.get("entries") {
                serde_json::from_value::<Vec<TreeEntryProof>>(entries.clone())?.into_iter().map(|entry|entry.stamp).collect::<Vec<_>>()
            } else if let Some(entries) = after.get("observed_manifest") {
                serde_json::from_value::<Vec<crate::plan::ManifestEntry>>(entries.clone())?.into_iter().map(|entry|entry.stamp).collect()
            } else if after.get("protocol").and_then(Value::as_str)==Some("verified_migration") {
                vec![serde_json::from_value::<Stamp>(after.get("target").ok_or(E::StorageUnavailable)?.clone())?]
            } else { vec![serde_json::from_value::<Stamp>(after.get("stamp").ok_or(E::StorageUnavailable)?.clone())?] };
            let mut query = db.prepare("SELECT hex(op_id),CASE WHEN inverse_of IS NULL THEN NULL ELSE hex(inverse_of) END,state,path_encoding,source_path,destination_path,manifest FROM operations WHERE rowid>?1 ORDER BY rowid DESC LIMIT 10001")?;
            let mut result=Vec::new();
            let mut rows=query.query([ordinal])?;
            let mut bytes=0usize;
            while let Some(row)=rows.next()? {
                let encoding:String=row.get(3)?;
                let source:Vec<u8>=row.get(4)?;
                let destination:Option<Vec<u8>>=row.get(5)?;
                let manifest:Vec<u8>=row.get(6)?;
                bytes=bytes.checked_add(manifest.len()).ok_or(E::Overflow)?;
                if bytes>64*1024*1024 { return Err(E::Overflow); }
                let stamps=serde_json::from_slice::<Vec<crate::plan::ManifestEntry>>(&manifest)?.into_iter().map(|entry|entry.stamp).collect();
                let mut paths=vec![native_path(&encoding,&source)?.to_path()?];
                if let Some(dest)=destination { paths.push(native_path(&encoding,&dest)?.to_path()?); }
                result.push(Later {id:row.get::<_,String>(0)?.parse()?,inverse:row.get::<_,Option<String>>(1)?.map(|v|v.parse()).transpose()?,state:row.get(2)?,paths,stamps});
            }
            if result.len()>10000 { return Err(E::Overflow); }
            Ok((target,stamps,result))
        })?;
        let mut undone = BTreeSet::new();
        let mut active = Vec::new();
        for row in rows {
            if live.contains(&row.id)
                || undone.contains(&row.id)
                || matches!(row.state.as_str(), "planned" | "skipped" | "failed")
            {
                continue;
            }
            if row.state == "done"
                && let Some(inverse) = &row.inverse
            {
                undone.insert(inverse.clone());
            }
            active.push(row);
        }
        if undone.contains(original) {
            return Err(E::AlreadyUndone);
        }
        let objects = stamps
            .iter()
            .map(Stamp::object_key)
            .collect::<BTreeSet<_>>();
        for row in active {
            if row
                .paths
                .iter()
                .any(|path| path.starts_with(&target) || target.starts_with(path))
                || row
                    .stamps
                    .iter()
                    .any(|stamp| objects.contains(&stamp.object_key()))
            {
                return Err(E::DependentOperation);
            }
        }
        Ok(())
    }

    pub(crate) fn verify_undo_copy(
        &self,
        approved: &ApprovedPlan,
        op: &PlannedOperation,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let (original, history) = self.inverse_original(op)?;
        let proof = copy_proof(self, &original, &history)?;
        let root = op.source.to_path()?;
        self.verify_tree_copy(&root, &proof, true)?;
        let expected = proof
            .iter()
            .map(|entry| Ok((entry.relative.to_path()?, entry)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        for entry in &op.manifest {
            if entry.kind != "Regular" {
                continue;
            }
            checkpoint(cancel)?;
            let path = entry.path.to_path()?;
            let before = expected
                .get(path.strip_prefix(&root).map_err(|_| E::InvalidPlan)?)
                .ok_or(E::StorageUnavailable)?;
            let permit = OperationContentPermit::issue_entry(self, approved, op, entry)?;
            let mut file = permit.open()?;
            let mut hasher = blake3::Hasher::new();
            let length = entry.size_bytes.parse::<u64>().map_err(|_| E::Overflow)?;
            let mut remaining = length;
            let mut buffer = vec![0u8; 128 * 1024];
            while remaining > 0 {
                checkpoint(cancel)?;
                permit.check_live()?;
                let chunk = remaining.min(buffer.len() as u64) as usize;
                let count = file.read(&mut buffer[..chunk])?;
                if count == 0 {
                    return Err(E::ChangedSincePlan);
                }
                hasher.update(&buffer[..count]);
                remaining -= count as u64;
            }
            let mut tail = [0u8; 1];
            if file.read(&mut tail)? != 0
                || Some(hasher.finalize().to_hex().as_str()) != before.blake3.as_deref()
            {
                return Err(E::ChangedSincePlan);
            }
            permit.verify_after(&file)?;
        }
        self.verify_tree_copy(&root, &proof, true)
    }
}

fn result<'a>(
    events: &'a [crate::journal::JournalEvent],
    op: &PlannedOperation,
    step: &str,
) -> Result<&'a Value> {
    let mut results = events
        .iter()
        .filter(|e| e.operation_id == op.id.as_str() && e.step == step && e.phase == "result");
    let value = results.next().ok_or(E::StorageUnavailable)?;
    if results.next().is_some()
        || !events.iter().any(|e| {
            e.operation_id == op.id.as_str()
                && e.id < value.id
                && e.step == step
                && e.phase == "intent"
        })
    {
        return Err(E::StorageUnavailable);
    }
    Ok(&value.payload)
}
fn copy_proof(
    session: &Session,
    op: &PlannedOperation,
    history: &BatchHistoryDetail,
) -> Result<Vec<TreeEntryProof>> {
    if op.kind != K::Copy {
        return Err(E::InvalidRequest);
    }
    let events = session.store.as_ref().ok_or(E::StorageRequired)?.journal_read(|db| {
        let mut query=db.prepare("SELECT event_id,step,phase,payload,created_at_s FROM operation_events WHERE op_id=?1 AND step IN ('copy_create','copy_stream','copy_publish','copy_complete','tree_create','tree_verify','tree_publish','tree_complete') ORDER BY event_id LIMIT 25")?;
        let mut rows=query.query(params![id_bytes(&op.id)?])?;
        let mut events=Vec::new();
        let mut total=0usize;
        while let Some(row)=rows.next()? {
            let payload:Vec<u8>=row.get(3)?;
            total=total.checked_add(payload.len()).ok_or(E::Overflow)?;
            if payload.len()>64*1024*1024 || total>192*1024*1024 {return Err(E::Overflow);}
            events.push(crate::journal::JournalEvent {id:row.get::<_,i64>(0)?.try_into().map_err(|_|E::StorageUnavailable)?,operation_id:op.id.to_string(),step:row.get(1)?,phase:row.get(2)?,payload:serde_json::from_slice(&payload)?,created_at:row.get::<_,i64>(4)?.try_into().map_err(|_|E::StorageUnavailable)?});
        }
        if events.len()>24 {return Err(E::StorageUnavailable);}
        Ok(events)
    })?;
    let destination = op.destination.as_ref().ok_or(E::StorageUnavailable)?;
    let root = op
        .manifest
        .iter()
        .find(|e| e.path == op.source)
        .ok_or(E::StorageUnavailable)?;
    let record = history
        .operations
        .iter()
        .find(|r| r.id == op.id.as_str())
        .ok_or(E::StorageUnavailable)?;
    let proof = if root.kind == "Directory" {
        let verify = result(&events, op, "tree_verify")?;
        let proof: Vec<TreeEntryProof> =
            serde_json::from_value(verify.get("entries").ok_or(E::StorageUnavailable)?.clone())?;
        validate_proof_shape(op, &proof)?;
        let created: Stamp = serde_json::from_value(
            result(&events, op, "tree_create")?
                .get("stamp")
                .ok_or(E::StorageUnavailable)?
                .clone(),
        )?;
        let root = proof
            .iter()
            .find(|entry| {
                entry
                    .relative
                    .to_path()
                    .is_ok_and(|path| path.as_os_str().is_empty())
            })
            .ok_or(E::StorageUnavailable)?;
        if !created.same_recorded_object(&root.stamp) {
            return Err(E::StorageUnavailable);
        }
        let seal = tree_seal(destination, &proof)?;
        if verify.get("temporary") != Some(&json!(destination.copy_temporary))
            || verify.get("metadata") != Some(&json!(destination.copy_metadata))
            || !events.iter().any(|e| {
                e.operation_id == op.id.as_str()
                    && e.step == "tree_publish"
                    && e.phase == "intent"
                    && e.payload == seal
            })
        {
            return Err(E::StorageUnavailable);
        }
        let published = json!({"destination":destination.path,"entries":proof,"metadata":destination.copy_metadata});
        if result(&events, op, "tree_publish")? != &published
            || result(&events, op, "tree_complete")? != &published
            || record.after_fingerprint.as_ref() != Some(&published)
        {
            return Err(E::StorageUnavailable);
        }
        proof
    } else if root.kind == "Regular" && op.manifest.len() == 1 {
        let created: Stamp = serde_json::from_value(
            result(&events, op, "copy_create")?
                .get("stamp")
                .ok_or(E::StorageUnavailable)?
                .clone(),
        )?;
        let verify = result(&events, op, "copy_stream")?;
        let verified: Stamp =
            serde_json::from_value(verify.get("stamp").ok_or(E::StorageUnavailable)?.clone())?;
        let final_result = result(&events, op, "copy_complete")?;
        let stamp: Stamp = serde_json::from_value(
            final_result
                .get("stamp")
                .ok_or(E::StorageUnavailable)?
                .clone(),
        )?;
        let hash = final_result
            .get("blake3")
            .and_then(Value::as_str)
            .ok_or(E::StorageUnavailable)?;
        if final_result.get("source") != Some(&json!(op.source))
            || final_result.get("destination") != Some(&json!(destination.path))
            || final_result.get("metadata") != Some(&json!(destination.copy_metadata))
            || final_result.get("length") != Some(&json!(root.size_bytes))
            || hash.len() != 64
            || !hash.bytes().all(|b| b.is_ascii_hexdigit())
            || !created.same_recorded_object(&stamp)
            || !verified.matches_relocated(&stamp, true)
            || verify.get("blake3") != final_result.get("blake3")
            || result(&events, op, "copy_publish")? != final_result
            || record.after_fingerprint.as_ref() != Some(final_result)
        {
            return Err(E::StorageUnavailable);
        }
        vec![TreeEntryProof {
            relative: NativePath::new(Path::new("")),
            kind: root.kind.clone(),
            stamp,
            length: root.size_bytes.clone(),
            blake3: Some(hash.to_owned()),
            link_target: None,
            symlink_directory: None,
        }]
    } else {
        return Err(E::StorageUnavailable);
    };
    Ok(proof)
}
