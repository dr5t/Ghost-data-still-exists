"""
Audit engine and deterministic step sequencer for Ghost Data Still Exists challenge.

Coordinates:
- Intent classification (intent.py)
- Identity resolution (identity.py)
- Evidence indexing and temporal filtering (evidence.py)
- Deletion policy rules and compliant state checks (policy.py)

Deterministically generates and sorts findings, remediations, and verifications
strictly adhering to the evaluation contract.
"""

from typing import Dict, List, Optional, Set, Tuple
import csv
import json
import os

from identity import IdentityResolver, UserIdentityGraph
from evidence import EvidenceIndexer, EvidenceItem
from intent import classify_intent
from policy import (
    is_violation,
    finding_operation,
    remediation_operation,
    verification_operation,
    compliant_state,
    get_required_action,
)

# ── Step Ordering Constants ──────────────────────────────────────────

PHASE_ORDER = {
    "FINDING": 1,
    "REMEDIATION": 2,
    "VERIFICATION": 3,
}

OP_ORDER = {
    # Findings
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,
    # Remediation
    "DISABLE_DATA_FLOW": 1,
    "BLOCK_RESTORE": 2,
    "DELETE_RECORD": 3,
    "REDACT_RECORD": 4,
    "ANONYMIZE_RECORD": 5,
    # Verification
    "VERIFY_RECORD_ABSENT": 1,
    "VERIFY_RECORD_PRESENT": 2,
    "VERIFY_RECORD_REDACTED": 3,
    "VERIFY_RECORD_ANONYMIZED": 4,
    "VERIFY_DATA_FLOW_DISABLED": 5,
    "VERIFY_RESTORE_BLOCKED": 6,
}


def sort_steps(steps: List[dict]) -> List[dict]:
    """
    Sort steps deterministically by:
    1. Phase (FINDING -> REMEDIATION -> VERIFICATION)
    2. Operation order within phase (per problem statement table)
    3. system_id ascending
    4. resource_id ascending
    Consecutively numbers step_no starting at 1.
    """
    def key_fn(s: dict):
        return (
            PHASE_ORDER.get(s["phase"], 99),
            OP_ORDER.get(s["operation"], 99),
            s["system_id"],
            s["resource_id"],
        )

    sorted_list = sorted(steps, key=key_fn)
    for idx, s in enumerate(sorted_list, start=1):
        s["step_no"] = idx
    return sorted_list


class AuditEngine:
    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = dataset_dir
        self.identity_resolver = IdentityResolver(dataset_dir)
        self.evidence_indexer = EvidenceIndexer(dataset_dir)
        self.system_activities: List[dict] = []
        self._load_system_activity()

    def _load_system_activity(self) -> None:
        act_path = os.path.join(self.dataset_dir, "system_activity.csv")
        if not os.path.exists(act_path):
            return
        with open(act_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            self.system_activities = list(reader)

    def audit_case(self, req: dict) -> Tuple[str, List[dict]]:
        """
        Audits a single deletion request.
        Returns: (deletion_status, steps)
        """
        case_id = req["case_id"]
        email = req["email"].strip()
        request_text = req.get("request_text", "")
        requested_at = req.get("requested_at", "")
        reported_status = req.get("reported_status", "")
        reported_at = req.get("reported_at", "")
        audit_at = req.get("audit_at", "")

        # 1. Determine intent first
        is_deletion, reason = classify_intent(request_text)
        if not is_deletion:
            return ("NOT_APPLICABLE", [])

        # 2. Resolve identity graph
        user_graph = self.identity_resolver.resolve(email)
        if not user_graph:
            return ("NOT_APPLICABLE", [])

        # 3. Retrieve all evidence items up to audit_at
        evidence_items = self.evidence_indexer.get_evidence_for_case(user_graph, audit_at)

        # 4. Aggregate resource states from evidence
        # Map: resource_id -> latest EvidenceItem
        resource_evidence: Dict[str, EvidenceItem] = {}
        for item in sorted(evidence_items, key=lambda x: x.captured_at):
            resource_evidence[item.resource_id] = item

        # Also determine primary account resource if not in evidence
        # Check system_activity in deletion window [requested_at, reported_at]
        account_res_id = None
        for res_id, item in resource_evidence.items():
            if item.system_id == "account_service":
                account_res_id = res_id
                break

        if not account_res_id:
            # Check system activity around deletion worker
            for a in self.system_activities:
                if requested_at <= a["event_time"] <= reported_at:
                    if a["source_system"] == "deletion_worker" and a["target_system"] == "account_service":
                        account_res_id = a["resource_id"]
                        break

        if not account_res_id and user_graph.user_id.startswith("user_"):
            try:
                num = int(user_graph.user_id.split("_")[1])
                account_res_id = f"account_{num:03d}"
            except Exception:
                account_res_id = f"account_{user_graph.user_id}"

        # If account resource was not in evidence, determine state at audit_at
        if account_res_id and account_res_id not in resource_evidence:
            # Check if there is an account database snapshot (e.g., failover replica) up to audit_at
            # In evidence_54 (2026-09-02T23:00:00Z) or similar
            ev_id = ""
            for fid, meta in self.evidence_indexer.manifest.items():
                if "customer_accounts_failover_replica" in meta["file_path"] and meta["captured_at"] <= audit_at:
                    ev_id = fid
                    break
            if not ev_id:
                for fid, meta in self.evidence_indexer.manifest.items():
                    if "customer_data_inventory" in meta["file_path"] and meta["captured_at"] <= audit_at:
                        ev_id = fid
                        break

            resource_evidence[account_res_id] = EvidenceItem(
                evidence_id=ev_id,
                file_path="",
                origin="account_service",
                captured_at=audit_at,
                system_id="account_service",
                resource_id=account_res_id,
                data_category="USER_PROFILE",
                state="ABSENT",
                identifiers=user_graph.emails | {user_graph.user_id},
            )

        # 5. Evaluate compliance and partition violations vs compliant
        violations: List[EvidenceItem] = []
        compliant: List[EvidenceItem] = []

        for res_id, item in resource_evidence.items():
            if is_violation(item.data_category, item.state):
                violations.append(item)
            else:
                compliant.append(item)

        # Determine overall case deletion status
        status = "INCOMPLETE" if len(violations) > 0 else "COMPLETE"

        # 6. Generate steps
        raw_steps: List[dict] = []

        if status == "INCOMPLETE":
            # Phase 1: Findings (cite participant-visible evidence)
            for item in violations:
                op, st = finding_operation(item.data_category, item.state)
                raw_steps.append({
                    "phase": "FINDING",
                    "system_id": item.system_id,
                    "resource_id": item.resource_id,
                    "operation": op,
                    "state": st,
                    "evidence_id": item.evidence_id,
                })

            # Phase 2: Remediation (empty evidence_id)
            for item in violations:
                op, st = remediation_operation(item.data_category)
                raw_steps.append({
                    "phase": "REMEDIATION",
                    "system_id": item.system_id,
                    "resource_id": item.resource_id,
                    "operation": op,
                    "state": st,
                    "evidence_id": "",
                })

            # Phase 3: Post-remediation verification for all resources (empty evidence_id)
            for item in violations + compliant:
                op, st = verification_operation(item.data_category, is_complete=False)
                raw_steps.append({
                    "phase": "VERIFICATION",
                    "system_id": item.system_id,
                    "resource_id": item.resource_id,
                    "operation": op,
                    "state": st,
                    "evidence_id": "",
                })
        else:
            # Status is COMPLETE: only verification steps proving compliant state
            for item in compliant:
                op, st = verification_operation(item.data_category, is_complete=True)
                raw_steps.append({
                    "phase": "VERIFICATION",
                    "system_id": item.system_id,
                    "resource_id": item.resource_id,
                    "operation": op,
                    "state": st,
                    "evidence_id": item.evidence_id,
                })

        # 7. Sort deterministically and number consecutively
        final_steps = sort_steps(raw_steps)
        return (status, final_steps)
