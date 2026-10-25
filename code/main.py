"""Deterministic deletion-audit orchestration and CSV serialization.

This module deliberately separates evidence discovery from policy decisions:
``EvidenceIndexer`` yields only evidence connected to a resolved identity and
captured by the audit cutoff; this engine reduces those observations to the
latest state of each resource and applies the supplied policy helpers.
"""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple

from evidence import EvidenceIndexer, EvidenceItem
from identity import IdentityResolver
from intent import classify_intent
from policy import (
    finding_operation,
    is_violation,
    remediation_operation,
    verification_operation,
)


STEP_FIELDS = (
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
)

FINDING_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
}
REMEDIATION_ORDER = {
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
}
VERIFICATION_ORDER = {
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}


@dataclass(frozen=True)
class AuditResult:
    case_id: str
    deletion_status: str
    steps: Tuple[Mapping[str, object], ...]


class AuditEngine:
    """Assess one deletion request from indexed, participant-visible evidence."""

    def __init__(self, resolver: IdentityResolver, evidence: EvidenceIndexer):
        self.resolver = resolver
        self.evidence = evidence

    @staticmethod
    def _resource_key(item: EvidenceItem) -> Tuple[str, str, str]:
        return (item.system_id, item.resource_id, item.data_category)

    def _latest_resources(
        self, user_graph, audit_at: str
    ) -> List[EvidenceItem]:
        """Return one deterministic, cutoff-filtered observation per resource.

        Later captures supersede earlier captures of the same resource.  A
        resource is never inferred solely from an activity-log operation: those
        rows are workflow claims, not current-state evidence.
        """
        selected: Dict[Tuple[str, str, str], EvidenceItem] = {}
        for item in self.evidence.get_evidence_for_case(user_graph, audit_at):
            key = self._resource_key(item)
            prior = selected.get(key)
            if prior is None or (item.captured_at, item.evidence_id) > (
                prior.captured_at,
                prior.evidence_id,
            ):
                selected[key] = item
        return sorted(selected.values(), key=lambda item: self._resource_key(item))

    @staticmethod
    def _sort_steps(steps: Iterable[Dict[str, object]], phase: str) -> List[Dict[str, object]]:
        operation_order = {
            "FINDING": FINDING_ORDER,
            "REMEDIATION": REMEDIATION_ORDER,
            "VERIFICATION": VERIFICATION_ORDER,
        }[phase]
        return sorted(
            steps,
            key=lambda step: (
                operation_order[step["operation"]],
                step["system_id"],
                step["resource_id"],
            ),
        )

    @staticmethod
    def _step(
        phase: str,
        item: EvidenceItem,
        operation: str,
        state: str,
        evidence_id: str,
    ) -> Dict[str, object]:
        return {
            "step_no": 0,
            "phase": phase,
            "system_id": item.system_id,
            "resource_id": item.resource_id,
            "operation": operation,
            "state": state,
            "evidence_id": evidence_id,
        }

    def audit(self, request: Mapping[str, str]) -> AuditResult:
        case_id = request["case_id"]
        intent, _ = classify_intent(request.get("request_text", ""))
        if intent != "DELETION":
            return AuditResult(case_id, "NOT_APPLICABLE", ())

        user_graph = self.resolver.resolve_by_email(request.get("email", ""))
        if user_graph is None:
            # An authorized request with no resolvable identity cannot be proven
            # complete.  No fabricated resource or evidence step is emitted.
            return AuditResult(case_id, "INCOMPLETE", ())

        resources = self._latest_resources(user_graph, request["audit_at"])
        if not resources:
            # Absence of linked evidence is not evidence of deletion.
            return AuditResult(case_id, "INCOMPLETE", ())
        violations = [
            item
            for item in resources
            if is_violation(item.data_category, item.state)
        ]

        if not violations:
            verification = []
            for item in resources:
                operation, state = verification_operation(item.data_category)
                verification.append(
                    self._step("VERIFICATION", item, operation, state, item.evidence_id)
                )
            return self._result(case_id, "COMPLETE", (), (), verification)

        findings = []
        remediations = []
        for item in violations:
            finding_op, finding_state = finding_operation(item.data_category, item.state)
            findings.append(
                self._step(
                    "FINDING", item, finding_op, finding_state, item.evidence_id
                )
            )
            remediation_op, remediation_state = remediation_operation(item.data_category)
            remediations.append(
                self._step("REMEDIATION", item, remediation_op, remediation_state, "")
            )

        # An incomplete case plans verification for every evidenced resource,
        # including resources already compliant, because the final state must be
        # demonstrated after dependent remediations have run.
        verification = []
        for item in resources:
            operation, state = verification_operation(item.data_category)
            verification.append(self._step("VERIFICATION", item, operation, state, ""))
        return self._result(case_id, "INCOMPLETE", findings, remediations, verification)

    def _result(
        self,
        case_id: str,
        status: str,
        findings: Sequence[Dict[str, object]],
        remediations: Sequence[Dict[str, object]],
        verification: Sequence[Dict[str, object]],
    ) -> AuditResult:
        ordered = (
            self._sort_steps(findings, "FINDING")
            + self._sort_steps(remediations, "REMEDIATION")
            + self._sort_steps(verification, "VERIFICATION")
        )
        for number, step in enumerate(ordered, start=1):
            step["step_no"] = number
        self._validate_steps(status, ordered)
        return AuditResult(case_id, status, tuple(ordered))

    @staticmethod
    def _validate_steps(status: str, steps: Sequence[Mapping[str, object]]) -> None:
        if status == "NOT_APPLICABLE":
            if steps:
                raise ValueError("NOT_APPLICABLE results must not contain steps")
            return
        for number, step in enumerate(steps, start=1):
            if tuple(step.keys()) != STEP_FIELDS:
                raise ValueError("Step schema does not match the output contract")
            if step["step_no"] != number:
                raise ValueError("Step numbers must be consecutive")
            if status == "INCOMPLETE" and step["phase"] != "FINDING" and step["evidence_id"]:
                raise ValueError("Future remediation and verification require empty evidence_id")
            if status == "COMPLETE" and step["phase"] != "VERIFICATION":
                raise ValueError("Complete results may contain verification only")


def read_requests(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as request_file:
        return sorted(csv.DictReader(request_file), key=lambda row: row["case_id"])


def write_output(results: Iterable[AuditResult], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(
            output_file, fieldnames=["case_id", "deletion_status", "steps_json"]
        )
        writer.writeheader()
        for result in sorted(results, key=lambda value: value.case_id):
            writer.writerow(
                {
                    "case_id": result.case_id,
                    "deletion_status": result.deletion_status,
                    "steps_json": json.dumps(result.steps, separators=(",", ":")),
                }
            )


def build_engine(dataset_dir: Path) -> AuditEngine:
    return AuditEngine(IdentityResolver(str(dataset_dir)), EvidenceIndexer(str(dataset_dir)))


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Audit deletion requests from participant evidence.")
    parser.add_argument(
        "--requests",
        type=Path,
        default=repo_root / "dataset" / "deletion_requests.csv",
        help="CSV request input (default: evaluation requests)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=repo_root / "output.csv",
        help="destination CSV (default: repository output.csv)",
    )
    args = parser.parse_args()
    engine = build_engine(repo_root / "dataset")
    write_output((engine.audit(row) for row in read_requests(args.requests)), args.output)


if __name__ == "__main__":
    main()
