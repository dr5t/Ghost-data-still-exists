"""Strict validation script for output.csv conforming to AGENTS.md contract."""

import csv
import json
import sys
from pathlib import Path


def validate_output(output_csv: Path, requests_csv: Path) -> dict:
    with requests_csv.open(encoding="utf-8") as f:
        expected_case_ids = [r["case_id"] for r in csv.DictReader(f)]

    with output_csv.open(encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = list(reader)

    print(f"Header: {header}")
    assert header == ["case_id", "deletion_status", "steps_json"], f"Header mismatch: {header}"
    print(f"Total rows: {len(rows)}")
    assert len(rows) == len(expected_case_ids), f"Expected {len(expected_case_ids)} rows, got {len(rows)}"

    case_ids = [r[0] for r in rows]
    assert case_ids == sorted(case_ids), "Rows are not sorted by case_id"
    assert case_ids == sorted(expected_case_ids), "Case IDs do not match requests CSV"

    allowed_phases = ("FINDING", "REMEDIATION", "VERIFICATION")
    phase_order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}

    allowed_ops = {
        "FINDING": {
            "REPORT_REMAINING_RECORD": "PRESENT",
            "REPORT_EXPOSED_PII": "PRESENT",
            "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
            "REPORT_RESTORE_RISK": "ACTIVE",
        },
        "REMEDIATION": {
            "DISABLE_DATA_FLOW": "DISABLED",
            "BLOCK_RESTORE": "BLOCKED",
            "DELETE_RECORD": "ABSENT",
            "REDACT_RECORD": "REDACTED",
            "ANONYMIZE_RECORD": "ANONYMIZED",
        },
        "VERIFICATION": {
            "VERIFY_RECORD_ABSENT": "ABSENT",
            "VERIFY_RECORD_PRESENT": "PRESENT",
            "VERIFY_RECORD_REDACTED": "REDACTED",
            "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
            "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
            "VERIFY_RESTORE_BLOCKED": "BLOCKED",
        },
    }

    status_counts = {}
    total_steps = 0

    for i, row in enumerate(rows):
        cid, status, steps_raw = row
        status_counts[status] = status_counts.get(status, 0) + 1
        assert status in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"), f"Invalid status: {status} at row {i}"

        steps = json.loads(steps_raw)
        assert isinstance(steps, list), f"steps_json is not an array at {cid}"
        total_steps += len(steps)

        if status == "NOT_APPLICABLE":
            assert len(steps) == 0, f"NOT_APPLICABLE has non-empty steps at {cid}: {steps}"
            continue

        current_phase_idx = 0
        for s_idx, s in enumerate(steps):
            step_no = s.get("step_no")
            expected_step_no = s_idx + 1
            assert step_no == expected_step_no, f"Step numbering error in {cid}: {step_no} != {expected_step_no}"

            phase = s.get("phase")
            assert phase in allowed_phases, f"Invalid phase {phase} in {cid}"
            phase_idx = phase_order[phase]
            assert phase_idx >= current_phase_idx, f"Phase out of order in {cid}: {phase} after {current_phase_idx}"
            current_phase_idx = phase_idx

            op = s.get("operation")
            st = s.get("state")
            assert op in allowed_ops[phase], f"Operation {op} not allowed in phase {phase} in {cid}"
            expected_state = allowed_ops[phase][op]
            assert st == expected_state, f"State {st} != {expected_state} for op {op} in {cid}"

            ev_id = s.get("evidence_id", "")
            if phase == "FINDING":
                assert ev_id != "", f"FINDING step in {cid} missing evidence_id"
            elif status == "COMPLETE":
                assert phase == "VERIFICATION", f"COMPLETE case {cid} has non-VERIFICATION step: {phase}"
                assert ev_id != "", f"COMPLETE case {cid} VERIFICATION step missing evidence_id"
            else:
                # INCOMPLETE remediation or post-remediation verification
                assert ev_id == "", f"INCOMPLETE step {expected_step_no} in {cid} has non-empty evidence_id: {ev_id}"

    print("All validations PASSED successfully!")
    print(f"Status distribution: {status_counts}")
    print(f"Total steps across all cases: {total_steps}")
    return {
        "status_counts": status_counts,
        "total_rows": len(rows),
        "total_steps": total_steps,
    }


if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parents[2]
    out_csv = repo_root / "output.csv"
    req_csv = repo_root / "dataset" / "deletion_requests.csv"
    if len(sys.argv) > 1:
        out_csv = Path(sys.argv[1])
    if len(sys.argv) > 2:
        req_csv = Path(sys.argv[2])
    validate_output(out_csv, req_csv)
