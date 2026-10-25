"""Sample output comparison and evaluation diagnostics."""

import csv
import json
from pathlib import Path


def run_comparison(repo_root: Path):
    sample_requests_path = repo_root / "dataset" / "sample_deletion_requests.csv"
    expected_output_path = repo_root / "dataset" / "sample_output.csv"
    actual_output_path = Path("/tmp/sample_output.csv")

    with expected_output_path.open("r", encoding="utf-8") as f:
        expected = {r["case_id"]: r for r in csv.DictReader(f)}

    with actual_output_path.open("r", encoding="utf-8") as f:
        actual = {r["case_id"]: r for r in csv.DictReader(f)}

    status_matches = 0
    exact_row_matches = 0
    steps_json_matches = 0
    structural_matches = 0

    mismatches = []

    for cid, exp in sorted(expected.items()):
        act = actual.get(cid, {})

        st_match = exp["deletion_status"] == act.get("deletion_status")
        if st_match:
            status_matches += 1

        exp_steps = json.loads(exp["steps_json"])
        act_steps = json.loads(act.get("steps_json", "[]"))

        json_match = exp_steps == act_steps
        if json_match:
            steps_json_matches += 1

        if exp == act:
            exact_row_matches += 1

        exp_struct = [
            (s.get("phase"), s.get("operation"), s.get("system_id"), s.get("resource_id"))
            for s in exp_steps
        ]
        act_struct = [
            (s.get("phase"), s.get("operation"), s.get("system_id"), s.get("resource_id"))
            for s in act_steps
        ]

        struct_match = exp_struct == act_struct
        if struct_match:
            structural_matches += 1

        if not json_match or not st_match:
            mismatches.append({
                "case_id": cid,
                "exp_status": exp["deletion_status"],
                "act_status": act.get("deletion_status"),
                "exp_steps": exp_steps,
                "act_steps": act_steps,
            })

    total = len(expected)
    print("=== SAMPLE COMPARATOR RESULTS ===")
    print(f"Total Cases: {total}")
    print(f"Status Agreement: {status_matches}/{total} ({status_matches/total*100:.1f}%)")
    print(f"Exact Row Agreement: {exact_row_matches}/{total} ({exact_row_matches/total*100:.1f}%)")
    print(f"Parsed steps_json Agreement: {steps_json_matches}/{total} ({steps_json_matches/total*100:.1f}%)")
    print(f"Structural Step Agreement: {structural_matches}/{total} ({structural_matches/total*100:.1f}%)")
    print(f"Remaining Mismatches: {len(mismatches)}")
    print("\n=== MISMATCH BREAKDOWN ===")
    for m in mismatches:
        cid = m["case_id"]
        exp_st = m["exp_status"]
        act_st = m["act_status"]
        exp_n = len(m["exp_steps"])
        act_n = len(m["act_steps"])
        exp_res = set(s.get("resource_id") for s in m["exp_steps"])
        act_res = set(s.get("resource_id") for s in m["act_steps"])
        diff_missing = sorted(list(exp_res - act_res))
        diff_extra = sorted(list(act_res - exp_res))
        print(f"Case {cid}: status exp={exp_st}, act={act_st}; exp_steps={exp_n}, act_steps={act_n}")
        if diff_missing:
            print(f"   Missing resources in actual: {diff_missing}")
        if diff_extra:
            print(f"   Extra resources in actual: {diff_extra}")


if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parents[2]
    run_comparison(repo_root)
