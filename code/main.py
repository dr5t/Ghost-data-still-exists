"""Deterministic deletion-audit runner and CSV serialization.

HackerRank Orchestrate — Ghost Data Still Exists
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, Iterable, List

from audit import AuditEngine, AuditResult, write_output


def read_requests(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as request_file:
        return sorted(csv.DictReader(request_file), key=lambda row: row["case_id"])


def build_engine(dataset_dir: Path) -> AuditEngine:
    return AuditEngine(dataset_dir=str(dataset_dir))


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
