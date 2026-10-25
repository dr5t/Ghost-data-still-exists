"""Focused contract tests for the Stage 3 audit orchestrator."""

import csv
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from evidence import EvidenceItem
from main import AuditEngine, AuditResult, write_output


class _Graph:
    pass


class _Resolver:
    def __init__(self, graph=_Graph()):
        self.graph = graph

    def resolve_by_email(self, _email):
        return self.graph


class _Evidence:
    def __init__(self, items):
        self.items = items

    def get_evidence_for_case(self, _graph, audit_at):
        return [item for item in self.items if item.captured_at <= audit_at]


def _item(resource, category, state, evidence_id="evidence_01", captured="2026-09-01T00:00:00Z"):
    systems = {
        "USER_PROFILE": "account_service",
        "SEARCH_INDEX_ENTRY": "search_service",
        "ANALYTICS_PROFILE": "analytics_platform",
        "SECURITY_AUDIT_LOG": "security_service",
        "SUPPORT_MESSAGE": "support_platform",
        "DATA_FLOW": "integration_service",
        "BACKUP_ARCHIVE": "backup_service",
    }
    return EvidenceItem(
        evidence_id=evidence_id,
        file_path="fixture",
        origin="fixture",
        captured_at=captured,
        system_id=systems[category],
        resource_id=resource,
        data_category=category,
        state=state,
        identifiers=set(),
    )


def _request(text="Please permanently delete my account."):
    return {
        "case_id": "case_001",
        "email": "person@example.test",
        "audit_at": "2026-09-15T00:00:00Z",
        "request_text": text,
    }


class TestAuditEngine(unittest.TestCase):
    def _engine(self, items, resolver=None):
        return AuditEngine(resolver or _Resolver(), _Evidence(items))

    def test_non_deletion_request_has_no_steps(self):
        result = self._engine([]).audit(_request("Please send an export; do not delete my account."))
        self.assertEqual(result.deletion_status, "NOT_APPLICABLE")
        self.assertEqual(result.steps, ())

    def test_missing_evidence_is_not_proof_of_completion(self):
        result = self._engine([]).audit(_request())
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertEqual(result.steps, ())

    def test_complete_uses_only_evidence_backed_verification(self):
        items = [
            _item("account_001", "USER_PROFILE", "ABSENT", "evidence_05"),
            _item("audit_001", "SECURITY_AUDIT_LOG", "PRESENT", "evidence_06"),
            _item("analytics_001", "ANALYTICS_PROFILE", "ANONYMIZED", "evidence_07"),
        ]
        result = self._engine(items).audit(_request())
        self.assertEqual(result.deletion_status, "COMPLETE")
        self.assertEqual(
            [(step["operation"], step["evidence_id"]) for step in result.steps],
            [
                ("VERIFY_RECORD_ABSENT", "evidence_05"),
                ("VERIFY_RECORD_PRESENT", "evidence_06"),
                ("VERIFY_RECORD_ANONYMIZED", "evidence_07"),
            ],
        )

    def test_incomplete_orders_flow_before_dependent_records(self):
        items = [
            _item("account_001", "USER_PROFILE", "ABSENT"),
            _item("audit_001", "SECURITY_AUDIT_LOG", "PRESENT"),
            _item("search_001", "SEARCH_INDEX_ENTRY", "PRESENT", "evidence_08"),
            _item("support_001", "SUPPORT_MESSAGE", "PRESENT", "evidence_08"),
            _item("analytics_001", "ANALYTICS_PROFILE", "PRESENT", "evidence_08"),
            _item("flow_001", "DATA_FLOW", "ACTIVE", "evidence_08"),
            _item("backup_001", "BACKUP_ARCHIVE", "ACTIVE", "evidence_08"),
        ]
        result = self._engine(items).audit(_request())
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertEqual(
            [step["operation"] for step in result.steps],
            [
                "REPORT_REMAINING_RECORD",
                "REPORT_EXPOSED_PII",
                "REPORT_EXPOSED_PII",
                "REPORT_ACTIVE_DATA_FLOW",
                "REPORT_RESTORE_RISK",
                "DISABLE_DATA_FLOW",
                "BLOCK_RESTORE",
                "DELETE_RECORD",
                "REDACT_RECORD",
                "ANONYMIZE_RECORD",
                "VERIFY_RECORD_ABSENT",
                "VERIFY_RECORD_ABSENT",
                "VERIFY_RECORD_PRESENT",
                "VERIFY_RECORD_REDACTED",
                "VERIFY_RECORD_ANONYMIZED",
                "VERIFY_DATA_FLOW_DISABLED",
                "VERIFY_RESTORE_BLOCKED",
            ],
        )
        self.assertTrue(all(step["evidence_id"] == "" for step in result.steps[5:]))
        self.assertEqual([step["step_no"] for step in result.steps], list(range(1, 18)))

    def test_later_observation_supersedes_stale_violation(self):
        items = [
            _item("search_001", "SEARCH_INDEX_ENTRY", "PRESENT", "evidence_01"),
            _item(
                "search_001",
                "SEARCH_INDEX_ENTRY",
                "ABSENT",
                "evidence_02",
                "2026-09-02T00:00:00Z",
            ),
        ]
        result = self._engine(items).audit(_request())
        self.assertEqual(result.deletion_status, "COMPLETE")
        self.assertEqual(result.steps[0]["evidence_id"], "evidence_02")

    def test_unknown_identity_cannot_be_complete(self):
        result = self._engine([], _Resolver(graph=None)).audit(_request())
        self.assertEqual(result.deletion_status, "INCOMPLETE")

    def test_csv_serialization_is_sorted_and_valid_json(self):
        first = AuditResult("case_010", "NOT_APPLICABLE", ())
        second = AuditResult("case_002", "COMPLETE", ())
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output.csv"
            write_output([first, second], output)
            with output.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
        self.assertEqual([row["case_id"] for row in rows], ["case_002", "case_010"])
        self.assertEqual([json.loads(row["steps_json"]) for row in rows], [[], []])


if __name__ == "__main__":
    unittest.main()
