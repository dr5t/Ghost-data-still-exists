"""Focused contract and regression tests for the Stage 3 audit orchestrator."""

import csv
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from evidence import EvidenceItem
from audit import AuditEngine, AuditResult, write_output, sort_steps
from identity import UserIdentityGraph


class _Graph:
    def __init__(self, user_id="user_01", emails=None, phones=None, email_hashes=None):
        self.user_id = user_id
        self.emails = emails or {"person@example.test"}
        self.phones = phones or set()
        self.email_hashes = email_hashes or set()


class _Resolver:
    def __init__(self, graph=_Graph()):
        self.graph = graph

    def resolve_by_email(self, _email):
        return self.graph

    def resolve(self, _email):
        return self.graph


class _Evidence:
    def __init__(self, items):
        self.items = items

    def get_evidence_for_case(self, _graph, audit_at):
        return [item for item in self.items if item.captured_at <= audit_at]


def _item(resource, category, state, evidence_id="evidence_01", captured="2026-09-01T00:00:00Z", system=None):
    systems = {
        "USER_PROFILE": "account_service",
        "SEARCH_INDEX_ENTRY": "search_service",
        "ANALYTICS_PROFILE": "analytics_platform",
        "SECURITY_AUDIT_LOG": "security_service",
        "SUPPORT_MESSAGE": "support_platform",
        "SUPPORT_ATTACHMENT": "support_platform",
        "DATA_FLOW": "integration_service",
        "BACKUP_ARCHIVE": "backup_service",
        "ACCOUNT_TOMBSTONE": "identity_service",
        "USER_EXPORT": "export_service",
    }
    sys_name = system or systems.get(category, "account_service")
    return EvidenceItem(
        evidence_id=evidence_id,
        file_path="fixture",
        origin="fixture",
        captured_at=captured,
        system_id=sys_name,
        resource_id=resource,
        data_category=category,
        state=state,
        identifiers=set(),
    )


def _request(text="Please permanently delete my account.", audit_at="2026-09-15T00:00:00Z", email="person@example.test"):
    return {
        "case_id": "case_001",
        "email": email,
        "requested_at": "2026-08-15T00:00:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-09-01T00:00:00Z",
        "audit_at": audit_at,
        "request_text": text,
    }


class TestAuditEngineContract(unittest.TestCase):
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

    def test_pre_request_observation_does_not_prove_current_state(self):
        items = [
            _item(
                "account_001",
                "USER_PROFILE",
                "PRESENT",
                "evidence_stale",
                "2026-08-01T00:00:00Z",
            ),
            _item(
                "account_001",
                "USER_PROFILE",
                "ABSENT",
                "evidence_current",
                "2026-08-16T00:00:00Z",
            ),
        ]
        result = self._engine(items).audit(_request())
        self.assertEqual(result.deletion_status, "COMPLETE")
        self.assertEqual(result.steps[0]["evidence_id"], "evidence_current")

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


class TestAuditEngineScenarios(unittest.TestCase):
    """Specific scenario tests requested in Stage 3."""

    def test_replica_drift_detected_as_incomplete(self):
        """Primary marked deleted earlier, but read replica snapshot shows PRESENT -> INCOMPLETE."""
        items = [
            _item("account_001", "USER_PROFILE", "ABSENT", "evidence_primary", "2026-09-01T12:00:00Z"),
            _item("account_001", "USER_PROFILE", "PRESENT", "evidence_replica", "2026-09-02T12:00:00Z"),
        ]
        engine = AuditEngine(_Resolver(), _Evidence(items))
        result = engine.audit(_request())
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        finding_ops = [s["operation"] for s in result.steps if s["phase"] == "FINDING"]
        self.assertIn("REPORT_REMAINING_RECORD", finding_ops)

    def test_strict_audit_at_cutoff(self):
        """Evidence captured after audit_at must be strictly excluded."""
        items = [
            _item("search_001", "SEARCH_INDEX_ENTRY", "PRESENT", "evidence_prior", "2026-09-10T00:00:00Z"),
            _item("search_001", "SEARCH_INDEX_ENTRY", "ABSENT", "evidence_post", "2026-09-20T00:00:00Z"),
        ]
        # audit_at is 2026-09-15T00:00:00Z
        engine = AuditEngine(_Resolver(), _Evidence(items))
        result = engine.audit(_request(audit_at="2026-09-15T00:00:00Z"))
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        # Evidence cited must be evidence_prior, not evidence_post
        finding_step = [s for s in result.steps if s["phase"] == "FINDING"][0]
        self.assertEqual(finding_step["evidence_id"], "evidence_prior")

    def test_tombstone_exposed_pii(self):
        """An account tombstone that still exposes PII must produce REPORT_EXPOSED_PII -> REDACT_RECORD."""
        items = [
            _item("account_001", "USER_PROFILE", "ABSENT", "evidence_acc"),
            _item("tombstone_001", "ACCOUNT_TOMBSTONE", "PRESENT", "evidence_tomb", system="identity_service"),
        ]
        engine = AuditEngine(_Resolver(), _Evidence(items))
        result = engine.audit(_request())
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertEqual(result.steps[0]["operation"], "REPORT_EXPOSED_PII")
        self.assertEqual(result.steps[0]["resource_id"], "tombstone_001")
        self.assertEqual(result.steps[1]["operation"], "REDACT_RECORD")
        self.assertEqual(result.steps[1]["state"], "REDACTED")

    def test_active_sync_data_flow(self):
        """Active data flow must produce REPORT_ACTIVE_DATA_FLOW -> DISABLE_DATA_FLOW -> VERIFY_DATA_FLOW_DISABLED."""
        items = [
            _item("account_001", "USER_PROFILE", "ABSENT", "evidence_acc"),
            _item("flow_001", "DATA_FLOW", "ACTIVE", "evidence_flow"),
        ]
        engine = AuditEngine(_Resolver(), _Evidence(items))
        result = engine.audit(_request())
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        ops = [s["operation"] for s in result.steps]
        self.assertIn("REPORT_ACTIVE_DATA_FLOW", ops)
        self.assertIn("DISABLE_DATA_FLOW", ops)
        self.assertIn("VERIFY_DATA_FLOW_DISABLED", ops)

    def test_restore_risk(self):
        """Active backup archive must produce REPORT_RESTORE_RISK -> BLOCK_RESTORE -> VERIFY_RESTORE_BLOCKED."""
        items = [
            _item("account_001", "USER_PROFILE", "ABSENT", "evidence_acc"),
            _item("backup_001", "BACKUP_ARCHIVE", "ACTIVE", "evidence_bak"),
        ]
        engine = AuditEngine(_Resolver(), _Evidence(items))
        result = engine.audit(_request())
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        ops = [s["operation"] for s in result.steps]
        self.assertIn("REPORT_RESTORE_RISK", ops)
        self.assertIn("BLOCK_RESTORE", ops)
        self.assertIn("VERIFY_RESTORE_BLOCKED", ops)

    def test_deterministic_step_ordering_rule(self):
        """Steps must strictly sort: FINDING -> REMEDIATION -> VERIFICATION, then by OP order, then system_id, resource_id."""
        raw_steps = [
            {"phase": "VERIFICATION", "operation": "VERIFY_RECORD_ABSENT", "system_id": "search_service", "resource_id": "search_02", "state": "ABSENT", "evidence_id": ""},
            {"phase": "FINDING", "operation": "REPORT_REMAINING_RECORD", "system_id": "search_service", "resource_id": "search_01", "state": "PRESENT", "evidence_id": "ev_01"},
            {"phase": "REMEDIATION", "operation": "DELETE_RECORD", "system_id": "search_service", "resource_id": "search_01", "state": "ABSENT", "evidence_id": ""},
            {"phase": "FINDING", "operation": "REPORT_ACTIVE_DATA_FLOW", "system_id": "integration_service", "resource_id": "flow_01", "state": "ACTIVE", "evidence_id": "ev_02"},
            {"phase": "REMEDIATION", "operation": "DISABLE_DATA_FLOW", "system_id": "integration_service", "resource_id": "flow_01", "state": "DISABLED", "evidence_id": ""},
        ]
        sorted_steps = sort_steps(raw_steps)
        self.assertEqual([s["step_no"] for s in sorted_steps], [1, 2, 3, 4, 5])
        # Findings first: REPORT_REMAINING_RECORD before REPORT_ACTIVE_DATA_FLOW
        self.assertEqual(sorted_steps[0]["operation"], "REPORT_REMAINING_RECORD")
        self.assertEqual(sorted_steps[1]["operation"], "REPORT_ACTIVE_DATA_FLOW")
        # Remediation second: DISABLE_DATA_FLOW before DELETE_RECORD
        self.assertEqual(sorted_steps[2]["operation"], "DISABLE_DATA_FLOW")
        self.assertEqual(sorted_steps[3]["operation"], "DELETE_RECORD")
        # Verification third
        self.assertEqual(sorted_steps[4]["operation"], "VERIFY_RECORD_ABSENT")

    def test_same_resource_supersession(self):
        """Later observation of the same canonical resource supersedes an earlier violation."""
        items = [
            _item("account_001", "USER_PROFILE", "PRESENT", "evidence_01", "2026-09-01T10:00:00Z"),
            _item("account_001", "USER_PROFILE", "ABSENT", "evidence_02", "2026-09-02T10:00:00Z"),
        ]
        engine = AuditEngine(_Resolver(), _Evidence(items))
        result = engine.audit(_request())
        self.assertEqual(result.deletion_status, "COMPLETE")
        self.assertEqual(len(result.steps), 1)
        self.assertEqual(result.steps[0]["resource_id"], "account_001")
        self.assertEqual(result.steps[0]["evidence_id"], "evidence_02")

    def test_different_resource_observations_in_same_batch(self):
        """Different resources in the same service do not supersede or mask each other."""
        items = [
            _item("account_001", "USER_PROFILE", "ABSENT", "evidence_01", "2026-09-01T10:00:00Z"),
            _item("account_002", "USER_PROFILE", "PRESENT", "evidence_01", "2026-09-01T10:00:00Z"),
        ]
        engine = AuditEngine(_Resolver(), _Evidence(items))
        result = engine.audit(_request())
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        finding_resources = [s["resource_id"] for s in result.steps if s["phase"] == "FINDING"]
        self.assertIn("account_002", finding_resources)

    def test_conflicting_observations_replication_drift(self):
        """Earlier compliant state followed by later violation proves replication drift / non-compliance."""
        items = [
            _item("account_001", "USER_PROFILE", "ABSENT", "evidence_01", "2026-09-01T10:00:00Z"),
            _item("account_001", "USER_PROFILE", "PRESENT", "evidence_02", "2026-09-03T10:00:00Z"),
        ]
        engine = AuditEngine(_Resolver(), _Evidence(items))
        result = engine.audit(_request())
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertEqual(result.steps[0]["operation"], "REPORT_REMAINING_RECORD")
        self.assertEqual(result.steps[0]["evidence_id"], "evidence_02")

    def test_evidence_beyond_audit_cutoff_excluded(self):
        """Observations captured after audit_at must never be used to establish pre-cutoff findings or state."""
        items = [
            _item("account_001", "USER_PROFILE", "PRESENT", "evidence_01", "2026-09-10T10:00:00Z"),
            _item("account_001", "USER_PROFILE", "ABSENT", "evidence_post", "2026-09-20T10:00:00Z"),
        ]
        # audit_at is 2026-09-15
        engine = AuditEngine(_Resolver(), _Evidence(items))
        result = engine.audit(_request(audit_at="2026-09-15T00:00:00Z"))
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertEqual(result.steps[0]["evidence_id"], "evidence_01")

    def test_missing_or_ambiguous_identity_linkage(self):
        """Unresolved identity returns INCOMPLETE without fabricating ungrounded claims."""
        engine = AuditEngine(_Resolver(graph=None), _Evidence([]))
        result = engine.audit(_request())
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertEqual(result.steps, ())

    def test_pre_request_tombstone_excluded_from_verification(self):
        """Pre-request compliant tombstone is excluded and not cited as proof of a later deletion request."""
        items = [
            _item("tombstone_001", "ACCOUNT_TOMBSTONE", "REDACTED", "evidence_pre", "2026-03-01T00:00:00Z", system="identity_service"),
        ]
        # requested_at is 2026-08-15
        engine = AuditEngine(_Resolver(), _Evidence(items))
        result = engine.audit(_request())
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertEqual(len(result.steps), 0)

    def test_post_request_tombstone_included_in_verification(self):
        """Post-request tombstone properly redacted is included as proof of compliant tombstone preservation."""
        items = [
            _item("account_001", "USER_PROFILE", "ABSENT", "evidence_01", "2026-08-20T00:00:00Z"),
            _item("tombstone_001", "ACCOUNT_TOMBSTONE", "REDACTED", "evidence_02", "2026-08-20T00:00:00Z", system="identity_service"),
        ]
        # requested_at is 2026-08-15
        engine = AuditEngine(_Resolver(), _Evidence(items))
        result = engine.audit(_request())
        self.assertEqual(result.deletion_status, "COMPLETE")
        tomb_steps = [s for s in result.steps if s["resource_id"] == "tombstone_001"]
        self.assertEqual(len(tomb_steps), 1)
        self.assertEqual(tomb_steps[0]["operation"], "VERIFY_RECORD_REDACTED")
        self.assertEqual(tomb_steps[0]["evidence_id"], "evidence_02")

    def test_pre_request_exposed_tombstone_retained_as_violation(self):
        """Pre-request tombstone that exposes PII remains an active violation until fixed."""
        items = [
            _item("tombstone_001", "ACCOUNT_TOMBSTONE", "PRESENT", "evidence_pre", "2026-03-01T00:00:00Z", system="identity_service"),
        ]
        engine = AuditEngine(_Resolver(), _Evidence(items))
        result = engine.audit(_request())
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertEqual(result.steps[0]["operation"], "REPORT_EXPOSED_PII")
        self.assertEqual(result.steps[0]["resource_id"], "tombstone_001")

    def test_unrelated_batch_activity_not_assigned_as_user_account(self):
        """Unrelated accounts in concurrent activity batches must never be assigned to a requester."""
        items = [
            _item("backup_4978", "BACKUP_ARCHIVE", "ACTIVE", "evidence_93", "2026-09-16T08:37:39Z"),
        ]
        graph = _Graph(user_id="user_61", emails={"k.appiah88@gmail.com"})
        engine = AuditEngine(_Resolver(graph=graph), _Evidence(items))
        # Provide unrelated activity in batch window
        engine.system_activities = [
            {
                "activity_id": "activity_3657",
                "event_time": "2026-09-05T10:50:10Z",
                "event_type": "DELETE_RECORD",
                "source_system": "deletion_worker",
                "target_system": "account_service",
                "resource_id": "account_294",
                "reported_result": "PARTIAL",
                "details": "Deletion worker submitted primary profile account_294 to account_service."
            }
        ]
        req = {
            "case_id": "case_09",
            "email": "k.appiah88@gmail.com",
            "requested_at": "2026-09-05T09:00:00Z",
            "reported_status": "NOT_STARTED",
            "reported_at": "2026-09-07T09:00:00Z",
            "audit_at": "2026-09-16T09:00:00Z",
            "request_text": "Please delete my account.",
        }
        result = engine.audit(req)
        # account_294 must NOT be assigned as a verified step
        step_resources = [s["resource_id"] for s in result.steps]
        self.assertNotIn("account_294", step_resources)

    def test_ungrounded_user_number_account_not_synthesized(self):
        """Account IDs must not be guessed or synthesized from user ID numbers without evidence."""
        items = [
            _item("tombstone_001", "ACCOUNT_TOMBSTONE", "REDACTED", "evidence_tomb", "2026-09-01T00:00:00Z", system="identity_service"),
        ]
        graph = _Graph(user_id="user_05", emails={"leila.haddad@yahoo.com"})
        engine = AuditEngine(_Resolver(graph=graph), _Evidence(items))
        req = {
            "case_id": "case_05",
            "email": "leila.haddad@yahoo.com",
            "requested_at": "2026-09-01T00:00:00Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-09-02T00:00:00Z",
            "audit_at": "2026-09-03T00:00:00Z",
            "request_text": "Please delete my account and personal data.",
        }
        result = engine.audit(req)
        step_resources = [s["resource_id"] for s in result.steps]
        # account_005 must not be synthesized if not in evidence
        self.assertNotIn("account_005", step_resources)

    def test_audit_cutoff_enforcement_ignores_post_cutoff_evidence(self):
        """Evidence captured strictly after audit_at must never establish state at audit_at."""
        items = [
            # Pre-cutoff violation
            _item("profile_rec_1", "USER_PROFILE", "PRESENT", "evidence_pre", "2026-09-10T00:00:00Z", system="account_service"),
            # Post-cutoff record claiming deletion or compliance
            _item("profile_rec_1", "USER_PROFILE", "ABSENT", "evidence_post", "2026-09-20T00:00:00Z", system="account_service"),
        ]
        graph = _Graph(user_id="user_10", emails={"test@example.org"})
        engine = AuditEngine(_Resolver(graph=graph), _Evidence(items))
        req = {
            "case_id": "case_test_cutoff",
            "email": "test@example.org",
            "requested_at": "2026-09-05T00:00:00Z",
            "reported_status": "PARTIALLY_COMPLETE",
            "reported_at": "2026-09-12T00:00:00Z",
            "audit_at": "2026-09-15T00:00:00Z",
            "request_text": "I request complete deletion of my account.",
        }
        result = engine.audit(req)
        # At audit_at (2026-09-15), evidence_post has not occurred yet; state is INCOMPLETE due to evidence_pre
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        finding_ev_ids = [s["evidence_id"] for s in result.steps if s["phase"] == "FINDING"]
        self.assertIn("evidence_pre", finding_ev_ids)
        self.assertNotIn("evidence_post", finding_ev_ids)

    def test_anonymized_analytics_without_linkage_not_attributed(self):
        """Analytics profiles stripped of user identifiers must not be attributed to requester."""
        from evidence import EvidenceIndexer
        indexer = EvidenceIndexer("dataset")
        graph = _Graph(user_id="user_20", emails={"mariam.al-mansoori@gmail.com"})
        items = indexer.get_evidence_for_case(graph, "2026-09-15T00:00:00Z")
        # Ensure that decoupled analytics records (e.g. analytics_9406) without identifiers are not linked
        linked_resources = {it.resource_id for it in items}
        self.assertNotIn("analytics_9406", linked_resources)

    def test_pdf_evidence_indexing_extracts_records(self):
        """PDF evidence files (e.g. evidence_55 and evidence_58) must be properly parsed and indexed."""
        from evidence import EvidenceIndexer
        indexer = EvidenceIndexer("dataset")
        ev55_items = [it for it in indexer.items if it.evidence_id == "evidence_55"]
        self.assertTrue(len(ev55_items) >= 1)
        self.assertEqual(ev55_items[0].resource_id, "audit_record_003")
        self.assertIn("user_03", ev55_items[0].identifiers)

        ev58_items = [it for it in indexer.items if it.evidence_id == "evidence_58"]
        self.assertTrue(len(ev58_items) >= 1)
        self.assertEqual(ev58_items[0].resource_id, "support_001")
        self.assertIn("priya.raman@gmail.com", ev58_items[0].identifiers)

    def test_escaped_quote_log_parsing_extracts_clean_identifiers(self):
        """Log records with embedded escaped quotes must be cleaned to match user tokens."""
        from evidence import EvidenceIndexer
        indexer = EvidenceIndexer("dataset")
        # Check that audit_record_6863 in evidence_25 was stripped of backslashes and quotes
        matched = [it for it in indexer.items if it.resource_id == "audit_record_6863"]
        self.assertTrue(len(matched) >= 1)
        self.assertEqual(matched[0].resource_id, "audit_record_6863")
        self.assertIn("user_261", matched[0].identifiers)
        # Ensure that no indexed items contain escaped backslashes in resource_id or identifiers
        for it in indexer.items:
            self.assertNotIn('\\"', it.resource_id)
            for ident in it.identifiers:
                self.assertNotIn('\\"', ident)


if __name__ == "__main__":
    unittest.main()

