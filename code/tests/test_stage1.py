"""
Focused tests for Stage 1: Identity resolution, evidence ingestion, and temporal filtering.
"""

import os
import sys
import unittest

# Ensure code directory is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from identity import IdentityResolver
from evidence import EvidenceIndexer


class TestStage1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resolver = IdentityResolver(dataset_dir="dataset")
        cls.indexer = EvidenceIndexer(dataset_dir="dataset")

    def test_identity_resolution_current_email(self):
        """Test direct match on current email."""
        graph = self.resolver.resolve_by_email("amina.elmasri@gmail.com")
        self.assertIsNotNone(graph)
        self.assertEqual(graph.user_id, "user_01")
        self.assertEqual(graph.current_email, "amina.elmasri@gmail.com")
        self.assertTrue(graph.matches_any("amina.elmasri@gmail.com"))

    def test_identity_resolution_historical_email(self):
        """Test match on historical email from user_audit_log.csv."""
        # Case 10: nadia.ionescu@yahoo.com changed email
        graph = self.resolver.resolve_by_email("nadia.ionescu@yahoo.com")
        self.assertIsNotNone(graph)
        self.assertIn("nadia.ionescu@yahoo.com", graph.emails)

    def test_identity_resolution_case_insensitivity(self):
        """Test uppercase/mixed case email resolution."""
        graph = self.resolver.resolve_by_email("SIPHO.MOKOENA@GMAIL.COM")
        self.assertIsNotNone(graph)
        self.assertEqual(graph.user_id, "user_36")

    def test_all_sample_requests_resolve(self):
        """Test that all 32 sample requests resolve to a user identity."""
        import csv
        with open("dataset/sample_deletion_requests.csv", "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cid = row["case_id"]
                email = row["email"]
                graph = self.resolver.resolve_by_email(email)
                self.assertIsNotNone(graph, f"Failed to resolve {cid} ({email})")

    def test_evidence_temporal_cutoff(self):
        """Test that evidence captured after audit_at is strictly excluded."""
        graph = self.resolver.resolve_by_email("amina.elmasri@gmail.com")
        # Early audit_at cutoff before evidence_54 was captured (2026-09-02T23:00:00Z)
        early_cutoff = "2026-09-01T00:00:00Z"
        items_early = self.indexer.get_evidence_for_case(graph, early_cutoff)
        for item in items_early:
            self.assertLessEqual(item.captured_at, early_cutoff)
            self.assertNotEqual(item.evidence_id, "evidence_54")

    def test_evidence_retrieval_case_03(self):
        """Test retrieval of evidence_94 for case_03 (l.fontaine46@yahoo.com)."""
        graph = self.resolver.resolve_by_email("l.fontaine46@yahoo.com")
        audit_at = "2026-09-26T11:00:00Z"
        items = self.indexer.get_evidence_for_case(graph, audit_at)
        ev_ids = {it.evidence_id for it in items}
        res_ids = {it.resource_id for it in items}

        self.assertIn("evidence_94", ev_ids)
        self.assertIn("account_7566", res_ids)
        self.assertIn("audit_record_2016", res_ids)

    def test_evidence_retrieval_case_07_pdf(self):
        """Test retrieval of PDF attachment evidence_58 for case_07 (priya.raman@gmail.com)."""
        graph = self.resolver.resolve_by_email("priya.raman@gmail.com")
        audit_at = "2026-09-12T08:00:00Z"
        items = self.indexer.get_evidence_for_case(graph, audit_at)
        res_ids = {it.resource_id for it in items}
        self.assertIn("support_001", res_ids)

    def test_evidence_retrieval_case_11_handover(self):
        """Test retrieval of handover report evidence_03 for case_11."""
        graph = self.resolver.resolve_by_email("novak.tomasz@icloud.com")
        audit_at = "2026-10-01T12:00:00Z"
        items = self.indexer.get_evidence_for_case(graph, audit_at)
        res_ids = {it.resource_id for it in items}
        self.assertIn("search_052", res_ids)
        self.assertIn("analytics_2034", res_ids)
        self.assertIn("support_864", res_ids)
        self.assertIn("data_flow_9522", res_ids)

    def test_evidence_retrieval_case_31_tombstone(self):
        """Test retrieval of tombstone evidence_51 for case_31."""
        graph = self.resolver.resolve_by_email("a.eze08@gmail.com")
        audit_at = "2026-09-15T12:00:00Z"
        items = self.indexer.get_evidence_for_case(graph, audit_at)
        res_ids = {it.resource_id for it in items}
        self.assertIn("tombstone_440", res_ids)
        self.assertIn("audit_record_6909", res_ids)

    def test_legacy_contact_index_is_a_secondary_identifier(self):
        """A contact-index trace is deleted rather than treated as a support chat."""
        items = self.indexer.items_by_resource["support_002"]
        self.assertTrue(
            any(
                item.evidence_id == "evidence_61"
                and item.data_category == "SECONDARY_IDENTIFIER"
                for item in items
            )
        )

    def test_marketing_consent_trace_is_not_an_analytics_profile(self):
        """Explicit email_opt_in provenance selects the marketing deletion rule."""
        items = self.indexer.items_by_resource["analytics_9914"]
        self.assertTrue(
            any(
                item.evidence_id == "evidence_01"
                and item.data_category == "MARKETING_PROFILE"
                for item in items
            )
        )

    def test_evidence_retrieval_case_34_image(self):
        """Test retrieval of image fact evidence_04 for case_34 (haruka.s1838@zoho.com)."""
        graph = self.resolver.resolve_by_email("haruka.s1838@zoho.com")
        audit_at = "2026-09-27T13:00:00Z"
        items = self.indexer.get_evidence_for_case(graph, audit_at)
        res_ids = {it.resource_id for it in items}
        self.assertIn("account_5762", res_ids)

    def test_all_518_eval_requests_resolve(self):
        """Test that all 518 evaluation requests resolve to a canonical user identity."""
        import csv
        with open("dataset/deletion_requests.csv", "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                count += 1
                email = row["email"]
                graph = self.resolver.resolve_by_email(email)
                self.assertIsNotNone(graph, f"Failed to resolve {row['case_id']} ({email})")
            self.assertEqual(count, 518)


if __name__ == "__main__":
    unittest.main()
