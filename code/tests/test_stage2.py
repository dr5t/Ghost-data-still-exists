"""
Tests for Stage 2: Intent classification and deletion policy engine.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

from intent import classify_intent
from policy import (
    RULES,
    get_required_action,
    compliant_state,
    is_violation,
    finding_operation,
    remediation_operation,
    verification_operation,
)


class TestIntentClassification(unittest.TestCase):

    # ── Positive deletion intents ──────────────────────────────────

    def test_english_delete(self):
        intent, _ = classify_intent(
            "Hi, I haven't used this account in years and would like it closed. "
            "Please remove the profile and the personal details attached to it."
        )
        self.assertEqual(intent, "DELETION")

    def test_spanish_delete(self):
        intent, _ = classify_intent(
            "Intenté eliminar mi cuenta ayer, pero la página terminó mostrando un error."
        )
        self.assertEqual(intent, "DELETION")

    def test_french_delete(self):
        intent, _ = classify_intent(
            "Je demande la suppression définitive du compte associé à cette adresse e-mail."
        )
        self.assertEqual(intent, "DELETION")

    def test_portuguese_delete(self):
        intent, _ = classify_intent(
            "Solicito a exclusão permanente da conta associada a este e-mail."
        )
        self.assertEqual(intent, "DELETION")

    def test_german_delete(self):
        intent, _ = classify_intent(
            "Ich möchte mein Konto und alle damit verbundenen persönlichen Daten löschen."
        )
        self.assertEqual(intent, "DELETION")

    def test_japanese_delete(self):
        intent, _ = classify_intent(
            "このメールアドレスに関連付けられたアカウントの削除をお願いします。"
        )
        self.assertEqual(intent, "DELETION")

    def test_korean_delete(self):
        intent, _ = classify_intent(
            "이 이메일 주소와 연결된 계정의 삭제를 요청합니다."
        )
        self.assertEqual(intent, "DELETION")

    def test_close_account_english(self):
        intent, _ = classify_intent(
            "Please close my account and process the associated personal-data deletion."
        )
        self.assertEqual(intent, "DELETION")

    def test_erase_english(self):
        intent, _ = classify_intent(
            "I would like the account associated with this address to be erased."
        )
        self.assertEqual(intent, "DELETION")

    # ── Negative / non-deletion intents ────────────────────────────

    def test_download_export(self):
        intent, _ = classify_intent(
            "I'd like to download my account information in a portable format. "
            "Please keep the account as it is."
        )
        self.assertEqual(intent, "NOT_APPLICABLE")

    def test_login_reset(self):
        intent, _ = classify_intent(
            "I can't access my profile and need help resetting the login. "
            "Do not close the account."
        )
        self.assertEqual(intent, "NOT_APPLICABLE")

    def test_name_correction(self):
        intent, _ = classify_intent(
            "My surname is misspelled on the account. "
            "Can you correct it without removing any of my records?"
        )
        self.assertEqual(intent, "NOT_APPLICABLE")

    def test_marketing_optout(self):
        intent, _ = classify_intent(
            "Please remove me from marketing lists only. "
            "I still want receipts and service messages for this account."
        )
        self.assertEqual(intent, "NOT_APPLICABLE")

    def test_data_access_request(self):
        intent, _ = classify_intent(
            "Can you tell me what personal information you hold about me? "
            "This is an information request, not a request to erase it."
        )
        self.assertEqual(intent, "NOT_APPLICABLE")

    def test_copy_request(self):
        intent, _ = classify_intent(
            "I need a copy of last year's invoices for my records. "
            "Please leave my profile and purchase history in place."
        )
        self.assertEqual(intent, "NOT_APPLICABLE")

    def test_email_change(self):
        intent, _ = classify_intent(
            "Please change the email address used for this account. "
            "I want to continue using the service."
        )
        self.assertEqual(intent, "NOT_APPLICABLE")

    def test_promo_stop(self):
        intent, _ = classify_intent(
            "Please stop the promotional emails. I still need the account "
            "and my order history, so I am not asking for deletion."
        )
        self.assertEqual(intent, "NOT_APPLICABLE")

    def test_phone_update(self):
        intent, _ = classify_intent(
            "The mobile number on my profile is out of date. "
            "Please replace it with the new one and leave the account active."
        )
        self.assertEqual(intent, "NOT_APPLICABLE")

    def test_copy_no_change(self):
        intent, _ = classify_intent(
            "Could you send me a copy of the information held on my account? "
            "I still use it, so please don't delete or change anything."
        )
        self.assertEqual(intent, "NOT_APPLICABLE")

    def test_empty(self):
        intent, _ = classify_intent("")
        self.assertEqual(intent, "NOT_APPLICABLE")

    # ── Full-dataset sanity: no crash and all intents are valid ────

    def test_all_518_classify(self):
        """Every request in deletion_requests.csv must classify without error."""
        import csv
        valid_intents = {"DELETION", "NOT_APPLICABLE"}
        with open(os.path.join(REPO_ROOT, "dataset/deletion_requests.csv"), "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                intent, reason = classify_intent(row["request_text"])
                self.assertIn(
                    intent, valid_intents,
                    f"{row['case_id']}: invalid intent '{intent}'"
                )

    def test_non_deletion_count(self):
        """Exactly 10 of the 518 cases should be NOT_APPLICABLE."""
        import csv
        na_count = 0
        with open(os.path.join(REPO_ROOT, "dataset/deletion_requests.csv"), "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                intent, _ = classify_intent(row["request_text"])
                if intent == "NOT_APPLICABLE":
                    na_count += 1
        # Cases 533-542 are all non-deletion
        self.assertEqual(na_count, 10, f"Expected 10 NOT_APPLICABLE, got {na_count}")


class TestPolicyEngine(unittest.TestCase):

    def test_all_15_rules_loaded(self):
        self.assertEqual(len(RULES), 15)

    def test_user_profile_delete(self):
        self.assertEqual(get_required_action("USER_PROFILE"), "DELETE")

    def test_search_index_delete(self):
        self.assertEqual(get_required_action("SEARCH_INDEX_ENTRY"), "DELETE")

    def test_support_message_redact(self):
        self.assertEqual(get_required_action("SUPPORT_MESSAGE"), "REDACT")

    def test_analytics_anonymize(self):
        self.assertEqual(get_required_action("ANALYTICS_PROFILE"), "ANONYMIZE")

    def test_security_audit_retain(self):
        self.assertEqual(get_required_action("SECURITY_AUDIT_LOG"), "RETAIN")

    def test_backup_retain(self):
        self.assertEqual(get_required_action("BACKUP_ARCHIVE"), "RETAIN")

    def test_tombstone_redact(self):
        self.assertEqual(get_required_action("ACCOUNT_TOMBSTONE"), "REDACT")

    def test_unknown_category(self):
        self.assertIsNone(get_required_action("NONEXISTENT_CATEGORY"))

    # ── Violation detection ────────────────────────────────────────

    def test_profile_present_is_violation(self):
        self.assertTrue(is_violation("USER_PROFILE", "PRESENT"))

    def test_profile_absent_ok(self):
        self.assertFalse(is_violation("USER_PROFILE", "ABSENT"))

    def test_analytics_present_is_violation(self):
        self.assertTrue(is_violation("ANALYTICS_PROFILE", "PRESENT"))

    def test_analytics_anonymized_ok(self):
        self.assertFalse(is_violation("ANALYTICS_PROFILE", "ANONYMIZED"))

    def test_support_present_is_violation(self):
        self.assertTrue(is_violation("SUPPORT_MESSAGE", "PRESENT"))

    def test_support_redacted_ok(self):
        self.assertFalse(is_violation("SUPPORT_MESSAGE", "REDACTED"))

    def test_backup_active_is_violation(self):
        self.assertTrue(is_violation("BACKUP_ARCHIVE", "ACTIVE"))

    def test_backup_blocked_ok(self):
        self.assertFalse(is_violation("BACKUP_ARCHIVE", "BLOCKED"))

    def test_tombstone_present_is_violation(self):
        self.assertTrue(is_violation("ACCOUNT_TOMBSTONE", "PRESENT"))

    def test_tombstone_redacted_ok(self):
        self.assertFalse(is_violation("ACCOUNT_TOMBSTONE", "REDACTED"))

    def test_security_present_ok(self):
        self.assertFalse(is_violation("SECURITY_AUDIT_LOG", "PRESENT"))

    # ── Compliant states ───────────────────────────────────────────

    def test_compliant_state_delete(self):
        self.assertEqual(compliant_state("DELETE"), "ABSENT")

    def test_compliant_state_redact(self):
        self.assertEqual(compliant_state("REDACT"), "REDACTED")

    def test_compliant_state_anonymize(self):
        self.assertEqual(compliant_state("ANONYMIZE"), "ANONYMIZED")

    def test_compliant_state_retain(self):
        self.assertEqual(compliant_state("RETAIN"), "PRESENT")

    # ── Finding operations ─────────────────────────────────────────

    def test_finding_data_flow(self):
        op, st = finding_operation("DATA_FLOW", "ACTIVE")
        self.assertEqual(op, "REPORT_ACTIVE_DATA_FLOW")
        self.assertEqual(st, "ACTIVE")

    def test_finding_backup(self):
        op, st = finding_operation("BACKUP_ARCHIVE", "ACTIVE")
        self.assertEqual(op, "REPORT_RESTORE_RISK")
        self.assertEqual(st, "ACTIVE")

    def test_finding_profile(self):
        op, st = finding_operation("USER_PROFILE", "PRESENT")
        self.assertEqual(op, "REPORT_REMAINING_RECORD")
        self.assertEqual(st, "PRESENT")

    def test_finding_analytics(self):
        op, st = finding_operation("ANALYTICS_PROFILE", "PRESENT")
        self.assertEqual(op, "REPORT_EXPOSED_PII")
        self.assertEqual(st, "PRESENT")

    # ── Remediation operations ─────────────────────────────────────

    def test_remediation_delete(self):
        op, st = remediation_operation("USER_PROFILE")
        self.assertEqual(op, "DELETE_RECORD")
        self.assertEqual(st, "ABSENT")

    def test_remediation_redact(self):
        op, st = remediation_operation("SUPPORT_MESSAGE")
        self.assertEqual(op, "REDACT_RECORD")
        self.assertEqual(st, "REDACTED")

    def test_remediation_anonymize(self):
        op, st = remediation_operation("ANALYTICS_PROFILE")
        self.assertEqual(op, "ANONYMIZE_RECORD")
        self.assertEqual(st, "ANONYMIZED")

    # ── Verification operations ────────────────────────────────────

    def test_verify_delete(self):
        op, st = verification_operation("USER_PROFILE")
        self.assertEqual(op, "VERIFY_RECORD_ABSENT")
        self.assertEqual(st, "ABSENT")

    def test_verify_retain(self):
        op, st = verification_operation("SECURITY_AUDIT_LOG")
        self.assertEqual(op, "VERIFY_RECORD_PRESENT")
        self.assertEqual(st, "PRESENT")

    def test_verify_anonymize(self):
        op, st = verification_operation("ANALYTICS_PROFILE")
        self.assertEqual(op, "VERIFY_RECORD_ANONYMIZED")
        self.assertEqual(st, "ANONYMIZED")

    def test_verify_backup(self):
        op, st = verification_operation("BACKUP_ARCHIVE")
        self.assertEqual(op, "VERIFY_RESTORE_BLOCKED")
        self.assertEqual(st, "BLOCKED")

    def test_verify_data_flow(self):
        op, st = verification_operation("DATA_FLOW")
        self.assertEqual(op, "VERIFY_DATA_FLOW_DISABLED")
        self.assertEqual(st, "DISABLED")


if __name__ == "__main__":
    unittest.main()
