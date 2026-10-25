"""
Deletion policy engine for Ghost Data Still Exists challenge.

Encodes the 15 rules from dataset/deletion_rules.csv and determines the
required treatment for each data_category found in evidence.  The engine
returns one of:

    DELETE      – entire record must be removed
    REDACT      – remove prohibited identifiers, keep the record
    ANONYMIZE   – irreversibly unlink from user, keep the record
    RETAIN      – keep the record as-is (legal/security/backup retention)

Rule application depends on data_category and may be conditioned on the
current state of the evidence record.
"""

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class DeletionRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str  # DELETE, REDACT, ANONYMIZE, RETAIN


# ── Static rule table (matches dataset/deletion_rules.csv exactly) ────

RULES: Dict[str, DeletionRule] = {
    r.data_category: r
    for r in [
        DeletionRule("rule_01", "USER_PROFILE", "Always", "DELETE"),
        DeletionRule("rule_02", "SECONDARY_IDENTIFIER", "Always", "DELETE"),
        DeletionRule("rule_03", "SEARCH_INDEX_ENTRY", "Always", "DELETE"),
        DeletionRule("rule_04", "CACHE_ENTRY", "Always", "DELETE"),
        DeletionRule("rule_05", "SUPPORT_MESSAGE",
                     "Conversation contains shared customer, agent, or order context that must be retained",
                     "REDACT"),
        DeletionRule("rule_06", "SUPPORT_ATTACHMENT",
                     "Attachment belongs only to the deletion subject",
                     "DELETE"),
        DeletionRule("rule_07", "ANALYTICS_PROFILE",
                     "Record is still attributable to a user",
                     "ANONYMIZE"),
        DeletionRule("rule_08", "PRODUCT_TELEMETRY",
                     "Record is still attributable to a user",
                     "ANONYMIZE"),
        DeletionRule("rule_09", "USER_EXPORT", "Always", "DELETE"),
        DeletionRule("rule_10", "MARKETING_PROFILE", "Always", "DELETE"),
        DeletionRule("rule_11", "EMAIL_DELIVERY_LOG",
                     "Log contains a user email address",
                     "REDACT"),
        DeletionRule("rule_12", "SECURITY_AUDIT_LOG",
                     "Record is within the supplied retention period",
                     "RETAIN"),
        DeletionRule("rule_13", "LEGAL_HOLD_RECORD",
                     "A supplied legal hold is active",
                     "RETAIN"),
        DeletionRule("rule_14", "BACKUP_ARCHIVE",
                     "Restore access can be blocked",
                     "RETAIN"),
        DeletionRule("rule_15", "ACCOUNT_TOMBSTONE",
                     "Account is deleted and only a stable internal user_id is needed to preserve references to retained records",
                     "REDACT"),
    ]
}


def get_required_action(data_category: str) -> Optional[str]:
    """Return the required_action for *data_category*, or None if unknown."""
    rule = RULES.get(data_category)
    return rule.required_action if rule else None


# ── Mapping: required_action → expected compliant state ──────────────

_COMPLIANT_STATE = {
    "DELETE": "ABSENT",
    "REDACT": "REDACTED",
    "ANONYMIZE": "ANONYMIZED",
    "RETAIN": "PRESENT",
}


def compliant_state(required_action: str) -> str:
    """Return the expected evidence state after a compliant action."""
    return _COMPLIANT_STATE.get(required_action, "ABSENT")


# ── Mapping: (required_action, current_state) → violation? ───────────

def is_violation(data_category: str, current_state: str) -> bool:
    """
    True when the current_state of a record violates deletion policy.
    
    For DATA_FLOW (integration_service connectors), an ACTIVE state means
    the flow can recreate data — this is a violation.
    
    For BACKUP_ARCHIVE, the policy is RETAIN but restore must be blocked.
    An ACTIVE state (restore allowed) is a violation; BLOCKED is compliant.
    """
    # Special case: DATA_FLOW – integration_service connectors can recreate data.
    # An ACTIVE state is a violation; DISABLED is compliant.
    if data_category == "DATA_FLOW":
        return current_state == "ACTIVE"

    # Special case: BACKUP_ARCHIVE – policy says RETAIN, but restore access
    # must be blocked.  An ACTIVE backup is a violation (restore risk).
    if data_category == "BACKUP_ARCHIVE":
        return current_state == "ACTIVE"

    # Special case: ACCOUNT_TOMBSTONE – policy says REDACT.
    # A PRESENT tombstone (still has direct identifiers) is a violation.
    # A REDACTED tombstone is compliant.
    if data_category == "ACCOUNT_TOMBSTONE":
        return current_state == "PRESENT"

    action = get_required_action(data_category)
    if action is None:
        return False

    expected = compliant_state(action)

    if action == "DELETE":
        return current_state != "ABSENT"
    elif action == "REDACT":
        return current_state not in ("REDACTED", "ABSENT")
    elif action == "ANONYMIZE":
        return current_state not in ("ANONYMIZED", "ABSENT")
    elif action == "RETAIN":
        # SECURITY_AUDIT_LOG and LEGAL_HOLD_RECORD must be present
        return current_state == "ABSENT"

    return False


# ── Step operation helpers ────────────────────────────────────────────

def finding_operation(data_category: str, current_state: str) -> tuple:
    """
    Return (operation, state) for a FINDING step based on category and state.
    """
    if data_category == "DATA_FLOW" and current_state == "ACTIVE":
        return ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE")
    if data_category == "BACKUP_ARCHIVE" and current_state == "ACTIVE":
        return ("REPORT_RESTORE_RISK", "ACTIVE")
    if data_category in ("ACCOUNT_TOMBSTONE",) and current_state == "PRESENT":
        return ("REPORT_EXPOSED_PII", "PRESENT")
    if data_category in ("SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG") and current_state == "PRESENT":
        return ("REPORT_EXPOSED_PII", "PRESENT")

    action = get_required_action(data_category)
    if action == "ANONYMIZE" and current_state == "PRESENT":
        return ("REPORT_EXPOSED_PII", "PRESENT")

    return ("REPORT_REMAINING_RECORD", "PRESENT")


def remediation_operation(data_category: str) -> tuple:
    """
    Return (operation, target_state) for a REMEDIATION step.
    """
    action = get_required_action(data_category)
    if action == "DELETE":
        return ("DELETE_RECORD", "ABSENT")
    elif action == "REDACT":
        return ("REDACT_RECORD", "REDACTED")
    elif action == "ANONYMIZE":
        return ("ANONYMIZE_RECORD", "ANONYMIZED")
    elif data_category == "DATA_FLOW":
        return ("DISABLE_DATA_FLOW", "DISABLED")
    elif data_category == "BACKUP_ARCHIVE":
        return ("BLOCK_RESTORE", "BLOCKED")
    return ("DELETE_RECORD", "ABSENT")


def verification_operation(data_category: str, is_complete: bool = True) -> tuple:
    """
    Return (operation, expected_state) for a VERIFICATION step.

    For a COMPLETE case the verification proves current compliance.
    For an INCOMPLETE case (remediation proposed) the verification checks
    the expected post-remediation state.
    """
    action = get_required_action(data_category)

    if data_category == "BACKUP_ARCHIVE":
        return ("VERIFY_RESTORE_BLOCKED", "BLOCKED")
    if data_category == "DATA_FLOW":
        return ("VERIFY_DATA_FLOW_DISABLED", "DISABLED")

    if action == "DELETE":
        return ("VERIFY_RECORD_ABSENT", "ABSENT")
    elif action == "REDACT":
        return ("VERIFY_RECORD_REDACTED", "REDACTED")
    elif action == "ANONYMIZE":
        return ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED")
    elif action == "RETAIN":
        return ("VERIFY_RECORD_PRESENT", "PRESENT")

    return ("VERIFY_RECORD_ABSENT", "ABSENT")
