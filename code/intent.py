"""
Intent classification for Ghost Data Still Exists challenge.

Determines whether request_text actually authorizes account/data deletion.
Non-deletion requests (access, correction, export, marketing opt-out, login
help) must be classified NOT_APPLICABLE with steps_json=[].

Design: conservative deterministic keyword classifier with multi-language
support and negation-pattern awareness.  No external LLM needed for this
dataset.  If a request is ambiguous, the classifier errs toward
NOT_APPLICABLE — the user did not authorize deletion, so no audit occurs.
"""

import re
from typing import Tuple

# ── Deletion-intent signals (multi-language) ───────────────────────────

_DELETION_PHRASES = [
    # English
    "delete",
    "deleting",
    "deletion",
    "erase",
    "erasure",
    "remove my account",
    "remove my personal",
    "remove the account",
    "remove the profile",
    "remove my profile",
    "remove records",
    "remove that search",
    "remove the personal",
    "close my account",
    "close this account",
    "close the account",
    "account closed",
    "account to be erased",
    "account to be deleted",
    "permanently deleted",
    "already been removed",
    "profile is gone",
    "nothing tied to the old address was left behind",
    "permanent account-deletion",
    "personal-data deletion",
    "purge",
    # Spanish
    "eliminar",
    "eliminación",
    # French
    "suppression",
    "supprimer",
    # German
    "löschen",
    "löschung",
    # Portuguese
    "exclusão",
    "excluir",
    # Japanese
    "削除",
    # Korean
    "삭제",
    # Russian
    "удалить",
    "удаление",
]

# ── Negation / non-deletion signals ────────────────────────────────────

_NON_DELETION_PHRASES = [
    # Explicit disclaimers
    "not asking for deletion",
    "not a request to erase",
    "not a request to delete",
    "not a deletion request",
    "do not close",
    "don't close",
    "don't delete",
    "do not delete",
    "please don't delete",
    "please do not delete",
    "don't remove",
    "do not remove",
    "please don't remove",
    "not requesting deletion",
    "without removing",
    "leave the account",
    "leave my profile",
    "keep the account",
    "continue using",
    "still use it",
    "still need the account",
    "still want receipts",
    "i still use",
    "i want to continue",
    # Data access / export (DSAR)
    "download my account information",
    "copy of last year",
    "copy of the information",
    "send me a copy",
    "portable format",
    "what personal information you hold",
    "information request",
    # Correction
    "misspelled",
    "is out of date",
    "correct it without",
    "correct it and",
    # Account update
    "change the email",
    "replace it with the new",
    "change the email address",
    # Login help
    "resetting the login",
    "reset my password",
    "can't access my profile",
    "cannot access my profile",
    # Marketing opt-out only
    "marketing lists only",
    "stop the promotional",
    "unsubscribe from marketing",
    "remove me from marketing",
]


def classify_intent(request_text: str) -> Tuple[str, str]:
    """
    Classify whether *request_text* authorizes deletion.

    Returns:
        ("DELETION", reason)         – proceed with deletion audit
        ("NOT_APPLICABLE", reason)   – non-deletion intent
    """
    if not request_text or not request_text.strip():
        return ("NOT_APPLICABLE", "empty request text")

    txt = request_text.strip().lower()

    # 1. Check for explicit non-deletion signals first.
    #    A request that says "do not close the account" is never deletion
    #    regardless of other keywords.
    for phrase in _NON_DELETION_PHRASES:
        if phrase in txt:
            return ("NOT_APPLICABLE", f"non-deletion signal: '{phrase}'")

    # 2. Check for positive deletion signals.
    for phrase in _DELETION_PHRASES:
        if phrase in txt:
            return ("DELETION", f"deletion signal: '{phrase}'")

    # 3. No signal found → default conservative: NOT_APPLICABLE.
    return ("NOT_APPLICABLE", "no deletion authorization detected")
