"""
Identity resolution module for Ghost Data Still Exists challenge.
Builds canonical UserIdentityGraph linking current and historical identifiers.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, Set
import csv
import os


@dataclass
class UserIdentityGraph:
    user_id: str
    name: str
    current_email: str
    emails: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)
    email_hashes: Set[str] = field(default_factory=set)
    updated_at: str = ""

    def matches_any(self, identifier: str) -> bool:
        if not identifier:
            return False
        clean_id = identifier.strip().lower()
        if clean_id == self.user_id.lower():
            return True
        if clean_id in self.emails:
            return True
        if clean_id in self.email_hashes:
            return True
        clean_phone = identifier.strip()
        if clean_phone in self.phones:
            return True
        if self.name and self.name.lower() in clean_id:
            return True
        return False


class IdentityResolver:
    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = dataset_dir
        self.users_by_id: Dict[str, UserIdentityGraph] = {}
        self.email_to_user_id: Dict[str, str] = {}
        self.phone_to_user_id: Dict[str, str] = {}
        self.hash_to_user_id: Dict[str, str] = {}
        self._load_identities()
        self._load_audit_log()

    def _load_identities(self) -> None:
        identities_path = os.path.join(self.dataset_dir, "user_identities.csv")
        if not os.path.exists(identities_path):
            raise FileNotFoundError(f"Missing {identities_path}")

        with open(identities_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                name = row["name"].strip()
                email = row["email"].strip().lower()
                phone = row["phone"].strip()
                email_hash = row["email_hash"].strip().lower()
                updated_at = row.get("updated_at", "").strip()

                graph = UserIdentityGraph(
                    user_id=uid,
                    name=name,
                    current_email=email,
                    emails={email},
                    phones={phone} if phone else set(),
                    email_hashes={email_hash} if email_hash else set(),
                    updated_at=updated_at,
                )
                self.users_by_id[uid] = graph
                self.email_to_user_id[email] = uid
                if phone:
                    self.phone_to_user_id[phone] = uid
                if email_hash:
                    self.hash_to_user_id[email_hash] = uid

    def _load_audit_log(self) -> None:
        audit_path = os.path.join(self.dataset_dir, "user_audit_log.csv")
        if not os.path.exists(audit_path):
            return

        with open(audit_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                field_name = row["field_name"].strip()
                old_val = row["old_value"].strip()
                new_val = row["new_value"].strip()

                graph = self.users_by_id.get(uid)
                if not graph:
                    continue

                if field_name == "email":
                    if old_val:
                        em_old = old_val.lower()
                        graph.emails.add(em_old)
                        self.email_to_user_id[em_old] = uid
                    if new_val:
                        em_new = new_val.lower()
                        graph.emails.add(em_new)
                        self.email_to_user_id[em_new] = uid
                elif field_name == "phone":
                    if old_val:
                        graph.phones.add(old_val)
                        self.phone_to_user_id[old_val] = uid
                    if new_val:
                        graph.phones.add(new_val)
                        self.phone_to_user_id[new_val] = uid
                elif field_name == "email_hash":
                    if old_val:
                        h_old = old_val.lower()
                        graph.email_hashes.add(h_old)
                        self.hash_to_user_id[h_old] = uid
                    if new_val:
                        h_new = new_val.lower()
                        graph.email_hashes.add(h_new)
                        self.hash_to_user_id[h_new] = uid

    def resolve_by_email(self, email: str) -> Optional[UserIdentityGraph]:
        if not email:
            return None
        clean_email = email.strip().lower()
        uid = self.email_to_user_id.get(clean_email)
        return self.users_by_id.get(uid) if uid else None

    def resolve_by_user_id(self, user_id: str) -> Optional[UserIdentityGraph]:
        if not user_id:
            return None
        return self.users_by_id.get(user_id.strip())

    def resolve(self, identifier: str) -> Optional[UserIdentityGraph]:
        if not identifier:
            return None
        clean_id = identifier.strip()
        clean_lower = clean_id.lower()

        if clean_id in self.users_by_id:
            return self.users_by_id[clean_id]
        if clean_lower in self.email_to_user_id:
            return self.users_by_id[self.email_to_user_id[clean_lower]]
        if clean_id in self.phone_to_user_id:
            return self.users_by_id[self.phone_to_user_id[clean_id]]
        if clean_lower in self.hash_to_user_id:
            return self.users_by_id[self.hash_to_user_id[clean_lower]]
        return None
