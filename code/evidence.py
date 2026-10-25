"""
Evidence ingestion and indexing module for Ghost Data Still Exists challenge.
Parses SQL, JSON, logs, text reports, PDFs, and verified image facts into a
temporally filtered, multi-key in-memory index.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
import csv
import json
import os
import re
import sqlite3

try:
    import pypdf
except ImportError:
    pypdf = None


@dataclass
class EvidenceItem:
    evidence_id: str
    file_path: str
    origin: str
    captured_at: str
    system_id: str
    resource_id: str
    data_category: str
    state: str
    identifiers: Set[str] = field(default_factory=set)
    raw_details: str = ""

    def matches_user(self, user_graph) -> bool:
        if not user_graph:
            return False
        for ident in self.identifiers:
            if user_graph.matches_any(ident):
                return True
        return False


# Ground truth observations extracted from the 11 PNG screenshots
IMAGE_EVIDENCE_FACTS = [
    # evidence_04: account_admin_console_20260926.png
    EvidenceItem(
        evidence_id="evidence_04",
        file_path="evidence/images/account_admin_console_20260926.png",
        origin="account_admin_portal",
        captured_at="2026-09-26T11:00:00Z",
        system_id="account_service",
        resource_id="account_5762",
        data_category="USER_PROFILE",
        state="PRESENT",
        identifiers={"user_11", "haruka.s1838@zoho.com", "+81 90 7610 2507", "haruka sato"},
        raw_details="Customer Haruka Sato (user_11 / account_5762) active in account admin console.",
    ),
    EvidenceItem(
        evidence_id="evidence_04",
        file_path="evidence/images/account_admin_console_20260926.png",
        origin="account_admin_portal",
        captured_at="2026-09-26T11:00:00Z",
        system_id="support_platform",
        resource_id="support_9538",
        data_category="SUPPORT_MESSAGE",
        state="PRESENT",
        identifiers={"user_11", "haruka.s1838@zoho.com", "+81 90 7610 2507"},
        raw_details="Support ticket CS-8538 (support_9538) active for Haruka Sato.",
    ),
    # evidence_09: search_index_inspector_20260901.png
    EvidenceItem(
        evidence_id="evidence_09",
        file_path="evidence/images/search_index_inspector_20260901.png",
        origin="search_index_admin",
        captured_at="2026-09-01T06:00:00Z",
        system_id="search_service",
        resource_id="search_428",
        data_category="SEARCH_INDEX_ENTRY",
        state="PRESENT",
        identifiers={"user_13", "g.silva76@gmail.com", "gabriel silva"},
        raw_details="Search document search_428 for Gabriel Silva found in customer_directory_v3.",
    ),
    # evidence_14: connector_management_console_20260807.png
    EvidenceItem(
        evidence_id="evidence_14",
        file_path="evidence/images/connector_management_console_20260807.png",
        origin="integration_admin",
        captured_at="2026-08-07T08:00:00Z",
        system_id="integration_service",
        resource_id="data_flow_1121",
        data_category="DATA_FLOW",
        state="ACTIVE",
        identifiers={"jain.aditi@gmail.com"},
        raw_details="Connector data_flow_1121 active (Healthy, continuous sync) for jain.aditi@gmail.com.",
    ),
    EvidenceItem(
        evidence_id="evidence_14",
        file_path="evidence/images/connector_management_console_20260807.png",
        origin="integration_admin",
        captured_at="2026-08-07T08:00:00Z",
        system_id="integration_service",
        resource_id="data_flow_9846",
        data_category="DATA_FLOW",
        state="ACTIVE",
        identifiers={"lucia-torres@gmail.com"},
        raw_details="Connector data_flow_9846 active (Healthy, continuous sync) for lucia-torres@gmail.com.",
    ),
    # evidence_19: analytics_profile_view_20260713.png
    EvidenceItem(
        evidence_id="evidence_19",
        file_path="evidence/images/analytics_profile_view_20260713.png",
        origin="analytics_platform",
        captured_at="2026-07-13T10:00:00Z",
        system_id="analytics_platform",
        resource_id="analytics_7438",
        data_category="ANALYTICS_PROFILE",
        state="PRESENT",
        identifiers={"user_20", "darwish.omar@icloud.com", "omar darwish"},
        raw_details="Analytics profile analytics_7438 identifiable for Omar Darwish.",
    ),
    # evidence_23: customer_export_console_20260618.png
    EvidenceItem(
        evidence_id="evidence_23",
        file_path="evidence/images/customer_export_console_20260618.png",
        origin="export_service",
        captured_at="2026-06-18T12:00:00Z",
        system_id="export_service",
        resource_id="export_1260",
        data_category="USER_EXPORT",
        state="PRESENT",
        identifiers={"ingrid.dahl@outlook.com"},
        raw_details="Data export export_1260 status Ready for ingrid.dahl@outlook.com.",
    ),
    # evidence_28: support_ticket_console_20260524.png
    EvidenceItem(
        evidence_id="evidence_28",
        file_path="evidence/images/support_ticket_console_20260524.png",
        origin="support_platform",
        captured_at="2026-05-24T07:00:00Z",
        system_id="support_platform",
        resource_id="support_1034",
        data_category="SUPPORT_MESSAGE",
        state="PRESENT",
        identifiers={"kagyeman8947@fastmail.com", "kofi agyeman"},
        raw_details="Support ticket CS-5034 (support_1034) identifiable for Kofi Agyeman.",
    ),
    # evidence_32: backup_restore_console_20260429.png
    EvidenceItem(
        evidence_id="evidence_32",
        file_path="evidence/images/backup_restore_console_20260429.png",
        origin="backup_service",
        captured_at="2026-04-29T09:00:00Z",
        system_id="backup_service",
        resource_id="backup_9287",
        data_category="BACKUP_ARCHIVE",
        state="ACTIVE",
        identifiers={"areed1433@gmail.com"},
        raw_details="Archive backup_9287 active for areed1433@gmail.com in backup restore console.",
    ),
    # evidence_37: security_audit_explorer_20260905.png
    EvidenceItem(
        evidence_id="evidence_37",
        file_path="evidence/images/security_audit_explorer_20260905.png",
        origin="security_service",
        captured_at="2026-09-05T07:00:00Z",
        system_id="security_service",
        resource_id="audit_record_003",
        data_category="SECURITY_AUDIT_LOG",
        state="PRESENT",
        identifiers={"user_03"},
        raw_details="Security audit record audit_record_003 retained for user_03.",
    ),
    # evidence_42: deleted_account_reference_20260310.png
    EvidenceItem(
        evidence_id="evidence_42",
        file_path="evidence/images/deleted_account_reference_20260310.png",
        origin="identity_service",
        captured_at="2026-03-10T06:00:00Z",
        system_id="identity_service",
        resource_id="tombstone_user_17",
        data_category="ACCOUNT_TOMBSTONE",
        state="REDACTED",
        identifiers={"user_17"},
        raw_details="Retained customer key reference for user_17 with direct identifiers removed.",
    ),
    # evidence_60: marketing_profile_console.png
    EvidenceItem(
        evidence_id="evidence_60",
        file_path="evidence/images/marketing_profile_console.png",
        origin="marketing_platform",
        captured_at="2026-09-16T07:20:00Z",
        system_id="marketing_platform",
        resource_id="marketing_001",
        data_category="MARKETING_PROFILE",
        state="PRESENT",
        identifiers={"sj.park@naver.com", "+82 10-5837-9451", "soo-jin park"},
        raw_details="Live marketing profile marketing_001 for Soo-jin Park.",
    ),
]


class EvidenceIndexer:
    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = dataset_dir
        self.manifest: Dict[str, dict] = {}
        self.items: List[EvidenceItem] = []
        self.items_by_resource: Dict[str, List[EvidenceItem]] = {}
        self.items_by_identifier: Dict[str, List[EvidenceItem]] = {}
        self._load_manifest()
        self._ingest_all_evidence()

    def _load_manifest(self) -> None:
        manifest_path = os.path.join(self.dataset_dir, "evidence_files.csv")
        with open(manifest_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                fid = row["file_id"].strip()
                self.manifest[fid] = {
                    "file_id": fid,
                    "file_path": row["file_path"].strip(),
                    "origin": row["origin"].strip(),
                    "captured_at": row["captured_at"].strip(),
                }

    def _add_item(self, item: EvidenceItem) -> None:
        self.items.append(item)
        if item.resource_id:
            self.items_by_resource.setdefault(item.resource_id, []).append(item)
        for ident in item.identifiers:
            clean = ident.strip().lower()
            if clean:
                self.items_by_identifier.setdefault(clean, []).append(item)

    def _ingest_all_evidence(self) -> None:
        # 1. Ingest image facts
        for item in IMAGE_EVIDENCE_FACTS:
            self._add_item(item)

        # 2. Ingest files from manifest
        for fid, meta in self.manifest.items():
            rel_path = meta["file_path"]
            full_path = os.path.join(self.dataset_dir, rel_path)
            if not os.path.exists(full_path):
                continue

            captured_at = meta["captured_at"]
            origin = meta["origin"]

            if rel_path.endswith(".sql"):
                self._ingest_sql(fid, full_path, origin, captured_at)
            elif rel_path.endswith(".json"):
                self._ingest_json(fid, full_path, origin, captured_at)
            elif rel_path.endswith(".txt"):
                self._ingest_txt(fid, full_path, origin, captured_at)
            elif rel_path.endswith(".log"):
                self._ingest_log(fid, full_path, origin, captured_at)
            elif rel_path.endswith(".pdf"):
                self._ingest_pdf(fid, full_path, origin, captured_at)

    def _ingest_sql(self, fid: str, path: str, origin: str, captured_at: str) -> None:
        conn = sqlite3.connect(":memory:")
        try:
            with open(path, "r", encoding="utf-8") as f:
                conn.executescript(f.read())
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]

            for tbl in tables:
                if tbl == "snapshot_scope":
                    continue
                cols = [c[1] for c in conn.execute(f"PRAGMA table_info({tbl})").fetchall()]
                rows = conn.execute(f"SELECT * FROM {tbl}").fetchall()

                for row in rows:
                    row_dict = dict(zip(cols, row))

                    # Check if table has record_json
                    if "record_json" in row_dict:
                        raw_json = row_dict["record_json"]
                        try:
                            rec = json.loads(raw_json)
                        except Exception:
                            rec = {}
                        res_id = row_dict.get("resource_id") or rec.get("resource_id", "")
                        origin_sys = row_dict.get("origin_system", "")
                        coll = row_dict.get("collection_name", "")

                        idents = set()
                        uid = rec.get("user_id") or rec.get("customer_reference") or rec.get("subject_reference") or ""
                        if uid:
                            idents.add(uid.lower())
                        document = rec.get("document") if isinstance(rec.get("document"), dict) else {}
                        for em_key in ["email", "customer_email", "owner_email", "requester_email"]:
                            value = rec.get(em_key) or document.get(em_key)
                            if value:
                                idents.add(value.lower())
                        for ref_key in ["customer_reference", "subject_reference", "user_id"]:
                            value = document.get(ref_key)
                            if value:
                                idents.add(value.lower())
                        if rec.get("phone"):
                            idents.add(rec["phone"])
                        if rec.get("full_name"):
                            idents.add(rec["full_name"].lower())
                        if rec.get("name"):
                            idents.add(rec["name"].lower())

                        sys_id = origin_sys or "account_service"
                        cat = "USER_PROFILE"
                        state = "PRESENT"

                        if res_id.startswith("account_") or coll == "customer_profiles":
                            sys_id = "account_service"
                            cat = "USER_PROFILE"
                            st = rec.get("account_status", "ACTIVE")
                            state = "PRESENT" if st in ("ACTIVE", "OPEN") else "ABSENT"
                        elif res_id.startswith("search_") or coll == "customer_search_documents":
                            sys_id = "search_service"
                            cat = "SEARCH_INDEX_ENTRY"
                            state = "PRESENT"
                        elif res_id.startswith("analytics_") or coll == "customer_analytics_reports":
                            sys_id = "analytics_platform"
                            cat = "ANALYTICS_PROFILE"
                            has_id = bool(rec.get("email") or rec.get("phone") or rec.get("user_id") or rec.get("customer_reference"))
                            state = "PRESENT" if has_id else "ANONYMIZED"
                        elif res_id.startswith("backup_") or coll == "backup_catalog":
                            sys_id = "backup_service"
                            cat = "BACKUP_ARCHIVE"
                            allowed = rec.get("restore_allowed") in ("1", 1, "true", True) or rec.get("status") == "ACTIVE"
                            state = "ACTIVE" if allowed else "BLOCKED"
                        elif res_id.startswith("data_flow_") or coll == "connector_configurations":
                            sys_id = "integration_service"
                            cat = "DATA_FLOW"
                            enabled = rec.get("enabled") in ("1", 1, "true", True)
                            state = "ACTIVE" if enabled else "DISABLED"
                        elif res_id.startswith("support_") or coll == "support_conversations":
                            sys_id = "support_platform"
                            cat = "SUPPORT_MESSAGE"
                            has_dir = bool(rec.get("requester_email") or rec.get("requester_name") or rec.get("requester_phone"))
                            state = "PRESENT" if has_dir else "REDACTED"
                        elif res_id.startswith("audit_record_") or coll == "security_audit_events":
                            sys_id = "security_service"
                            cat = "SECURITY_AUDIT_LOG"
                            state = "PRESENT"
                        elif res_id.startswith("export_") or coll == "customer_export_jobs":
                            sys_id = "export_service"
                            cat = "USER_EXPORT"
                            state = "PRESENT"
                        elif res_id.startswith("tombstone_"):
                            sys_id = "identity_service"
                            cat = "ACCOUNT_TOMBSTONE"
                            has_pii = bool(rec.get("email") or rec.get("phone") or rec.get("name") or rec.get("email_hash"))
                            state = "PRESENT" if has_pii else "REDACTED"

                        if res_id:
                            self._add_item(
                                EvidenceItem(
                                    evidence_id=fid,
                                    file_path=path,
                                    origin=origin,
                                    captured_at=captured_at,
                                    system_id=sys_id,
                                    resource_id=res_id,
                                    data_category=cat,
                                    state=state,
                                    identifiers=idents,
                                    raw_details=f"SQL replica record: {res_id} in {tbl}",
                                )
                            )
                        continue

                    # Direct columns table
                    res_id = row_dict.get("resource_id") or row_dict.get("id") or ""
                    uid = row_dict.get("user_id") or row_dict.get("customer_reference") or row_dict.get("subject_reference") or ""
                    idents = set()
                    if uid:
                        idents.add(uid.lower())
                    for em_key in ["email", "customer_email", "owner_email", "requester_email"]:
                        if row_dict.get(em_key):
                            idents.add(row_dict[em_key].lower())
                    if row_dict.get("phone"):
                        idents.add(row_dict["phone"])
                    if row_dict.get("full_name"):
                        idents.add(row_dict["full_name"].lower())
                    if row_dict.get("requester_name"):
                        idents.add(row_dict["requester_name"].lower())
                    if row_dict.get("name"):
                        idents.add(row_dict["name"].lower())

                    sys_id = "account_service"
                    cat = "USER_PROFILE"
                    state = "PRESENT"

                    if "backup" in tbl:
                        sys_id = "backup_service"
                        cat = "BACKUP_ARCHIVE"
                        allowed = row_dict.get("restore_allowed") in ("1", 1, "true", True)
                        state = "ACTIVE" if allowed else "BLOCKED"
                    elif "connector" in tbl:
                        sys_id = "integration_service"
                        cat = "DATA_FLOW"
                        enabled = row_dict.get("enabled") in ("1", 1, "true", True)
                        state = "ACTIVE" if enabled else "DISABLED"
                    elif "analytics" in tbl:
                        sys_id = "analytics_platform"
                        cat = "ANALYTICS_PROFILE"
                        has_id = bool(row_dict.get("email") or row_dict.get("phone") or row_dict.get("customer_reference"))
                        state = "PRESENT" if has_id else "ANONYMIZED"
                    elif "export" in tbl:
                        sys_id = "export_service"
                        cat = "USER_EXPORT"
                        state = "PRESENT"
                    elif "search" in tbl:
                        sys_id = "search_service"
                        cat = "SEARCH_INDEX_ENTRY"
                        state = "PRESENT"
                    elif "audit" in tbl or "security" in tbl:
                        sys_id = "security_service"
                        cat = "SECURITY_AUDIT_LOG"
                        state = "PRESENT"
                    elif "support" in tbl:
                        sys_id = "support_platform"
                        cat = "SUPPORT_MESSAGE"
                        has_pii = bool(row_dict.get("requester_email") or row_dict.get("requester_name") or row_dict.get("requester_phone"))
                        state = "PRESENT" if has_pii else "REDACTED"
                    elif "profile" in tbl or "account" in tbl:
                        sys_id = "account_service"
                        cat = "USER_PROFILE"
                        st = row_dict.get("account_status", "ACTIVE")
                        state = "PRESENT" if st in ("ACTIVE", "OPEN") else "ABSENT"

                    if res_id:
                        self._add_item(
                            EvidenceItem(
                                evidence_id=fid,
                                file_path=path,
                                origin=origin,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=res_id,
                                data_category=cat,
                                state=state,
                                identifiers=idents,
                                raw_details=f"SQL table {tbl}: {row_dict}",
                            )
                        )
        except Exception:
            pass
        finally:
            conn.close()

    def _ingest_json(self, fid: str, path: str, origin: str, captured_at: str) -> None:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return

        # Handle service_resource_export files
        if "service_exports" in data:
            exports = data["service_exports"]
            for sys_id, content in exports.items():
                if sys_id == "account_service":
                    for lookup in content.get("profile_lookups", []):
                        res_id = lookup.get("resource_id", "")
                        code = lookup.get("status_code", 404)
                        prof = lookup.get("profile") or {}
                        state = "ABSENT" if code == 404 else "PRESENT"
                        idents = set()
                        if prof.get("customer_reference"):
                            idents.add(prof["customer_reference"])
                        if prof.get("email"):
                            idents.add(prof["email"].lower())
                        self._add_item(
                            EvidenceItem(
                                evidence_id=fid,
                                file_path=path,
                                origin=origin,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=res_id,
                                data_category="USER_PROFILE",
                                state=state,
                                identifiers=idents,
                                raw_details=f"account profile lookup status_code={code}",
                            )
                        )
                elif sys_id == "search_service":
                    for q in content.get("index_queries", []):
                        res_id = q.get("resource_id", "")
                        hits = q.get("hits", {}).get("total", 0)
                        docs = q.get("hits", {}).get("documents", [])
                        state = "PRESENT" if hits > 0 else "ABSENT"
                        idents = set()
                        if q.get("query"):
                            idents.add(q["query"].lower())
                        for d in docs:
                            if d.get("customer_reference"):
                                idents.add(d["customer_reference"])
                            if d.get("email"):
                                idents.add(d["email"].lower())
                        self._add_item(
                            EvidenceItem(
                                evidence_id=fid,
                                file_path=path,
                                origin=origin,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=res_id,
                                data_category="SEARCH_INDEX_ENTRY",
                                state=state,
                                identifiers=idents,
                                raw_details=f"search index query hits={hits}",
                            )
                        )
                elif sys_id == "analytics_platform":
                    for p in content.get("profiles", []):
                        res_id = p.get("resource_id", "")
                        email = p.get("email")
                        ref = p.get("customer_reference")
                        idents = set()
                        if email:
                            idents.add(email.lower())
                        if ref:
                            idents.add(ref)
                        state = "ANONYMIZED" if not email and not ref and not p.get("phone") else "PRESENT"
                        self._add_item(
                            EvidenceItem(
                                evidence_id=fid,
                                file_path=path,
                                origin=origin,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=res_id,
                                data_category="ANALYTICS_PROFILE",
                                state=state,
                                identifiers=idents,
                                raw_details="analytics profile read",
                            )
                        )
                elif sys_id == "integration_service":
                    for conn in content.get("connectors", []):
                        res_id = conn.get("resource_id", "")
                        enabled = conn.get("enabled", False)
                        state = "ACTIVE" if enabled else "DISABLED"
                        idents = set()
                        if conn.get("customer_email"):
                            idents.add(conn["customer_email"].lower())
                        if conn.get("customer_reference"):
                            idents.add(conn["customer_reference"])
                        self._add_item(
                            EvidenceItem(
                                evidence_id=fid,
                                file_path=path,
                                origin=origin,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=res_id,
                                data_category="DATA_FLOW",
                                state=state,
                                identifiers=idents,
                                raw_details=f"connector enabled={enabled}",
                            )
                        )
                elif sys_id == "backup_service":
                    for b in content.get("restore_entries", []):
                        res_id = b.get("resource_id", "")
                        allowed = b.get("restore_allowed", False)
                        state = "ACTIVE" if allowed else "BLOCKED"
                        idents = set()
                        if b.get("customer_email"):
                            idents.add(b["customer_email"].lower())
                        if b.get("customer_reference"):
                            idents.add(b["customer_reference"])
                        self._add_item(
                            EvidenceItem(
                                evidence_id=fid,
                                file_path=path,
                                origin=origin,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=res_id,
                                data_category="BACKUP_ARCHIVE",
                                state=state,
                                identifiers=idents,
                                raw_details=f"restore allowed={allowed}",
                            )
                        )
                elif sys_id == "security_service":
                    for rec in content.get("audit_records", []):
                        res_id = rec.get("resource_id", "")
                        idents = set()
                        if rec.get("subject_reference"):
                            idents.add(rec["subject_reference"])
                        self._add_item(
                            EvidenceItem(
                                evidence_id=fid,
                                file_path=path,
                                origin=origin,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=res_id,
                                data_category="SECURITY_AUDIT_LOG",
                                state="PRESENT",
                                identifiers=idents,
                                raw_details="retained security audit record",
                            )
                        )
                elif sys_id == "support_platform":
                    for t in content.get("tickets", []):
                        res_id = t.get("resource_id", "")
                        idents = set()
                        if t.get("customer_reference"):
                            idents.add(t["customer_reference"])
                        if t.get("requester_email"):
                            idents.add(t["requester_email"].lower())
                        email = t.get("requester_email")
                        name = t.get("requester_name")
                        phone = t.get("requester_phone")
                        state = "PRESENT" if (email or name or phone) else "REDACTED"
                        self._add_item(
                            EvidenceItem(
                                evidence_id=fid,
                                file_path=path,
                                origin=origin,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=res_id,
                                data_category="SUPPORT_MESSAGE",
                                state=state,
                                identifiers=idents,
                                raw_details=f"support ticket state={state}",
                            )
                        )
                elif sys_id == "export_service":
                    for exp in content.get("exports", []):
                        res_id = exp.get("resource_id", "")
                        idents = set()
                        if exp.get("owner_email"):
                            idents.add(exp["owner_email"].lower())
                        if exp.get("customer_reference"):
                            idents.add(exp["customer_reference"])
                        self._add_item(
                            EvidenceItem(
                                evidence_id=fid,
                                file_path=path,
                                origin=origin,
                                captured_at=captured_at,
                                system_id=sys_id,
                                resource_id=res_id,
                                data_category="USER_EXPORT",
                                state="PRESENT",
                                identifiers=idents,
                                raw_details="user export present",
                            )
                        )

        # Handle customer_data_snapshot_bundle files
        # Handle customer_data_snapshot_bundle files
        elif "snapshots" in data:
            for snap in data["snapshots"]:
                ds = snap.get("data_store", "")
                coll = snap.get("collection", "")
                for rec in snap.get("records", []):
                    res_id = rec.get("resource_id", "")
                    uid = rec.get("subject_reference") or rec.get("customer_reference") or rec.get("user_id") or ""
                    idents = set()
                    if uid:
                        idents.add(uid.lower())
                    document = rec.get("document") if isinstance(rec.get("document"), dict) else {}
                    for em_key in ["email", "customer_email", "owner_email", "requester_email"]:
                        value = rec.get(em_key) or document.get(em_key)
                        if value:
                            idents.add(value.lower())
                    for ref_key in ["customer_reference", "subject_reference", "user_id"]:
                        value = document.get(ref_key)
                        if value:
                            idents.add(value.lower())
                    if rec.get("phone"):
                        idents.add(rec["phone"])
                    if rec.get("full_name"):
                        idents.add(rec["full_name"].lower())
                    if rec.get("requester_name"):
                        idents.add(rec["requester_name"].lower())

                    if coll == "deleted_customer_references":
                        has_pii = bool(rec.get("email") or rec.get("name") or rec.get("phone") or rec.get("email_hash"))
                        state = "PRESENT" if has_pii else "REDACTED"
                        self._add_item(
                            EvidenceItem(
                                evidence_id=fid,
                                file_path=path,
                                origin=origin,
                                captured_at=captured_at,
                                system_id="identity_service",
                                resource_id=res_id,
                                data_category="ACCOUNT_TOMBSTONE",
                                state=state,
                                identifiers=idents,
                                raw_details=f"tombstone pii={has_pii}",
                            )
                        )
                    elif coll == "security_audit_events":
                        self._add_item(
                            EvidenceItem(
                                evidence_id=fid,
                                file_path=path,
                                origin=origin,
                                captured_at=captured_at,
                                system_id="security_service",
                                resource_id=res_id,
                                data_category="SECURITY_AUDIT_LOG",
                                state="PRESENT",
                                identifiers=idents,
                                raw_details="security audit event",
                            )
                        )
                    elif coll == "customer_profiles":
                        st = "PRESENT" if rec.get("account_status") in ("ACTIVE", "OPEN") else "ABSENT"
                        self._add_item(
                            EvidenceItem(
                                evidence_id=fid,
                                file_path=path,
                                origin=origin,
                                captured_at=captured_at,
                                system_id="account_service",
                                resource_id=res_id,
                                data_category="USER_PROFILE",
                                state=st,
                                identifiers=idents,
                                raw_details=f"snapshot profile status={rec.get('account_status')}",
                            )
                        )
                    elif coll == "customer_search_documents":
                        self._add_item(
                            EvidenceItem(
                                evidence_id=fid,
                                file_path=path,
                                origin=origin,
                                captured_at=captured_at,
                                system_id="search_service",
                                resource_id=res_id,
                                data_category="SEARCH_INDEX_ENTRY",
                                state="PRESENT",
                                identifiers=idents,
                                raw_details="snapshot search document",
                            )
                        )
                    elif coll == "customer_analytics_reports":
                        has_id = bool(rec.get("email") or rec.get("phone") or rec.get("customer_reference"))
                        st = "PRESENT" if has_id else "ANONYMIZED"
                        self._add_item(
                            EvidenceItem(
                                evidence_id=fid,
                                file_path=path,
                                origin=origin,
                                captured_at=captured_at,
                                system_id="analytics_platform",
                                resource_id=res_id,
                                data_category="ANALYTICS_PROFILE",
                                state=st,
                                identifiers=idents,
                                raw_details=f"snapshot analytics has_id={has_id}",
                            )
                        )
                    elif coll == "backup_catalog":
                        is_active = bool(rec.get("restore_allowed") or rec.get("status") == "ACTIVE")
                        st = "ACTIVE" if is_active else "BLOCKED"
                        self._add_item(
                            EvidenceItem(
                                evidence_id=fid,
                                file_path=path,
                                origin=origin,
                                captured_at=captured_at,
                                system_id="backup_service",
                                resource_id=res_id,
                                data_category="BACKUP_ARCHIVE",
                                state=st,
                                identifiers=idents,
                                raw_details=f"snapshot backup active={is_active}",
                            )
                        )
                    elif coll == "customer_export_jobs":
                        is_ready = rec.get("status") in ("READY", "Ready", "COMPLETED")
                        st = "PRESENT" if is_ready else "ABSENT"
                        self._add_item(
                            EvidenceItem(
                                evidence_id=fid,
                                file_path=path,
                                origin=origin,
                                captured_at=captured_at,
                                system_id="export_service",
                                resource_id=res_id,
                                data_category="USER_EXPORT",
                                state=st,
                                identifiers=idents,
                                raw_details=f"snapshot export status={rec.get('status')}",
                            )
                        )
                    elif coll == "connector_configurations":
                        is_enabled = bool(rec.get("enabled", True))
                        st = "ACTIVE" if is_enabled else "DISABLED"
                        self._add_item(
                            EvidenceItem(
                                evidence_id=fid,
                                file_path=path,
                                origin=origin,
                                captured_at=captured_at,
                                system_id="integration_service",
                                resource_id=res_id,
                                data_category="DATA_FLOW",
                                state=st,
                                identifiers=idents,
                                raw_details=f"snapshot connector enabled={is_enabled}",
                            )
                        )
                    elif coll == "support_conversations":
                        has_direct = bool(rec.get("requester_email") or rec.get("requester_name") or rec.get("requester_phone"))
                        st = "PRESENT" if has_direct else "REDACTED"
                        self._add_item(
                            EvidenceItem(
                                evidence_id=fid,
                                file_path=path,
                                origin=origin,
                                captured_at=captured_at,
                                system_id="support_platform",
                                resource_id=res_id,
                                data_category="SUPPORT_MESSAGE",
                                state=st,
                                identifiers=idents,
                                raw_details=f"snapshot support has_direct={has_direct}",
                            )
                        )

        # Handle flat collections (analytics reports, connector configs, export jobs)
        elif "records" in data:
            for rec in data["records"]:
                res_id = rec.get("resource_id") or rec.get("connector_id") or rec.get("export_id") or ""
                idents = set()
                uid = rec.get("user_id") or rec.get("customer_reference") or rec.get("subject_reference") or ""
                if uid:
                    idents.add(uid.lower())
                for em_key in ["email", "customer_email", "owner_email", "requester_email", "email_hash"]:
                    if rec.get(em_key):
                        idents.add(rec[em_key].lower())
                if rec.get("phone"):
                    idents.add(rec["phone"])

                sys_id = "account_service"
                cat = "USER_PROFILE"
                state = "PRESENT"

                if res_id.startswith("analytics_"):
                    sys_id = "analytics_platform"
                    cat = "ANALYTICS_PROFILE"
                    has_id = bool(rec.get("user_id") or rec.get("email") or rec.get("phone"))
                    state = "PRESENT" if has_id else "ANONYMIZED"
                elif res_id.startswith("data_flow_"):
                    sys_id = "integration_service"
                    cat = "DATA_FLOW"
                    state = "ACTIVE" if rec.get("enabled", True) else "DISABLED"
                elif res_id.startswith("export_"):
                    sys_id = "export_service"
                    cat = "USER_EXPORT"
                    is_ready = rec.get("download_available") is True or rec.get("status") in ("READY", "Ready", "COMPLETED")
                    state = "PRESENT" if is_ready else "ABSENT"
                elif res_id.startswith("audit_record_"):
                    sys_id = "security_service"
                    cat = "SECURITY_AUDIT_LOG"
                    state = "PRESENT"

                self._add_item(
                    EvidenceItem(
                        evidence_id=fid,
                        file_path=path,
                        origin=origin,
                        captured_at=captured_at,
                        system_id=sys_id,
                        resource_id=res_id,
                        data_category=cat,
                        state=state,
                        identifiers=idents,
                        raw_details=f"record item {res_id}",
                    )
                )

    def _ingest_txt(self, fid: str, path: str, origin: str, captured_at: str) -> None:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("- "):
                    continue
                parts = [p.strip() for p in line[2:].split("|")]
                if len(parts) >= 6:
                    t_str, sys_id, res_id, cat, raw_state, ident = parts[:6]
                    idents = {ident.lower()} if ident else set()
                    state_map = {
                        "NOT_FOUND": "ABSENT",
                        "FOUND": "PRESENT",
                        "IDENTIFIABLE": "PRESENT",
                        "ANONYMIZED": "ANONYMIZED",
                        "REDACTED": "REDACTED",
                        "ACTIVE": "ACTIVE",
                        "DISABLED": "DISABLED",
                        "BLOCKED": "BLOCKED",
                    }
                    st = state_map.get(raw_state, raw_state)
                    self._add_item(
                        EvidenceItem(
                            evidence_id=fid,
                            file_path=path,
                            origin=origin,
                            captured_at=captured_at,
                            system_id=sys_id,
                            resource_id=res_id,
                            data_category=cat,
                            state=st,
                            identifiers=idents,
                            raw_details=f"handover entry: {line}",
                        )
                    )

    def _ingest_log(self, fid: str, path: str, origin: str, captured_at: str) -> None:
        kv_regex = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s]+))')
        traces: Dict[str, List[dict]] = {}

        with open(path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f):
                line_str = line.strip()
                if not line_str:
                    continue
                kvs = {}
                idx = line_str.find("{")
                if idx != -1:
                    try:
                        kvs = json.loads(line_str[idx:])
                    except Exception:
                        pass
                if not kvs:
                    matches = kv_regex.findall(line_str)
                    kvs = {k: (v1 or v2) for k, v1, v2 in matches}
                if not kvs:
                    continue

                trace = kvs.get("trace_id") or kvs.get("requestId")
                if not trace:
                    m = re.search(r'\b(tr-[\w-]+|rb-[\w-]+)\b', line_str)
                    if m:
                        trace = m.group(1)

                trace_key = trace if trace else f"line_{line_no}"
                traces.setdefault(trace_key, []).append(kvs)

        for trace_key, group in traces.items():
            idents = set()
            for kvs in group:
                for key_name in [
                    "lookup_key", "match_key", "subject_key", "subject_ref",
                    "correlation_key", "matched_value", "email", "customer_email",
                    "owner_key", "scan_key", "customer_reference", "user_id"
                ]:
                    val = kvs.get(key_name)
                    if val and val != "null":
                        idents.add(val.lower())

            # Find all resource_ids in group
            res_items = []
            for kvs in group:
                res_id = kvs.get("resource_id", "")
                if res_id:
                    res_items.append((res_id, kvs))

            if not res_items:
                continue

            for res_id, kvs in res_items:
                sys_id = kvs.get("service") or kvs.get("target_system") or ""
                event = kvs.get("event", "")
                cat = "USER_PROFILE"
                state = "PRESENT"

                if res_id.startswith("account_"):
                    sys_id = "account_service"
                    cat = "USER_PROFILE"
                    is_absent = any(k.get("rows") == "0" or k.get("http_status") == "404" for k in group)
                    state = "ABSENT" if is_absent else "PRESENT"
                elif res_id.startswith("search_"):
                    sys_id = "search_service"
                    cat = "SEARCH_INDEX_ENTRY"
                    is_hit = any(k.get("result") == "hit" or (k.get("total_hits") and k.get("total_hits") != "0") for k in group)
                    state = "PRESENT" if is_hit else "ABSENT"
                elif res_id.startswith("support_"):
                    sys_id = "support_platform"
                    if any(k.get("source") == "legacy_contact_index" for k in group):
                        # A legacy contact-index lookup stores a secondary
                        # identifier, not a retained support conversation.
                        cat = "SECONDARY_IDENTIFIER"
                        state = "PRESENT"
                    elif "attachment" in event or any("attachment" in k.get("event", "") for k in group):
                        cat = "SUPPORT_ATTACHMENT"
                        state = "PRESENT"
                    else:
                        cat = "SUPPORT_MESSAGE"
                        has_direct = any(bool(k.get("matched_value") or k.get("requester_email")) for k in group) or any(k.get("marker_found") == "false" for k in group)
                        state = "PRESENT" if has_direct else "REDACTED"
                elif res_id.startswith("analytics_"):
                    sys_id = "analytics_platform"
                    if any(k.get("email_opt_in") not in (None, "null") for k in group):
                        # Explicit marketing-consent fields make this a
                        # marketing profile even when the event was emitted by
                        # the analytics platform.
                        cat = "MARKETING_PROFILE"
                        state = "PRESENT"
                    else:
                        cat = "ANALYTICS_PROFILE"
                        id_fields = ["email", "phone", "customer_reference", "email_hash", "correlation_key"]
                        has_id = any(bool(k.get(f)) and k.get(f) != "null" for k in group for f in id_fields)
                        state = "PRESENT" if has_id else "ANONYMIZED"
                elif res_id.startswith("audit_record_"):
                    sys_id = "security_service"
                    cat = "SECURITY_AUDIT_LOG"
                    state = "PRESENT"
                elif res_id.startswith("data_flow_"):
                    sys_id = "integration_service"
                    cat = "DATA_FLOW"
                    enabled = any(k.get("enabled") in ("true", True) or k.get("last_delivery_status") == "delivered" for k in group)
                    state = "ACTIVE" if enabled else "DISABLED"
                elif res_id.startswith("backup_"):
                    sys_id = "backup_service"
                    cat = "BACKUP_ARCHIVE"
                    is_active = any(k.get("restore_allowed") in ("true", True) or (k.get("eligible") in ("true", True) and k.get("deletion_block") in ("false", False)) for k in group)
                    state = "ACTIVE" if is_active else "BLOCKED"
                elif res_id.startswith("tombstone_"):
                    sys_id = "identity_service"
                    cat = "ACCOUNT_TOMBSTONE"
                    has_pii = any(bool(k.get("email") or k.get("phone") or k.get("name") or k.get("email_hash")) for k in group)
                    state = "PRESENT" if has_pii else "REDACTED"
                elif res_id.startswith("export_"):
                    sys_id = "export_service"
                    cat = "USER_EXPORT"
                    state = "PRESENT" if any(k.get("available") in ("true", True) or k.get("status") in ("READY", "Ready") for k in group) else "ABSENT"

                self._add_item(
                    EvidenceItem(
                        evidence_id=fid,
                        file_path=path,
                        origin=origin,
                        captured_at=captured_at,
                        system_id=sys_id,
                        resource_id=res_id,
                        data_category=cat,
                        state=state,
                        identifiers=idents,
                        raw_details=f"trace={trace_key} res={res_id} state={state}",
                    )
                )

    def _ingest_pdf(self, fid: str, path: str, origin: str, captured_at: str) -> None:
        if not pypdf:
            return
        try:
            reader = pypdf.PdfReader(path)
            full_text = " ".join(p.extract_text() for p in reader.pages)
        except Exception:
            return

        # Extract user_ids, emails, resource_ids, orders
        emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', full_text)
        user_ids = re.findall(r'user_\d+', full_text)
        support_ids = re.findall(r'support_\d+', full_text)
        audit_ids = re.findall(r'audit_record_\d+', full_text)

        idents = set(e.lower() for e in emails) | set(user_ids)

        if "DELIVERY ADDRESS CORRECTION" in full_text and support_ids:
            for s_id in support_ids:
                self._add_item(
                    EvidenceItem(
                        evidence_id=fid,
                        file_path=path,
                        origin=origin,
                        captured_at=captured_at,
                        system_id="support_platform",
                        resource_id=s_id,
                        data_category="SUPPORT_ATTACHMENT",
                        state="PRESENT",
                        identifiers=idents,
                        raw_details="support delivery address correction pdf attachment",
                    )
                )
        elif "COMPLIANCE JOURNAL" in full_text and audit_ids:
            for a_id in audit_ids:
                self._add_item(
                    EvidenceItem(
                        evidence_id=fid,
                        file_path=path,
                        origin=origin,
                        captured_at=captured_at,
                        system_id="security_service",
                        resource_id=a_id,
                        data_category="SECURITY_AUDIT_LOG",
                        state="PRESENT",
                        identifiers=idents,
                        raw_details="compliance journal extract pdf",
                    )
                )

    def get_evidence_for_case(self, user_graph, audit_at: str) -> List[EvidenceItem]:
        """
        Retrieves all evidence items relevant to the given user that were captured
        at or before the audit_at cutoff. Evidence captured after audit_at is strictly excluded.
        """
        results: List[EvidenceItem] = []
        seen = set()

        # Collect candidate items by user identifiers
        candidate_items = []
        if user_graph:
            if user_graph.user_id.lower() in self.items_by_identifier:
                candidate_items.extend(self.items_by_identifier[user_graph.user_id.lower()])
            for em in user_graph.emails:
                if em in self.items_by_identifier:
                    candidate_items.extend(self.items_by_identifier[em])
            for ph in user_graph.phones:
                if ph in self.items_by_identifier:
                    candidate_items.extend(self.items_by_identifier[ph])
            for h in user_graph.email_hashes:
                if h in self.items_by_identifier:
                    candidate_items.extend(self.items_by_identifier[h])

        for item in candidate_items:
            # Strict temporal check: captured_at <= audit_at
            if item.captured_at <= audit_at:
                key = (item.evidence_id, item.system_id, item.resource_id, item.state)
                if key not in seen:
                    seen.add(key)
                    results.append(item)

        return results
