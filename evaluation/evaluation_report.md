# Ghost Data Still Exists: Evaluation Report

**HackerRank Orchestrate (October 2026)**  
**Challenge:** Ghost Data Still Exists  
**Component:** AI-Powered Deletion-Audit Agent

---

## 1. Executive Summary

This evaluation report documents the empirical performance, architectural methodology, failure modes, diagnostic sample comparison, and custom regression evaluations of the `Ghost Data Still Exists` deletion-audit engine.

The engine conducts an end-to-end audit of deletion requests by:
1. Classifying user intent across multi-lingual and ambiguous request texts to distinguish deletion requests from Subject Access Requests (SARs), rectifications, or marketing opt-outs.
2. Resolving current and historical identifiers across aliases, phone numbers, and SHA-256 email hashes into a canonical `UserIdentityGraph`.
3. Ingesting multi-modal participant evidence (SQL snapshot replicas, structured JSON documents, log files, text records, and PDF documents) strictly respecting each case's `audit_at` temporal cutoff.
4. Applying the 15 statutory deletion rules from `deletion_rules.csv` to partition records into compliant versus policy-violating states.
5. Deterministically generating strictly ordered remediation plans and evidence-backed verification sequences serialized to CSV.

---

## 2. Public Sample Benchmark & Diagnostic Analysis

Evaluation on `dataset/sample_deletion_requests.csv` against `dataset/sample_output.csv` (32 requests):

| Metric | Measured Value | Percentage | Details |
|---|---|---|---|
| **Case-Level Status Accuracy** | **29 / 32** | **90.6%** | Evaluated on participant-visible evidence |
| **Exact Row String Agreement** | **10 / 32** | **31.2%** | Exact byte-for-byte match with sample CSV |
| **Parsed `steps_json` Exact Agreement** | **12 / 32** | **37.5%** | Identical array of step dictionaries |
| **Structural Step Sequence Agreement** | **12 / 32** | **37.5%** | Identical `(phase, operation, system_id, resource_id)` |
| **Permanent Unit & Regression Suite** | **115 / 115** | **100%** | Passing in 2.781s |

### Diagnostic Analysis of the 20 Sample Mismatches

The public sample comparison served as an essential diagnostic tool to audit the boundary between grounded evidence and synthetic sample generator artifacts:

1. **Ungrounded Account IDs (18 cases)**:
   - *Cases*: `case_01`, `case_02`, `case_04`, `case_07`, `case_08`, `case_10`, `case_18`, `case_20`, `case_21`, `case_22`, `case_23`, `case_25`, `case_27`, `case_28`, `case_29`, `case_30`, `case_31`, `case_32`.
   - *Root Cause*: The generator's expected output cites `account_xxx` resources. However, in the participant-visible dataset files under `dataset/`, those account IDs are absent, or appear only in multi-tenant batch operations in `system_activity.csv` alongside unrelated users without user identifiers.
   - *Resolution*: Earlier versions attempted an ungrounded heuristic (`user_num <= 10` guess and batch window scanning). Per `AGENTS.md` §6.6 ("Treat activity logs, workflow statuses, and system messages as claims unless the available evidence establishes the resulting state", "Do not infer case membership from the manifest alone"), this heuristic was removed. Resources are only associated when participant-visible evidence supports the relationship.
   - *Case 06 Grounding*: In `case_06`, search document metadata (`search_001` linking to `account_006`) provides grounded two-hop evidence to verify `account_006` absent in post-remediation verification, achieving 100% parsed step agreement without heuristics.

2. **Decoupled Anonymized Analytics Records (7 cases)**:
   - *Cases*: `case_03` (`analytics_9406`), `case_04` (`analytics_901`), `case_21` (`analytics_5335`), `case_25` (`analytics_1895`), `case_26` (`analytics_4566`), `case_27` (`analytics_4574`), `case_28` (`analytics_6077`).
   - *Root Cause*: In the evidence files, these analytics records have already been irreversibly anonymized per Rule 07: direct identifiers (`email`, `phone`, `customer_reference`) are `null`.
   - *Resolution*: Because all identifiers were removed, the records can no longer be linked to the user at `audit_at`. Attributing them would require ungrounded guessing.

3. **Non-Existent Security Audit Records (2 cases)**:
   - *Cases*: `case_18` (`audit_record_6645`), `case_20` (`audit_record_5569`).
   - *Root Cause*: These security audit records do not exist anywhere in `dataset/evidence/` or participant-facing dataset files; they appear only in `dataset/sample_output.csv`.
   - *Resolution*: Strictly adhering to participant evidence. Verified records `audit_record_4902` (`case_09`), `audit_record_7095` (`case_24`), `audit_record_4128` (`case_23`), `audit_record_3954` (`case_29`), and `audit_record_1707` (`case_30`) were successfully grounded through snapshot timestamp and log event timestamp fixes.


---

## 3. Full Evaluation Dataset Results (518 Requests)

Execution of `code/main.py` across all 518 evaluation requests in `dataset/deletion_requests.csv` generated root `output.csv`. Full validation confirms 100% conformance to challenge schema and rules:

- **Total Requests Evaluated**: 518
- **Total Valid Output Rows**: 518
- **Unique `case_id` Alignment**: 100% (sorted identically to input)
- **CSV Header**: `case_id,deletion_status,steps_json`
- **Total Steps Emitted**: 2,714 steps

### Status Distribution

| Status | Count | Percentage | Description |
|---|---|---|---|
| `INCOMPLETE` | 373 | 72.0% | Genuine deletion requests with unfulfilled policy requirements or remaining evidence |
| `COMPLETE` | 135 | 26.1% | Verified complete deletions with evidence-backed compliance at `audit_at` |
| `NOT_APPLICABLE` | 10 | 1.9% | Access requests, data rectification, or marketing opt-outs (`steps_json=[]`) |

### Step and Field Validation Metrics

- **JSON Validity**: 100% (518 / 518 rows parse without errors)
- **Step Numbering**: 100% consecutively numbered starting at `step_no: 1`
- **Phase Ordering**: 100% strictly ordered: `FINDING` $\rightarrow$ `REMEDIATION` $\rightarrow$ `VERIFICATION`
- **Operation & State Invariants**: 100% compliant with §6.4:
  - Findings cite participant-visible `evidence_id`.
  - Incomplete remediation and post-remediation verification steps have empty `evidence_id: ""`.
  - Complete verification steps cite valid, non-empty `evidence_id`.
  - Non-applicable cases contain empty arrays `[]`.

---

## 4. Participant-Created Custom Evaluation Cases

To test edge cases beyond the public sample, three comprehensive test cases were designed and added to the regression suite:

### Custom Case 1: Active Data Flow Race Condition (`case_custom_01`)
- **Intent**: DELETION
- **Scenario**: Requester submitted an authorized deletion request. The user account profile in `account_service` was successfully removed. However, `integration_service` contains an active data flow (`data_flow_8812`) configured to synchronize customer records nightly from an unpurged partner replica.
- **Expected Status**: `INCOMPLETE`
- **Evaluated Output**:
  1. `FINDING`: `integration_service`, `data_flow_8812`, `REPORT_ACTIVE_DATA_FLOW`, state `ACTIVE`, citing `evidence_id`.
  2. `REMEDIATION`: `integration_service`, `data_flow_8812`, `DISABLE_DATA_FLOW`, state `DISABLED`.
  3. `VERIFICATION`: `integration_service`, `data_flow_8812`, `VERIFY_DATA_FLOW_DISABLED`, state `DISABLED`.
  4. `VERIFICATION`: `account_service`, `account_088`, `VERIFY_RECORD_ABSENT`, state `ABSENT`.
- **Result**: PASSED. Confirms data flows are halted before verification and cannot recreate data.

### Custom Case 2: Account Tombstone with Leaked PII (`case_custom_02`)
- **Intent**: DELETION
- **Scenario**: Platform preserved an account tombstone (`tombstone_771`) in `identity_service` to maintain referential integrity. However, while the email was removed, the customer's phone number was inadvertently retained in the tombstone payload.
- **Expected Status**: `INCOMPLETE`
- **Evaluated Output**:
  1. `FINDING`: `identity_service`, `tombstone_771`, `REPORT_EXPOSED_PII`, state `PRESENT`, citing `evidence_id`.
  2. `REMEDIATION`: `identity_service`, `tombstone_771`, `REDACT_RECORD`, state `REDACTED`.
  3. `VERIFICATION`: `identity_service`, `tombstone_771`, `VERIFY_RECORD_REDACTED`, state `REDACTED`.
- **Result**: PASSED. Confirms tombstones are audited for prohibited direct identifiers.

### Custom Case 3: Subject Access Request (SAR) (`case_custom_03`)
- **Intent**: NOT DELETION
- **Scenario**: Requester writes: *"Please provide an export of all my personal data and past order invoices stored on your platform under GDPR Article 15."*
- **Expected Status**: `NOT_APPLICABLE`
- **Evaluated Output**: `NOT_APPLICABLE` with `steps_json=[]`.
- **Result**: PASSED. Confirms non-deletion intents are cleanly rejected without emitting findings or remediation.

---

## 5. Failures Found and Engineering Improvements

1. **PDF Evidence Parsing Defect**:
   - *Failure*: Ingestion of PDF files (`evidence_55`, `evidence_58`) was initially blocked due to missing `pypdf` in the runtime environment.
   - *Fix*: Installed `pypdf-6.21.2` in `/Users/shauryatiwari/.venv`. Implemented robust multi-page text extraction in `code/evidence.py` indexing `audit_record_003` and `support_001`.
2. **Ungrounded Account Synthesis Removal**:
   - *Failure*: An earlier heuristic guessed `account_001..010` based on `user_num` and matched arbitrary deletion worker events from concurrent batches in `system_activity.csv`.
   - *Fix*: Removed all synthetic account generation. Enforced strict evidence provenance: records are only linked if participant-visible evidence explicitly references the user's current or historical identity tokens.
3. **Audit Cutoff Boundary Enforcement**:
   - *Failure*: Observations captured after `audit_at` were previously leaking into resource state resolution.
   - *Fix*: Enforced filtering on `captured_at <= audit_at` during evidence aggregation, ensuring snapshot truth is fixed at audit cutoff.
4. **Deterministic CSV & JSON Serialization**:
   - *Failure*: Default `json.dumps()` introduced extraneous whitespace, and dictionary iteration caused variable key ordering.
   - *Fix*: Standardized serialization with `separators=(',', ':')` and `sort_keys=True`, guaranteeing deterministic, byte-level output stability.
5. **Log Record Escaped Quote Ingestion Defect**:
   - *Failure*: In `_ingest_log`, 343 records in `dataset/evidence/logs/` contained embedded escaped quotes (e.g. `correlation_key=\"user_261\"` and `resource_id=\"audit_record_6863\"`), leaving unstripped literal backslashes and quotes that prevented token matching.
   - *Fix*: Standardized log parsing to strip escaped quotes from extracted key-value pairs, resolving 72 previously unlinked evidence steps across the evaluation dataset.
6. **Two-Hop Source Account Post-Remediation Verification & POSIX LF Line Endings**:
   - *Failure*: Incomplete cases where dependent resources (e.g. search documents) reference an upstream source account omitted the post-remediation verification assertion for the source account, causing parsed step divergence on `case_06`. Additionally, default CSV writer line terminators could emit platform-dependent CRLF line endings.
   - *Fix*: Added two-hop source account verification linking in `code/audit.py` to ensure dependent accounts are verified absent post-remediation. Standardized CSV output with `lineterminator="\n"`, locking in contract compliance and adding regression tests (`test_two_hop_source_resource_id_linking`, `test_post_remediation_verification_contract`, `test_exact_row_and_parsed_json_key_order_contract`) for 115 total passing tests.


