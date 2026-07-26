# Security Policy

## Scope

**In scope — please report these:**
- Smart contract vulnerabilities (reentrancy, fund loss, logic errors in vault/rebalance/offramp)
- Authentication or authorization bypass
- Data exposure (user PII, private keys, JWT secrets)
- Injection attacks (SQL, command, XSS with financial impact)
- Privilege escalation in the API or admin endpoints
- Cryptographic weaknesses

**Out of scope — do not report these as security issues:**
- Feature requests or general usability bugs
- UI/styling issues with no security impact
- Rate-limiting on non-sensitive endpoints
- Issues requiring physical access to a user's device
- Self-XSS or social engineering attacks

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.** Doing so exposes users before a fix is available.

Instead, use one of the following:

1. **GitHub Private Vulnerability Reporting** (preferred) — click **"Report a vulnerability"** under the Security tab of this repository.
2. **Email** — send a report to **security@nester.dev** with the subject line `[SECURITY] <brief description>`.

### What to include in your report

- Affected component (smart contract name, API endpoint, service)
- Description of the vulnerability and its potential impact
- Step-by-step reproduction instructions
- Any proof-of-concept code or screenshots (if safe to share)
- Your severity assessment (Critical / High / Medium / Low)

## Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 1 week |
| Fix or mitigation | Depends on severity (Critical: ASAP, High: 2 weeks, Medium/Low: next release) |
| Public disclosure | Coordinated with reporter after fix is deployed |

## Severity Classification

| Severity | Examples |
|----------|---------|
| **Critical** | Smart contract funds at risk, private key exposure, complete auth bypass |
| **High** | Privilege escalation, significant PII data breach, DoS of critical services |
| **Medium** | Limited data exposure, partial auth weakness, DoS of non-critical services |
| **Low** | Information disclosure, best-practice violations with minimal impact |

## Known and Accepted Vulnerabilities

We maintain a list of known vulnerabilities in our dependency chain that we have assessed and accepted based on their risk profile:

| ID | Module | Severity | Reason | Status |
|----|--------|----------|--------|--------|
| **GO-2026-4316** | `github.com/go-chi/chi` | Medium | Open redirect in unused `RedirectSlashes` middleware. Transitive dependency via `github.com/stellar/go-stellar-sdk`. Middleware not used in codebase. Waiting for upstream fix. | Accepted |

**Mitigation strategy:** Our CI/CD pipeline (`govulncheck` step in `.github/workflows/security.yml`) explicitly allows known accepted vulnerabilities and only fails on new or unreviewed vulnerabilities.

To report a vulnerability not listed here, see [Reporting a Vulnerability](#reporting-a-vulnerability) above.

## Safe Harbor

Nester commits to not pursuing legal action against security researchers who:

- Report vulnerabilities through this policy in good faith
- Avoid accessing, modifying, or deleting user data beyond what is necessary to demonstrate the issue
- Do not disrupt production services or degrade user experience during testing
- Give us reasonable time to resolve the issue before public disclosure

## Recognition

We maintain a Hall of Fame for researchers who responsibly disclose valid security issues. Credit will be given in the relevant release notes and security advisory unless you prefer to remain anonymous.


We do not currently operate a paid bug bounty program, but we appreciate and publicly recognize all valid reports.

---

## Tamper-Evident Audit Log (Issue #834)

### Overview

Nester maintains a cryptographically hash-chained audit log for all security-relevant actions (admin operations, role changes, fund movements, configuration changes, authentication events). The goal is to make silent modification or deletion of log entries **detectable** even by a compromised database or malicious insider.

### Integrity Model

Each audit log entry includes four chain fields in addition to the standard event payload:

| Field | Description |
|-------|-------------|
| `sequence` | Strictly monotone integer assigned under a serializable transaction + mutex. No gaps are allowed. |
| `prev_hash` | SHA-256 of the canonical serialization of the **previous** entry (empty for entry #1). |
| `entry_hash` | SHA-256 of this entry's canonical serialization, including `prev_hash`. |
| `anchored` / `anchor_tx_hash` | Whether the entry's hash has been recorded outside the DB (file log today; Stellar chain in production). |

**Hash input canonical form** — deterministic JSON serialization (sorted keys):
```
SHA256( JSON({sequence, prev_hash, actor, action, target, detail, timestamp}) )
```

### Chain Construction

Entries are written inside a **`SERIALIZABLE`** isolation-level transaction and guarded by an in-process `sync.Mutex`. This ensures:

1. No two goroutines can race on the sequence counter.
2. The database rejects non-serial concurrent writes.
3. Every new entry's `prev_hash` exactly matches the `entry_hash` of the previous entry.

### Verification

The `AuditService.VerifyChain(ctx, fromSeq, toSeq)` method:
1. Fetches entries in sequence order from `fromSeq` to `toSeq`.
2. Detects **sequence gaps** (a gap means an entry was deleted).
3. Recomputes each `entry_hash` from the raw fields and compares it to the stored value. A mismatch means the entry was modified.
4. Checks `prev_hash` linkage across entries.

Returns `(ok bool, brokenAtSeq int64, err error)` — when `ok=false`, `brokenAtSeq` is the sequence number where the first break was detected.

### Background Verification Job

`scheduler.AuditChainVerifier` runs on a configurable interval (default: 30 minutes). On each tick it calls `VerifyChain` over the entire table. If a break is found, it calls `ChainBreakAlerter.AlertChainBreak` — in production this should page on-call.

**Environment variables:**
```
AUDIT_VERIFIER_ENABLED=true
AUDIT_VERIFIER_INTERVAL_MINUTES=30
```

### On-Demand Operator Verification

Administrators can trigger a one-shot integrity check via:
```
GET /api/v1/admin/audit/verify
Authorization: Bearer <admin JWT>
```

**Response (intact chain):**
```json
{ "chain_ok": true, "broken_at_sequence": 0 }
```

**Response (break detected):**
```json
{ "chain_ok": false, "broken_at_sequence": 7, "error": "entry_hash mismatch at sequence 7" }
```

### Redaction

Sensitive fields (e.g. plaintext tokens inadvertently logged) can be redacted via `AuditService.RedactEntry`. Redaction:
- Replaces the targeted field value with `"[REDACTED]"` in `detail`.
- Sets `redacted = true` on the entry.
- Appends a **new** `REDACTION` audit entry (which is itself chained), so the redaction event is itself tamper-evident.
- The **original `entry_hash` is preserved** so historical chains that reference this entry remain verifiable.

### Anchoring

The latest entry's hash can be anchored outside the database via `AuditService.AnchorLatestEntry`:
- **MVP**: Written to an append-only local file (`AUDIT_ANCHOR_FILE_PATH`).
- **Production target**: Published to a Stellar ledger transaction via `apps/api/internal/stellar/invoker.go`.

Once anchored, the `anchored = true` and `anchor_tx_hash` are set. Any later modification of the anchored entry can be proved fraudulent by comparing against the external anchor.

### Threat Model and Limitations

| Threat | Mitigation |
|--------|------------|
| DBA deletes a row | Sequence gap detected on next `VerifyChain` call |
| DBA modifies a field | Hash mismatch detected on next `VerifyChain` call |
| DBA recomputes hash after modification | `prev_hash` chain breaks on the following entry; or anchored hash in Stellar is contradicted |
| Attacker reconstructs entire chain | Requires control of all external anchors and all on-chain Stellar transactions |
| In-process race / dual-write | Prevented by `sync.Mutex` + `SERIALIZABLE` transaction |

> **Note:** The hash-chained model provides **tamper evidence**, not full **tamper prevention**. A sufficiently privileged attacker who can also rewrite the anchor store could still forge entries. Full prevention requires HSM-backed signing, which is tracked as a future enhancement.
