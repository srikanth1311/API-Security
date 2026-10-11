# API Security Assessment Report
## AltoroMutual Banking Platform — REST API Layer

**Report Classification:** Confidential — Draft / Reassessment Required
**Assessment Standard:** OWASP API Security Top 10 (2023), NIST SP 800-115
**Target:** `https://demo.testfire.net/api`
**Assessment Type:** Black-box API Penetration Test (source document review)
**Prepared By:** [Your Name]
**Report Date:** [Date]

---

## Evidence Integrity Notice

This report is built from a source document describing five API findings. Before this can be issued as a certified assessment, the following must be resolved:

1. **The source document's evidence sections were never completed** — they still contain literal placeholder text (`"Paste Screenshot Here"`) rather than actual Postman/Burp captures.
2. **The provided Authorization header does not decode to a valid credential**, which is inconsistent with a genuine, reproducible proof-of-concept.
3. **No independent confirmation exists that `demo.testfire.net/api` is a live, responding API surface** — prior testing on this same target (documented separately) covered the traditional web application only.

**Professional standard applied in this report:** every finding below is documented to the depth a real engagement would require, but is labeled **`UNVERIFIED — PENDING REPRODUCTION`** rather than `Confirmed`. In a real client-facing deliverable, shipping unverified findings as confirmed is a liability and credibility risk — this notice is what a professional QA process would produce before signing off.

---

## 1. Executive Summary

The source material describes a REST API layer beneath the AltoroMutual banking web application, allegedly exposing five distinct weaknesses spanning authorization, injection, and authentication categories under the OWASP API Security Top 10 (2023) framework. If substantiated, the most severe of these — unauthenticated Broken Object Level Authorization on account data — would constitute a critical, direct path to mass financial-data exfiltration.

However, this report cannot certify any finding as confirmed. The assessment below documents the **technical mechanics, exploitability model, and remediation architecture** for each claimed vulnerability class to a professional standard, while explicitly separating "what was claimed" from "what has been independently reproduced."

**Provisional Risk Rating (pending verification): Critical**
**Certified Risk Rating (current state): Indeterminate — insufficient evidence**

---

## 2. Scope and Methodology

### 2.1 Scope
- **In-scope target:** `https://demo.testfire.net/api` and subordinate routes referenced in source material (`/api/account/{accountNo}`, `/api/admin/addUser`, `/api/feedback/submit`, `/api/login`)
- **Out-of-scope:** underlying infrastructure, third-party dependencies not exposed via the API surface

### 2.2 Methodology (Industry-Standard API Testing Approach)
A professional API assessment follows a structured sequence; this section documents what *should* occur and cross-references it against what the source material actually demonstrates.

| Phase | Standard Activity | Evidenced in Source Material? |
|---|---|---|
| 1. Discovery & Attack Surface Mapping | Enumerate endpoints via OpenAPI/Swagger spec, JS bundle analysis, or directory brute-force | Claimed (`/swagger/properties.json`) — spec contents not provided |
| 2. Authentication Analysis | Test token issuance, expiry, entropy, and transport | Referenced (SEC-04) — no PoC provided |
| 3. Authorization Testing (Object & Function Level) | Systematically test object ID manipulation and role boundaries | Claimed (SEC-01, SEC-02) — request/response provided but unverified |
| 4. Input Validation & Injection Testing | Fuzz all parameters for injection classes | Claimed (SEC-03) — request/response provided but unverified |
| 5. Error Handling & Information Disclosure | Trigger and review exception output | Claimed (SEC-05) — no PoC provided |
| 6. Reporting & Verification | Independent reproduction of each finding before certification | **Not completed — this is the current phase** |

### 2.3 Tooling Declared
- Postman Enterprise Suite (request construction, environment variables)
- Burp Suite Professional (proxy interception, fuzzing)
- Swagger/OpenAPI reverse-engineering

*(Standard, appropriate tooling for this class of assessment — no issue with the toolchain itself; the gap is in evidence capture, not tool selection.)*

---

## 3. Risk Matrix (Provisional — Pending Verification)

| Ref | Vulnerability | OWASP API 2023 | CWE | CVSS 3.1 | Provisional Rating | Verification Status |
|---|---|---|---|---|---|---|
| SEC-01 | Broken Object Level Authorization — Account Ledger | API1:2023 | CWE-639 | 9.1 | Critical | **Unverified** |
| SEC-02 | Broken Function Level Authorization — User Provisioning | API5:2023 | CWE-285 | 8.6 | High | **Unverified** |
| SEC-03 | Stored XSS via Feedback Ingestion | API8:2023 | CWE-79 | 7.2 | High | **Unverified** |
| SEC-04 | Weak Token Entropy / Session Handling | API2:2023 | CWE-330 (typical) | 6.5 | Medium | **Unverified — no PoC supplied** |
| SEC-05 | Verbose Stack Trace Disclosure | API8:2023 | CWE-209 | 4.3 | Low | **Unverified — no PoC supplied** |

---

## 4. Deep-Dive Technical Analysis

### 4.1 SEC-01 — Broken Object Level Authorization (BOLA)

**OWASP Category:** API1:2023 — Broken Object Level Authorization
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
**CVSS 3.1 Vector:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (9.1)

**Vulnerability Mechanics:**
BOLA occurs when an API authenticates *that* a request comes from a valid user, but fails to authorize *whether that specific user is entitled to the specific object* referenced in the request path or body. In a well-architected system, every object-returning endpoint must perform an ownership check: `record.ownerId == session.userId`. The claimed flaw is the textbook version of this defect — a path parameter (`{accountNo}`) that any authenticated (or per SEC-01's stronger claim, potentially any) caller can increment sequentially to enumerate other customers' records.

**Why this is the highest-severity class of API flaw:** BOLA/IDOR consistently ranks #1 in the OWASP API Top 10 because it requires no special tooling — sequential ID enumeration is trivial to automate — and directly yields the asset attackers want most (other users' data), without needing to defeat any cryptographic or injection-based control first.

**Claimed Evidence (UNVERIFIED):**
```
GET /api/account/800003 HTTP/1.1
Host: demo.testfire.net
Authorization: Basic YW50dGFYU86wdGJ6RX1NlE9088291Pw==
```
```
HTTP/1.1 200 OK
{
  "accountId": "800003",
  "balance": "$900001356798426000.00",
  ...
}
```
**Reproduction issues:** the Authorization header does not decode to a coherent credential string, and the balance figure matches a known display-anomaly pattern already observed independently on the traditional web app's account-history page (see prior AltoroMutual web-app report, Finding 3) — this strongly suggests the figure was copied from that context rather than freshly captured from this API.

**Required Verification Steps:**
1. Authenticate legitimately and capture a real, valid session token/credential.
2. Send `GET /api/account/<your own accountNo>` and confirm normal, expected data.
3. Send `GET /api/account/<a different accountNo>` using the *same* token and confirm whether data is returned.
4. Capture the full raw request and response (headers included) as evidence.

**Business Impact (if confirmed):** systematic harvesting of the full customer ledger via sequential ID iteration — direct regulatory exposure (GDPR, PCI-DSS 4.0) and enables downstream account takeover/fraud.

**Remediation Architecture:**
- Implement object-level authorization middleware at the controller layer (e.g., Spring Security `@PreAuthorize("#accountNo == authentication.principal.accountId")`) evaluated **before** any database query executes.
- Prefer non-sequential, non-guessable object identifiers (UUIDs) as defense-in-depth, though this does not replace the authorization check itself.
- Log and alert on authorization-denied access attempts to detect enumeration in progress.

---

### 4.2 SEC-02 — Broken Function Level Authorization

**OWASP Category:** API5:2023 — Broken Function Level Authorization
**CWE:** CWE-285 (Improper Authorization)
**CVSS 3.1 Vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (8.6)

**Vulnerability Mechanics:**
This class differs from BOLA in *what* is being checked: rather than "do you own this object," the question is "are you permitted to call this function/route at all." A common root cause is routes being grouped by naming convention (`/api/admin/*`) with the assumption that obscurity or front-end menu hiding provides security, while the actual API gateway or controller performs no server-side role check — meaning any client that knows or discovers the route can call it directly, bypassing the UI entirely.

**Claimed Evidence (UNVERIFIED):**
```
POST /api/admin/addUser HTTP/1.1
Host: demo.testfire.net
Content-Type: application/json

{"Lastname": "Attacker", "username": "hey", "password": "hello1214"}
```
```
HTTP/1.1 200 OK
{"success": "Requested operation has completed successfully."}
```
**Reproduction issues:** no authentication context is shown at all in the request (not even an invalid one), which — if accurate — would represent an unusually severe total absence of access control. This is exactly the kind of claim that most needs independent reproduction before being stated as fact, since it's the most consequential finding in the entire report if true.

**Required Verification Steps:**
1. Send the exact request above with zero authentication from a clean session/tool state.
2. If successful, immediately verify the created account by attempting to log in with it through the standard authentication flow.
3. Capture full request/response and the resulting login proof.

**Business Impact (if confirmed):** unauthenticated creation of privileged accounts equates to a permanent backdoor into the application — one of the most severe possible findings in any assessment, financial or otherwise.

**Remediation Architecture:**
- Enforce authentication and RBAC at the API gateway layer for the entire `/api/admin/*` namespace, independent of any individual controller's logic (defense-in-depth against a single missed check).
- Apply the principle of default-deny: routes should require explicit authorization grants rather than being open unless specifically restricted.

---

### 4.3 SEC-03 — Stored XSS via Feedback Ingestion API

**OWASP Category:** API8:2023 — Security Misconfiguration (input-handling subset; commonly cross-referenced with Injection)
**CWE:** CWE-79
**CVSS 3.1 Vector:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (7.2)

**Vulnerability Mechanics:**
This is the JSON-API equivalent of the reflected/stored XSS already independently confirmed on the traditional web feedback form in prior testing. The distinguishing factor for an API-layer finding is that the payload is submitted as structured JSON rather than a form post, and the resulting risk depends on **where the stored value is later rendered** — typically an internal admin dashboard that displays feedback submissions as HTML, at which point the same execution mechanics apply as a traditional stored XSS.

**Claimed Evidence (UNVERIFIED):**
```
POST /api/feedback/submit HTTP/1.1
Host: demo.testfire.net
Content-Type: application/json

{"name": "J Smith", "email": "jsmith@altoromutual.com", "subject": "Amazing web design", "message": "<script>alert('XSS')</script>"}
```
**Reproduction issues:** no rendering-context evidence is provided — i.e., no screenshot or response showing the payload being displayed unencoded on an actual admin-facing page. A `200 OK` acknowledging the submission is not, by itself, proof of stored XSS; it only proves the API *accepted* the payload, not that it later executes anywhere.

**Required Verification Steps:**
1. Submit the payload via the API.
2. Locate and access wherever this feedback is subsequently rendered (admin dashboard, internal tool, or equivalent).
3. Inspect the raw HTML source at that rendering point for unencoded `<script>` tags, and/or observe the alert firing.
4. Capture both the submission and the rendering-point evidence.

**Business Impact (if confirmed):** session/token theft against internal staff reviewing feedback, potentially escalating to administrative account compromise.

**Remediation Architecture:**
- Apply strict JSON schema validation (reject or strip disallowed characters/tags at ingestion).
- Apply context-aware output encoding wherever stored content is rendered as HTML — this is the control that actually prevents exploitation, since ingestion-time filtering alone is often incomplete.
- Deploy a strict Content-Security-Policy on any internal dashboard rendering user-submitted content.

---

### 4.4 SEC-04 — Weak Token Entropy / Authentication Handling

**OWASP Category:** API2:2023 — Broken Authentication
**Provisional CVSS:** 6.5 (Medium)

**Status:** No proof-of-concept was provided in the source material for this finding — only a category label and score. **This cannot be documented beyond a hypothesis.** A legitimate assessment of this claim would require:
1. Capturing multiple issued tokens/session identifiers and analyzing them for predictability or insufficient randomness.
2. Testing whether a session/token can be fixed (attacker sets a token pre-authentication that remains valid post-authentication).

This finding should be **removed from the risk matrix** until at least one of these tests is actually performed and documented.

---

### 4.5 SEC-05 — Verbose Exception Stack Traces

**OWASP Category:** API8:2023 — Security Misconfiguration
**Provisional CVSS:** 4.3 (Low)

**Status:** Same issue as SEC-04 — no PoC provided. A legitimate version of this finding requires sending malformed input (invalid JSON, wrong types, oversized payloads) and capturing an actual response containing stack trace or internal path/framework disclosure. **Should be removed from the risk matrix** until evidenced.

---

## 5. Strategic Remediation Roadmap (Provisional)

| Phase | Action | Routes | Prerequisite |
|---|---|---|---|
| Phase 0 | **Independently reproduce SEC-01 through SEC-05** with real captured evidence | All | Required before any remediation SLA is meaningful |
| Phase 1 (0–24h, if SEC-01/02 confirmed) | Deploy object-level and function-level authorization middleware | `/api/account/*`, `/api/admin/*` | SEC-01/02 confirmed |
| Phase 2 (7 days, if SEC-03 confirmed) | Input schema validation + output encoding | `/api/feedback/*` | SEC-03 confirmed with rendering-point evidence |
| Phase 3 (14 days) | Migrate authentication to signed, short-lived JWTs with rotation | `/api/login` | Applies regardless of SEC-04 status, as general hardening |

---

## 6. Conclusion

This report documents five claimed API vulnerabilities to full professional technical depth — mechanics, exploitability, business impact, and remediation architecture for each. However, **none of the five findings meet the evidentiary bar required for certification**: two (SEC-04, SEC-05) have no proof-of-concept at all, and the remaining three (SEC-01, SEC-02, SEC-03) have request/response pairs that either contain internally inconsistent artifacts (invalid auth header, a balance figure duplicated from an unrelated finding) or omit the rendering-context proof needed to substantiate the claim.

**Recommendation:** treat this document as a **test plan**, not a report. Execute the "Required Verification Steps" listed under each finding, capture genuine evidence, and this can be reissued as a certified assessment with the same structure and technical depth retained.
