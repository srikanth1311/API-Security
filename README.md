# API Penetration Testing — REST API Security Assessment

**Type:** API Security Assessment (REST)
**Tooling:** Burp Suite, Postman
**Report:** [`API-Pentest-Report.pdf`](./API-Pentest-Report.pdf) | [`API_Security.md`](./API_Security.md) | [`postman-project.pdf`](./postman-project.pdf)

---

## Summary

This assessment targeted a REST API, using Postman for request crafting/collection management and Burp Suite for interception, manipulation, and automated attacks (Intruder). Testing covered authentication/session handling, broken access control (IDOR), business-logic abuse (transaction/money-transfer manipulation), and standard injection classes (SQLi, XSS).

---

## Findings

| # | Vulnerability | Area | Evidence |
|---|---|---|---|
| 1 | IDOR — account ID & balance disclosure | Access Control | `screenshots/idor-acc-id.png`, `idor-acc-id-balance-burp.png`, `idor-burp.png` |
| 2 | Transaction/money-transfer manipulation via Intruder | Business Logic | `screenshots/transaction-details-after-intruder.png`, `transaction-details-using-intruder.png`, `money-transfer-burp.png`, `money-transfer.png`, `changing-from-to-burp.png` |
| 3 | SQL Injection | Input Validation | `screenshots/sql-injection.png` |
| 4 | Cross-Site Scripting (XSS) in API response | Input Validation | `screenshots/xss-api.png` |
| 5 | Account detail / balance exposure via API | Data Exposure | `screenshots/account-details-api-burp.png`, `checking-acc-id-balance.png`, `checking-acc-id-balance-burp.png`, `checking-account-details-api.png` |
| 6 | JSESSIONID exposed/reused before authentication | Session Management | `screenshots/jsessionid-check-before-login.png` |
| 7 | User creation endpoint abuse | Authorization | `screenshots/user-creation-api.png`, `user-creation-api-burp.png` |

---

## Methodology

1. **API Discovery** — imported the API site/collection into Postman (`import-site-link-postman.png`), identified base URL and REST endpoints (`selecting-base-url.png`, `setting-base-url.png`, `selecting-rest-api.png`).
2. **Authentication Review** — tested login flow and checked session token (JSESSIONID) handling before and after authentication.
3. **Access Control Testing** — manipulated account ID parameters to test for IDOR, exposing other users' account details and balances.
4. **Business Logic Testing** — intercepted and modified transaction/money-transfer requests using Burp Intruder to test for unauthorized fund transfers.
5. **Injection Testing** — tested API input fields for SQL injection and XSS.
6. **Authorization Testing** — tested the user-creation endpoint for improper access restrictions.

---

## Disclaimer

This assessment was performed in an authorized testing environment. All screenshots and findings are documented for educational/portfolio purposes only. Do not run any of these techniques against APIs or applications you do not own or have explicit written authorization to test.

## Files

- `API-Pentest-Report.pdf` — full formatted report
- `API_Security.md` — findings notes
- `postman-project.pdf` — exported Postman collection/documentation
- `screenshots/` — evidence for each finding
