# Unauthenticated Flashloan Callbacks Allow Direct Invocation and Fund Theft

##  Query
- Glider DB: https://r.xyz/glider-query-database/query/6946d67adb3b3efd61383808

##  Description

This query detects flashloan callback functions (such as `executeOperation`, `onFlashLoan`, or similar) that perform state changes, external calls, or value transfers **without validating `msg.sender` against a trusted flashloan provider**.

In such implementations, an attacker may directly invoke the callback function without initiating a legitimate flashloan, bypassing the intended flashloan lifecycle.

If the callback contains sensitive logic (e.g., external calls, token transfers, or execution of encoded actions), this can enable unauthorized execution paths and potential asset loss.

While some implementations rely on internal state flags or initiator checks, the absence of explicit caller authentication introduces a fragile trust assumption that has historically resulted in real-world exploits.

---

##  Impact

- Unauthorized execution of flashloan logic
- Direct invocation of privileged flows
- Potential fund theft

---

