# PortSwigger Lab: Broken Brute-Force Protection — IP Block Bypass

**Author:** Neelesh Pandey  
**Platform:** PortSwigger Web Security Academy  
**Difficulty:** Practitioner  
**Category:** Authentication / Brute-Force Protection Bypass  
**Lab:** Broken brute-force protection, IP block  

---

## Overview

This lab demonstrates a logic flaw in brute-force protection where the failed login counter resets when a successful login occurs. By interleaving valid credentials with attack attempts, the counter never reaches the lockout threshold — allowing unlimited password brute-forcing against the victim's account.

Instead of manually building payload lists, a **custom Python script** was written to automatically generate the interleaved username and password lists — ensuring correct pairing and alignment across 100+ attempts.

---

## The Logic Flaw

### Normal Protection Behaviour
```
3 failed logins → IP temporarily blocked
```

### The Flaw
```
Failed login 1 → counter = 1
Failed login 2 → counter = 2
Successful login (wiener:peter) → counter RESETS to 0
Failed login 1 → counter = 1
Failed login 2 → counter = 2
Successful login (wiener:peter) → counter RESETS to 0
...repeat indefinitely
```

The server resets the failure counter on ANY successful login — including logging in as a completely different user. This means an attacker can insert their own valid credentials every 2-3 attempts to reset the counter before lockout triggers.

---

## Methodology

```
Confirm lockout threshold → Identify counter reset on success →
Generate interleaved payload lists → Pitchfork attack (1 thread) →
Find 302 for carlos → Login
```

---

## 1. Reconnaissance

### Step 1 — Confirm Lockout Behaviour

Submitted 3 incorrect logins in a row — IP temporarily blocked after the third attempt. Lockout threshold = **3 failed attempts**.

### Step 2 — Identify Counter Reset

Submitted 2 incorrect logins, then logged in successfully as `wiener:peter`. Tried 2 more incorrect logins — no lockout. Counter confirmed to reset on successful login.

**The attack pattern:**
```
Attempt 1: wiener:peter     → success → counter resets to 0
Attempt 2: carlos:password1 → fail   → counter = 1
Attempt 3: carlos:password2 → fail   → counter = 2
Attempt 4: wiener:peter     → success → counter resets to 0
Attempt 5: carlos:password3 → fail   → counter = 1
Attempt 6: carlos:password4 → fail   → counter = 2
...
```

Every 3rd request is a valid wiener login — counter never reaches 3 for carlos.

---

## 2. Payload List Generation — Custom Python Script

Instead of manually building interleaved lists of 100+ entries, a Python script was written to generate both lists automatically with correct alignment:

```python
print("########## Usernames: ##########")
for i in range(150):
    if i % 3:
        print("carlos")
    else:
        print("wiener")

print("########## Passwords: ##########")
with open('passwords.txt', 'r') as f:
    lines = f.readlines()

i = 0
for pwd in lines:
    if i % 3:
        print(pwd.strip('\n'))
    else:
        print("peter")
        print(pwd.strip('\n'))
        i = i + 1
    i = i + 1
```

### How the Script Works

**Username list logic (`i % 3`):**

| i | i % 3 | Username |
|---|-------|----------|
| 0 | 0 (false) | wiener |
| 1 | 1 (true) | carlos |
| 2 | 2 (true) | carlos |
| 3 | 0 (false) | wiener |
| 4 | 1 (true) | carlos |
| 5 | 2 (true) | carlos |

Every 3rd position (i=0, 3, 6...) outputs `wiener`. All others output `carlos`.

**Password list logic:**

Every time `wiener` appears in the username list, `peter` is inserted in the password list at the same position — keeping the username:password pairs aligned:

```
wiener  → peter          (position 0)
carlos  → password1      (position 1)
carlos  → password2      (position 2)
wiener  → peter          (position 3)
carlos  → password3      (position 4)
carlos  → password4      (position 5)
```

**Why this alignment matters:** Pitchfork attack fires both lists simultaneously — position N of list 1 is paired with position N of list 2. If wiener appears at position 3, peter must also appear at position 3 or the wrong password gets sent.

---

## 3. Burp Intruder Pitchfork Attack

### Configuration

Sent `POST /login` to Burp Intruder. Selected **Pitchfork** attack type.

```http
POST /login HTTP/2
Host: <lab-id>.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=§wiener§&password=§peter§
```

**Payload position 1 (username):** Generated username list from script  
**Payload position 2 (password):** Generated password list from script

### Critical Setting — Maximum Concurrent Requests: 1

Set Resource Pool to **1 concurrent request** — this ensures requests fire sequentially in the exact order of the payload list. Without this, requests could arrive out of order — wiener login might arrive after carlos attempts instead of before, causing lockout.

```
Resource Pool → Maximum concurrent requests → 1
```

---

## 4. Results

After attack completed:
- Filtered to hide HTTP 200 responses
- Sorted remaining results by username
- Single **HTTP 302** response for `carlos` — successful login
- Password identified from Payload 2 column

Logged in as carlos → accessed account page → lab solved.

---

## 5. Attack Flow Summary

```
3 failed logins → IP blocked → threshold confirmed
        ↓
2 failed + wiener:peter success → counter resets → flaw confirmed
        ↓
Python script generates interleaved payload lists:
wiener/peter → carlos/pwd1 → carlos/pwd2 → wiener/peter → ...
        ↓
Pitchfork attack, 1 thread (preserves order)
        ↓
Filter results → HTTP 302 for carlos → password found
        ↓
Login as carlos → account page → solved
```

---

## 6. Why 1 Concurrent Request is Critical

| Setting | Problem |
|---------|---------|
| Multiple concurrent | Requests arrive out of order — carlos attempts may land before wiener reset — triggers lockout |
| 1 concurrent | Requests fire sequentially in exact payload list order — wiener always resets before carlos attempts |

The entire attack depends on ordering. Concurrency destroys ordering.

---

## 7. Key Takeaways

- **Successful login by ANY user resets the counter** — the flaw is that the counter tracks failed attempts per IP, not per username; resetting it on any success is the logic error
- **Interleaving valid credentials bypasses rate limiting** — the attacker uses their own account as a "reset token" every 2 attempts
- **Payload alignment is critical in Pitchfork attacks** — username and password lists must be exactly aligned; the Python script ensures this automatically
- **1 concurrent request preserves ordering** — multi-threaded attacks break sequential logic; always use single-thread when order matters
- **Python automation beats manual list building** — generating 150 interleaved entries manually is error-prone; scripting it is faster and guaranteed correct
- **HTTP 302 signals successful authentication** — in login brute-force, always filter for status codes that differ from the normal failure response

---

## 8. Real-World Relevance

This logic flaw appears when:
- Failed login counters are stored per IP rather than per username
- The counter resets on any successful authentication event
- The application doesn't distinguish between "reset because this user logged in" vs "reset because some user logged in"

In real bug bounty, this is testable by: making 2 failed attempts, successfully logging into your own account, then making 2 more failed attempts — if no lockout occurs, the flaw exists.

---

## 9. Remediation

| Finding | Risk | Fix |
|---------|------|-----|
| Counter resets on any successful login | High | Reset counter only for the specific username that successfully authenticated — not globally per IP |
| Counter tracked per IP only | High | Track failed attempts per username AND per IP — lockout the username after N failures regardless of IP |
| No CAPTCHA | Medium | Add CAPTCHA after 3 failed attempts to prevent automation |
| Lockout bypassable via own account | High | Implement exponential backoff — delays increase regardless of successful logins from other accounts |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite Professional | Proxy, Intruder Pitchfork attack |
| Python | Custom payload list generation with correct interleaving |

---

## References

- [PortSwigger — Brute-Force Attacks](https://portswigger.net/web-security/authentication/password-based)
- [PortSwigger — Authentication Vulnerabilities](https://portswigger.net/web-security/authentication)

---

*Write-up by Neelesh Pandey — [GitHub](https://github.com/Neelesh707) | [LinkedIn](https://www.linkedin.com/in/neelesh-pandey021/)*
