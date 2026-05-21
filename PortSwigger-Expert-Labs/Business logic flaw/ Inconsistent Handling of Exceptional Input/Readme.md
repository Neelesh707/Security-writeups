# Lab Writeup: Inconsistent Handling of Exceptional Input

**Platform:** PortSwigger Web Security Academy  
**Category:** Business Logic Vulnerabilities  
**Difficulty:** Practitioner  
**Status:** ✅ Solved

---

## Table of Contents

1. [Lab Overview](#lab-overview)
2. [Vulnerability Explanation](#vulnerability-explanation)
3. [Key Concepts](#key-concepts)
4. [Step-by-Step Solution](#step-by-step-solution)
5. [Payload Construction](#payload-construction)
6. [Root Cause Analysis](#root-cause-analysis)
7. [Remediation](#remediation)
8. [Lessons Learned](#lessons-learned)

---

## Lab Overview

| Field | Details |
|---|---|
| **Objective** | Access the admin panel and delete user `carlos` |
| **Vulnerability Type** | Business Logic — Inconsistent Input Handling |
| **Attack Vector** | Email truncation abuse during account registration |
| **Admin Restriction** | Only `@dontwannacry.com` employees can access `/admin` |

---

## Vulnerability Explanation

The application suffers from **inconsistent handling of long input** across two different layers:

| Layer | Behavior |
|---|---|
| **Email delivery server** | Uses the **full** email address to send confirmation |
| **Application database** | **Truncates** stored email to **255 characters** |

This mismatch allows an attacker to register with an email that:
- Gets **delivered** to an inbox they control (real domain at the end)
- Gets **stored** in the database as a `@dontwannacry.com` address (after truncation)

---

## Key Concepts

### Email Domain vs Subdomain

```
attacker@dontwannacry.com.yourid.web-security-academy.net
          ↑
          This is a SUBDOMAIN, not the real domain!
          Real domain = web-security-academy.net
```

The mail server delivers to `web-security-academy.net` infrastructure (which you control), while `dontwannacry.com` is just a label in the subdomain chain.

### Truncation Abuse

```
Before truncation (300 chars):
AAAA...AAAA@dontwannacry.com.yourid.web-security-academy.net

After truncation (255 chars):
AAAA...AAAA@dontwannacry.com
            ↑
            .yourid.web-security-academy.net is GONE
```

---

## Step-by-Step Solution

### Step 1 — Discover the Admin Panel

Browse to `/admin`. Access is denied, but the error message reveals:

> "This functionality is only available to DontWannaCry users."

### Step 2 — Confirm Registration Page Hint

Visit the account registration page. A notice tells `DontWannaCry` employees to use their company email address (`@dontwannacry.com`).

### Step 3 — Get Your Email Client ID

Open the email client from the lab banner. Note your unique email server ID:

```
@YOUR-EMAIL-ID.web-security-academy.net
```

### Step 4 — Test the Truncation

Register with a long email (200+ characters) in this format:

```
AAAA...AAAA@YOUR-EMAIL-ID.web-security-academy.net
```

- Receive the confirmation email → click the link → log in
- Go to **My Account** → observe the email is truncated to **255 characters**

This confirms the database truncates at 255 chars.

### Step 5 — Craft the Exploit Email

Register a new account with a carefully crafted email:

```
very-long-string@dontwannacry.com.YOUR-EMAIL-ID.web-security-academy.net
```

The padding must be sized so the **255th character is exactly the `m` in `dontwannacry.com`**.

### Step 6 — Verify and Login

- Go to the email client → receive confirmation email → click the link
- Log in → visit **My Account** → email now shows as `...@dontwannacry.com`
- Admin panel at `/admin` is now accessible ✅

### Step 7 — Delete Carlos

Navigate to `/admin` → find user `carlos` → delete → **Lab Solved** ✅

---

## Payload Construction

### Calculate the Padding Length

```
Total allowed characters  = 255
Characters used by @      = 1
Characters in dontwannacry.com = 16
                            --------
Padding (A's) needed      = 255 - 1 - 16 = 238 characters
```

### Final Payload

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@dontwannacry.com.YOUR-EMAIL-ID.web-security-academy.net
```

*(238 A's + @dontwannacry.com = exactly 255 chars)*

### What Each System Sees

```
┌─────────────────────────────────────────────────────────┐
│ MAIL SERVER (sees full address)                         │
│ Delivers to: YOUR-EMAIL-ID.web-security-academy.net ✅  │
│ You receive the confirmation email                      │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ DATABASE (stores only 255 chars)                        │
│ Stores:  AAAA...AAAA@dontwannacry.com                  │
│ Rest is CUT OFF → looks like real employee ✅           │
└─────────────────────────────────────────────────────────┘
```

---

## Root Cause Analysis

```
┌──────────────┐     full email      ┌──────────────────┐
│   Browser    │ ─────────────────►  │   App Server     │
└──────────────┘                     │  (sends email    │
                                     │   to full addr)  │
                                     └────────┬─────────┘
                                              │
                                              │ truncates to 255 chars
                                              ▼
                                     ┌──────────────────┐
                                     │    Database      │
                                     │  stores truncated│
                                     │  email as-is     │
                                     └──────────────────┘
```

The bug lives **between** the email delivery layer and the storage layer. Neither is broken alone — the inconsistency between them is the vulnerability.

---

## Remediation

| Fix | Description |
|---|---|
| **Validate before storing** | Enforce email length limits at the application layer before saving to DB |
| **Consistent limits** | Apply the same 255-char limit at client, server, and DB |
| **Re-validate on login** | Ensure the stored email matches what was actually verified |
| **Reject oversized input early** | Return an error if input exceeds the allowed length instead of silently truncating |

The golden rule:

> **Never trust truncation as a security boundary. Validate input consistently at every layer.**

---

## Lessons Learned

- Business logic bugs often arise from **mismatched assumptions** between application layers
- Input that is "too long" can be a valid attack vector, not just a UX problem
- Truncation is a data integrity issue — not a sanitization strategy
- Always test what happens at boundary conditions (max length, empty input, special chars)
- Admin restrictions based on email domain must be validated against the **verified, original** email — not a derived or stored value

---

*Writeup by: Neelesh Pandey*  
*Date: 2026*  
*Reference: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input*
