# Lab Writeup: Authentication Bypass via Encryption Oracle

**Platform:** PortSwigger Web Security Academy  
**Category:** Business Logic Vulnerabilities  
**Difficulty:** Practitioner  
**Status:** ✅ Solved

---

## Table of Contents

1. [Lab Overview](#lab-overview)
2. [Vulnerability Explanation](#vulnerability-explanation)
3. [Key Concepts](#key-concepts)
4. [Discovering the Oracles](#discovering-the-oracles)
5. [Step-by-Step Solution](#step-by-step-solution)
6. [The Block Cipher Math](#the-block-cipher-math)
7. [Full Attack Chain](#full-attack-chain)
8. [Root Cause Analysis](#root-cause-analysis)
9. [Remediation](#remediation)
10. [Lessons Learned](#lessons-learned)

---

## Lab Overview

| Field | Details |
|---|---|
| **Objective** | Gain access to admin panel and delete user `carlos` |
| **Vulnerability Type** | Encryption Oracle — Logic Flaw |
| **Attack Method** | Forge encrypted `stay-logged-in` cookie using encryption + decryption oracles |
| **Credentials** | `wiener:peter` |
| **Key Cookie** | `stay-logged-in` → format: `username:timestamp` (encrypted) |

---

## Vulnerability Explanation

The application uses the **same encryption key** for two completely different purposes:

| Cookie | Purpose | Direction |
|---|---|---|
| `stay-logged-in` | Authenticates who you are | App reads and decrypts it |
| `notification` | Shows error messages | App encrypts your input and returns it |

This creates two oracles:

- **Encryption Oracle** → submit any data via `email` parameter → app encrypts it → returns ciphertext in `notification` cookie
- **Decryption Oracle** → submit any ciphertext via `notification` cookie → app decrypts it → shows result as error message

Since both use the **same key**, an attacker can encrypt arbitrary data and use it as a `stay-logged-in` cookie to impersonate any user including the administrator.

---

## Key Concepts

### What is an Encryption Oracle?

```
Normal encryption: only the server can encrypt/decrypt
Oracle:            YOU can ask the server to encrypt anything for you

Server accidentally gives you a "stamp machine" that uses the royal seal
You can now forge official-looking documents
```

### Block Cipher (AES-CBC)

The app uses a **block cipher** — data is processed in fixed chunks of **16 bytes** each:

```
Block 1: bytes  1 - 16
Block 2: bytes 17 - 32
Block 3: bytes 33 - 48
...

You can ONLY delete complete blocks — never partial ones
Deleting partial block = corrupted data = decryption fails
```

### The Prefix Problem

Every time you encrypt via the email oracle, the app prepends:
```
"Invalid email address: "   ← exactly 23 characters
```

This prefix gets encrypted along with your data — you must remove it cleanly.

---

## Discovering the Oracles

### Step 1 — Find the Encryption Oracle

Log in with "Stay logged in" enabled. Post a comment with an invalid email:

```
email = "test@@invalid"

Response sets:
notification = [encrypted cookie]

Error message shows:
"Invalid email address: test@@invalid"
```

The app encrypted your input and returned it — this is the **encryption oracle**.

### Step 2 — Find the Decryption Oracle

The `notification` cookie is decrypted by the app to display the error message. Submit any encrypted data in it:

```
PUT anything in notification cookie
App decrypts it
Shows result as error message on the page
```

This is the **decryption oracle**.

### Step 3 — Reveal the Cookie Format

Take your own `stay-logged-in` cookie and place it into the `notification` cookie (decryption oracle):

```
notification = [value of stay-logged-in cookie]

Response shows:
"wiener:1598530205184"
         ↑
    Format confirmed: username:timestamp
```

---

## Step-by-Step Solution

### Phase 1 — Setup Repeater Tabs

Send these two requests to Burp Repeater and rename tabs:

```
Tab "encrypt" → POST /post/comment       (email param = encryption oracle)
Tab "decrypt" → GET /post?postId=x       (notification cookie = decryption oracle)
```

### Phase 2 — Learn the Cookie Format

In the **decrypt** tab, replace the `notification` cookie with your `stay-logged-in` cookie value. Send the request. Note the decrypted output:

```
wiener:1598530205184
       ↑
  Copy this timestamp!
```

### Phase 3 — Encrypt the Target Value (with padding)

In the **encrypt** tab, set the email parameter. You must add **9 x's** as padding:

```
email = xxxxxxxxxadministrator:1598530205184
        ←9 x's→
```

Why 9 x's? See [The Block Cipher Math](#the-block-cipher-math) section below.

Send the request and copy the new `notification` cookie from the response.

### Phase 4 — Decode the Cookie

In Burp Decoder (or manually):

```
Step 1: URL decode  →  converts %2f→/ and %3d→=
Step 2: Base64 decode  →  gives you raw bytes (64 bytes total)
```

### Phase 5 — Delete First 32 Bytes

In Burp Repeater, switch to the **Hex tab**. Select and delete the first 32 bytes:

```
Offset 00: xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx  ← DELETE (block 1)
Offset 10: xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx  ← DELETE (block 2)
Offset 20: xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx  ← KEEP ✅
Offset 30: xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx  ← KEEP ✅
```

Remaining = **32 bytes** (2 clean blocks).

### Phase 6 — Re-encode

```
Step 1: Base64 encode the remaining 32 bytes
Step 2: URL encode  →  replace + with %2b, / with %2f, = with %3d
```

### Phase 7 — Verify

Paste the re-encoded value into the `notification` cookie in the **decrypt** tab. Send the request. Response must show:

```
administrator:1598530205184 ✅
(no "Invalid email address: " prefix)
```

### Phase 8 — Use as stay-logged-in Cookie

From proxy history, send `GET /` to Repeater. Modify the cookies:

```
DELETE the session cookie entirely
REPLACE stay-logged-in with your forged cookie value
```

Send the request. You are now logged in as administrator!

### Phase 9 — Delete Carlos

```
Browse to: /admin
Find the delete user option
Browse to: /admin/delete?username=carlos
```

Lab Solved ✅

---

## The Block Cipher Math

### Why 23 Bytes Can't Be Deleted Directly

```
Prefix = "Invalid email address: " = 23 bytes
23 ÷ 16 = 1 remainder 7  → NOT a complete number of blocks ❌
```

### Why We Add 9 x's

```
We need the bytes to delete to be a multiple of 16:
16 × 2 = 32 bytes

Prefix (23) + Padding (9) = 32 bytes = exactly 2 complete blocks ✅

So delete 32 bytes → removes prefix + padding cleanly
Remaining data = just "administrator:timestamp"
```

### Visual Block Layout

```
With 9 x's padding:

Block 1 (bytes 01-16): "Invalid email ad"   ← DELETE
Block 2 (bytes 17-32): "dress: xxxxxxxxx"   ← DELETE
Block 3 (bytes 33-48): "administrator:15"   ← KEEP ✅
Block 4 (bytes 49-64): "98530205184"        ← KEEP ✅

Delete blocks 1+2 = remove prefix + padding perfectly
```

### Padding Formula

```
Padding needed = (16 × N) - prefix_length
               = (16 × 2) - 23
               = 32 - 23
               = 9 characters
```

---

## Full Attack Chain

```
┌─────────────────────────────────────────────────────────────────────┐
│                        FULL ATTACK CHAIN                            │
└─────────────────────────────────────────────────────────────────────┘

1. DECRYPT own cookie
   stay-logged-in → notification cookie → decryption oracle
   Result: "wiener:1598530205184"
   Learned: format = username:timestamp

2. ENCRYPT target with padding
   email = "xxxxxxxxxadministrator:1598530205184"
   Encryption oracle returns: notification cookie (64 bytes encrypted)

3. DECODE
   URL decode → Base64 decode → 64 raw bytes

4. DELETE first 32 bytes
   Remove blocks 1+2 (prefix "Invalid email address: " + 9 padding chars)
   Remaining: 32 bytes = "administrator:1598530205184" encrypted

5. RE-ENCODE
   Base64 encode → URL encode

6. VERIFY
   Paste into notification cookie → decrypt oracle
   Response shows: "administrator:1598530205184" ✅

7. FORGE
   Use re-encoded value as stay-logged-in cookie
   Delete session cookie
   Send GET / → logged in as administrator ✅

8. DELETE CARLOS
   GET /admin/delete?username=carlos → Lab Solved ✅
```

---

## Root Cause Analysis

| Flaw | Description |
|---|---|
| **Same key for different purposes** | `stay-logged-in` and `notification` cookies share the same encryption key |
| **Encryption oracle exposed** | User input is encrypted and returned to the user |
| **Decryption oracle exposed** | User-supplied ciphertext is decrypted and output reflected |
| **No integrity check** | Encrypted cookies are trusted without any signature verification |
| **Predictable cookie format** | `username:timestamp` format is simple to forge once known |

### The Core Problem

```
Encryption ≠ Authentication

Just because data is encrypted does NOT mean it can be trusted.
The app encrypts but never SIGNS — so forgery is undetectable.
```

---

## Remediation

| Fix | Description |
|---|---|
| **Separate encryption keys** | Use different keys for authentication cookies vs notification cookies |
| **Add HMAC signatures** | Sign all cookies — verify signature before decrypting |
| **Use AES-GCM** | Authenticated encryption — detects tampering automatically |
| **Never return encrypted user input** | Don't expose an encryption oracle via error messages |
| **Never decrypt user-supplied ciphertext** | Don't expose a decryption oracle |
| **Use server-side sessions** | Store session data server-side — don't trust encrypted client-side cookies |

### Correct Implementation

```
❌ Current (vulnerable):
encrypt(user_input) → return to user
decrypt(user_cookie) → trust the result

✅ Correct:
encrypt(data) + HMAC_sign(data) → return to user
verify_signature(cookie) → only then decrypt → use result
```

---

## Lessons Learned

- Encryption provides **confidentiality** — not **integrity** or **authenticity**
- Returning encrypted user input to the user creates an **encryption oracle**
- Decrypting user-supplied ciphertext creates a **decryption oracle**
- When both oracles exist with the same key — an attacker can **forge any encrypted value**
- Block ciphers process data in fixed-size chunks — **always think in multiples of 16**
- The padding trick (adding 9 chars) is needed to align the prefix to a **complete block boundary**
- Always use **authenticated encryption** (AES-GCM) or add **HMAC signatures** to cookies
- Never store sensitive auth data in client-side cookies without proper signing

---

*Writeup by: Neelesh Padney*  
*Date: 2026*  
*Reference: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-encryption-oracle*
