# PortSwigger Lab: Brute-Forcing a Stay-Logged-In Cookie

**Author:** Neelesh Pandey  
**Platform:** PortSwigger Web Security Academy  
**Difficulty:** Practitioner  
**Category:** Authentication / Cookie Brute-Force  
**Lab:** Brute-forcing a stay-logged-in cookie  

---

## Overview

This lab demonstrates how a predictable "stay-logged-in" cookie can be brute-forced to gain access to any user's account without knowing their password. The cookie is constructed from the username and an MD5 hash of the password, encoded in Base64 — a pattern that can be reverse-engineered and weaponised once the construction formula is discovered.

---

## The Vulnerability

### Cookie Construction Formula

```
stay-logged-in = base64( username + ":" + md5(password) )
```

**Example for wiener:peter:**
```
md5("peter") = 51dc30ddc473d43a6011e9ebba6ca770
concat       = "wiener:51dc30ddc473d43a6011e9ebba6ca770"
base64       = d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw
```

**Why this is insecure:**
- MD5 is a fast hashing algorithm — not designed for password storage
- No salt — same password always produces the same hash
- The formula is discoverable by studying your own cookie
- Once the formula is known, any user's cookie can be generated from a password wordlist

---

## 1. Cookie Discovery and Analysis

### Step 1 — Log in with Stay Logged In

Logged in as `wiener:peter` with "Stay logged in" checkbox selected. Burp Proxy captured the response setting the cookie:

```http
Set-Cookie: stay-logged-in=d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw
```

### Step 2 — Decode and Analyse

Decoded the Base64 value in Burp Inspector:

```
d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw
→ wiener:51dc30ddc473d43a6011e9ebba6ca770
```

**Analysis:**
- Format: `username:hash`
- Hash length: 32 characters — matches MD5 output length
- Character set: hexadecimal (0-9, a-f) — MD5 characteristic

**Verification:**
```
md5("peter") = 51dc30ddc473d43a6011e9ebba6ca770 ✓
```

Cookie construction formula confirmed.

---

## 2. Exploitation — Burp Intruder with Payload Processing

### Strategy

Generate valid cookies for Carlos by:
1. Taking each candidate password
2. Hashing it with MD5
3. Prepending `carlos:`
4. Base64 encoding the result
5. Sending as the `stay-logged-in` cookie value

### Step 1 — Capture Target Request

Sent `GET /my-account?id=carlos` to Burp Intruder with the `stay-logged-in` cookie as the payload position:

```http
GET /my-account?id=carlos HTTP/2
Host: <lab-id>.web-security-academy.net
Cookie: stay-logged-in=§payload§; session=<session>
```

### Step 2 — Payload Processing Rules

Added three sequential processing rules in Intruder → Payloads → Payload processing:

| Order | Rule | Input → Output |
|-------|------|----------------|
| 1 | Hash: MD5 | `password123` → `482c811da5d5b4bc6d497ffa98491e38` |
| 2 | Add prefix: `carlos:` | `482c811da5d5b4bc6d497ffa98491e38` → `carlos:482c811da5d5b4bc6d497ffa98491e38` |
| 3 | Encode: Base64 | `carlos:482c811da5d5b4bc6d497ffa98491e38` → `Y2FybG9zOjQ4MmM4MTFkYTVkNWI0YmM2ZDQ5N2ZmYTk4NDkxZTM4` |

**Order is critical** — applying Base64 before MD5 would produce wrong results.

### Step 3 — Success Detection

Added grep match rule to flag responses containing `Update email` — this button only appears on authenticated account pages.

```
Settings → Grep - Match → Add → "Update email"
```

### Step 4 — Validate with Own Account First

Tested with `wiener:peter` first:
- Payload: `peter`
- Processing: MD5 → prefix `wiener:` → Base64
- Response: Contains `Update email` ✓

Confirmed payload processing rules work correctly before attacking Carlos.

### Step 5 — Attack Carlos

Modified attack:
- Payload list: PortSwigger candidate passwords
- URL: `GET /my-account?id=carlos`
- Prefix rule: `carlos:` instead of `wiener:`

### Step 6 — Results

One response returned containing `Update email` — that payload is Carlos's valid `stay-logged-in` cookie. Lab solved.

---

## 3. Attack Flow Summary

```
Login as wiener → capture stay-logged-in cookie
        ↓
Decode Base64 → wiener:51dc30ddc473d43a6011e9ebba6ca770
        ↓
Identify MD5 hash → verify md5("peter") matches
        ↓
Formula confirmed: base64(username:md5(password))
        ↓
Intruder: GET /my-account?id=carlos
Payload processing: MD5 → prefix "carlos:" → Base64
Payload list: candidate passwords
        ↓
Grep for "Update email" → one match = valid cookie found
        ↓
Carlos's account accessed → lab solved
```

---

## 4. Why MD5 Is Dangerous for Passwords

| Property | MD5 | bcrypt/Argon2 |
|----------|-----|---------------|
| Speed | Very fast (~10 billion/sec on GPU) | Deliberately slow |
| Salt support | None built-in | Built-in |
| Crackability | Rainbow tables exist | Infeasible with salt |
| Purpose | Data integrity | Password hashing |

MD5 was never designed for password storage — it's designed to be fast for checksums. This makes it trivial to brute-force offline. Well-known password hashes (MD5 of common passwords) are available in rainbow tables online — paste the hash into a search engine and the password appears immediately.

---

## 5. Key Takeaways

- **Study your own cookie to discover the construction formula** — any feature you can access yourself reveals how the application works; the "remember me" cookie is no exception
- **MD5 is not a password hashing function** — it's a checksum algorithm; using it for passwords is always a vulnerability regardless of encoding
- **Base64 is encoding not encryption** — it adds zero security; it's trivially reversible and exists only to make binary data ASCII-safe
- **No salt means identical passwords produce identical hashes** — if two users share a password, their cookie hashes match; rainbow tables crack unsalted MD5 instantly
- **Payload processing in Burp Intruder is powerful** — chaining MD5 → prefix → Base64 transforms a simple password list into valid authentication cookies automatically
- **Grep match rules enable automated success detection** — flagging `Update email` means you don't need to manually check 100+ responses

---

## 6. Real-World Relevance

Predictable cookie patterns appear when developers:
- Roll their own "remember me" functionality instead of using framework defaults
- Use fast hash functions (MD5, SHA1) thinking they're secure for passwords
- Concatenate predictable values (username + hash) without a secret key or HMAC

In bug bounty, always decode cookies with Base64 and inspect the structure. If you see `username:hash` patterns, test whether the hash algorithm can be identified and the cookie reproduced from a wordlist.

---

## 7. Remediation

| Finding | Risk | Fix |
|---------|------|-----|
| Predictable cookie formula | Critical | Use cryptographically random token — store server-side against user ID |
| MD5 for password hashing | Critical | Use bcrypt, scrypt, or Argon2 with appropriate work factor |
| No salt in hash | Critical | Always use unique per-user salt — prevents rainbow table attacks |
| Base64 as "encryption" | High | Base64 is encoding not encryption — use HMAC-SHA256 with server secret |

**Secure implementation:**
```python
import secrets
import hashlib

# Generate secure remember-me token
def generate_remember_token(user_id):
    token = secrets.token_hex(32)  # cryptographically random
    # Store token → user_id mapping in database with expiry
    db.store_remember_token(token, user_id, expires_in=30_days)
    return token

# Never: base64(username + md5(password))
# Always: random token stored server-side
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite Professional | Proxy, cookie inspection via Inspector |
| Burp Intruder | Automated cookie generation with payload processing |
| Burp Payload Processing | MD5 hash → prefix → Base64 encode pipeline |

---

## References

- [PortSwigger — Authentication Vulnerabilities](https://portswigger.net/web-security/authentication)
- [PortSwigger — Stay Logged In Cookie](https://portswigger.net/web-security/authentication/other-mechanisms)
- [OWASP — Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

---

*Write-up by Neelesh Pandey — [GitHub](https://github.com/Neelesh707) | [LinkedIn](https://www.linkedin.com/in/neelesh-pandey021/)*
