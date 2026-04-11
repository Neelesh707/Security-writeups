# PortSwigger Lab: Username Enumeration via Response Timing

**Author:** Neelesh Pandey  
**Platform:** PortSwigger Web Security Academy  
**Difficulty:** Practitioner  
**Category:** Authentication / Username Enumeration  
**Lab:** Username enumeration via response timing  

---

## Overview

This lab demonstrates username enumeration through **response timing analysis** — a technique where the time taken by the server to respond reveals whether a username is valid or not. Combined with IP spoofing to bypass rate limiting, this allows an attacker to enumerate valid usernames and brute-force their passwords without triggering account lockout.

This is a more subtle attack than error message enumeration — the application returns identical responses for valid and invalid usernames, but the **time difference** betrays the truth.

---

## Vulnerability Explanation

### Why Timing Differs

When an invalid username is submitted:
```
Server checks username → not found → immediately returns error
Response time: ~fast (consistent)
```

When a valid username is submitted:
```
Server checks username → found → proceeds to check password
Password checking (hashing comparison) takes time proportional to password length
Response time: ~slow (increases with password length)
```

**Key insight:** By submitting a very long password (100+ characters), the password hashing process takes measurably longer for valid usernames — creating a detectable timing difference.

### IP-Based Rate Limiting Bypass

The application blocks IPs after too many failed attempts. However, it trusts the `X-Forwarded-For` header — intended for load balancers to pass the original client IP. By spoofing a different IP in this header for each request, the rate limit is bypassed.

```
X-Forwarded-For: 1    → request 1
X-Forwarded-For: 2    → request 2
X-Forwarded-For: 3    → request 3
```

Each request appears to come from a different IP — rate limit never triggers.

---

## Methodology

```
Confirm timing difference → Identify X-Forwarded-For bypass →
Enumerate usernames via timing → Identify valid username →
Brute-force password → Login
```

---

## 1. Reconnaissance

### Step 1 — Observe Rate Limiting

Submitted multiple invalid login attempts. After several requests, IP was blocked — confirming rate limiting is active.

### Step 2 — Discover X-Forwarded-For Bypass

Added `X-Forwarded-For: 1` header to the request. Rate limit was bypassed — the server trusts this header to identify the client IP.

### Step 3 — Observe Timing Difference

Tested with known valid username (`wiener`) and a very long password (100 characters):

```http
POST /login HTTP/2
X-Forwarded-For: 1
username=wiener&password=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

**Response time: significantly longer** than with an invalid username.

With invalid username + same long password:
```http
username=invaliduser&password=aaaaaaa...
```

**Response time: fast** — server rejects immediately without hashing.

---

## 2. Username Enumeration — Burp Intruder Pitchfork Attack

### Attack Configuration

Sent the login request to Burp Intruder. Selected **Pitchfork** attack type — fires two payload lists simultaneously, one per position.

**Request with payload positions:**
```http
POST /login HTTP/2
Host: <lab-id>.web-security-academy.net
X-Forwarded-For: §1§
Content-Type: application/x-www-form-urlencoded

username=§candidate-username§&password=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

**Payload position 1 — X-Forwarded-For (IP spoofing):**
- Type: Numbers
- Range: 1–100
- Step: 1
- Max fraction digits: 0

**Payload position 2 — Username:**
- Type: Simple list
- Values: PortSwigger candidate username list

Password set to 100-character string to maximise timing difference for valid usernames.

### Results Analysis

After attack completed:
- Enabled **Response received** and **Response completed** columns
- Sorted by response time
- One username showed significantly longer response time than all others

**Valid username identified** — confirmed by repeating the request multiple times and observing consistent delay.

---

## 3. Password Brute-Force — Second Pitchfork Attack

### Attack Configuration

New Intruder attack on the same endpoint with the confirmed username:

```http
POST /login HTTP/2
X-Forwarded-For: §1§
Content-Type: application/x-www-form-urlencoded

username=<confirmed-username>&password=§candidate-password§
```

**Payload position 1 — X-Forwarded-For:** Numbers 1–100  
**Payload position 2 — Password:** PortSwigger candidate password list

### Results

Sorted results by Status column. One request returned **HTTP 302** (redirect) — indicating successful login.

**Password identified.**

---

## 4. Login and Account Access

Used the enumerated credentials to log in and access the account page — lab solved.

---

## Attack Flow Summary

```
Multiple login attempts → IP blocked → rate limiting confirmed
        ↓
X-Forwarded-For header tested → bypass confirmed
        ↓
Valid username (wiener) + 100-char password → slow response
Invalid username + 100-char password → fast response
        ↓
Pitchfork attack: IP spoofing + username list + long password
→ One username shows significantly longer response time
→ Valid username confirmed
        ↓
Second Pitchfork: IP spoofing + confirmed username + password list
→ HTTP 302 response = successful login
→ Password confirmed
        ↓
Login → account page → lab solved
```

---

## 5. Why Pitchfork Attack Type

| Attack Type | Behaviour | Use Case |
|-------------|-----------|----------|
| Sniper | One payload list, one position | Single parameter fuzzing |
| Battering ram | Same payload in all positions | Same value everywhere |
| Pitchfork | Multiple lists, fired simultaneously | Different value per position |
| Cluster bomb | Every combination of all lists | Full brute-force |

**Pitchfork** was used because position 1 (IP) and position 2 (username/password) need different values from different lists fired in sync — each request gets a new IP paired with the next candidate value.

---

## 6. Key Takeaways

- **Timing attacks reveal logic even when responses look identical** — the application returns the same error message for valid and invalid usernames, but processing time betrays which is which
- **Long passwords amplify timing differences** — hashing a 100-character password takes measurably longer than a short one; this is the amplification technique that makes timing observable
- **X-Forwarded-For is dangerous when trusted blindly** — IP-based rate limiting is easily bypassed if the application accepts client-supplied IP headers; always validate this header comes from a trusted proxy
- **Pitchfork attack is purpose-built for paired payloads** — when you need a different IP per request alongside a different username/password, Pitchfork is the correct Intruder attack type
- **302 status = successful login** — in brute-force attacks, always look for status codes that differ from the normal failure response; 302 redirect on a login form means the credentials worked
- **Timing enumeration is harder to detect than error enumeration** — no different error messages to alert a WAF or log monitoring system; purely statistical

---

## 7. Real-World Relevance

Timing-based username enumeration appears when:
- Applications use bcrypt/scrypt/Argon2 for password hashing — these are deliberately slow algorithms
- The server only hashes the password when a valid username is found
- The difference between "user not found" and "wrong password" processing paths has measurable timing

In bug bounty, timing attacks require careful statistical analysis — network jitter can mask small differences. Use multiple requests per candidate and average the response times for reliable results.

---

## 8. Remediation

| Finding | Risk | Fix |
|---------|------|-----|
| Timing difference between valid/invalid usernames | High | Hash the password regardless of whether username exists — use a dummy hash operation for invalid usernames to normalise response time |
| X-Forwarded-For trusted for rate limiting | High | Only trust X-Forwarded-For from known, trusted load balancer IPs; implement rate limiting at the load balancer level |
| No CAPTCHA after failed attempts | Medium | Add CAPTCHA after 3-5 failed attempts to prevent automated attacks |
| Rate limiting bypassable via IP spoofing | High | Implement rate limiting based on multiple signals — device fingerprint, session, username — not just IP |

**Secure timing normalisation (pseudocode):**
```python
def login(username, password):
    user = db.find_user(username)
    
    if user:
        # Real hash comparison
        is_valid = bcrypt.check(password, user.password_hash)
    else:
        # Dummy hash to normalise timing — prevent enumeration
        bcrypt.check(password, DUMMY_HASH)
        is_valid = False
    
    if not is_valid:
        return error("Invalid credentials")
    return redirect("/account")
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite Professional | Proxy, request interception |
| Burp Repeater | Manual timing observation |
| Burp Intruder (Pitchfork) | Automated username enumeration and password brute-force |

---

## References

- [PortSwigger — Username Enumeration via Response Timing](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing)
- [PortSwigger — Authentication Vulnerabilities](https://portswigger.net/web-security/authentication)
- [OWASP — Testing for Account Enumeration](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account)

---

*Write-up by Neelesh Pandey — [GitHub](https://github.com/Neelesh707) | [LinkedIn](https://www.linkedin.com/in/neelesh-pandey021/)*
