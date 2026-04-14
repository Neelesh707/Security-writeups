# PortSwigger Lab: Password Brute-Force via Password Change Functionality

**Author:** Neelesh Pandey  
**Platform:** PortSwigger Web Security Academy  
**Difficulty:** Practitioner  
**Category:** Authentication / Logic Flaw / Brute-Force  
**Lab:** Password brute-force via password change  

---

## Overview

This lab demonstrates how password change functionality can be exploited as an alternative brute-force channel. The change-password form accepts the current password and two new passwords — and crucially, returns **different error messages** depending on whether the current password is correct or not. This difference becomes a side channel for enumerating the correct password, bypassing any brute-force protection on the main login endpoint.

---

## The Vulnerability

### Error Message Behaviour

| Current Password | new-password-1 | new-password-2 | Response |
|-----------------|----------------|----------------|----------|
| Wrong | same | same | Account locked |
| Wrong | different | different | `Current password is incorrect` |
| Correct | different | different | `New passwords do not match` |

**The key insight:** When `new-password-1 ≠ new-password-2`, the application checks the current password first before validating the new ones. If the current password is wrong → "incorrect" message. If correct → "do not match" message.

By keeping `new-password-1 ≠ new-password-2`, we turn the error message into a password oracle — one specific message reveals when the current password is correct.

---

## Why This Bypasses Login Brute-Force Protection

The main `/login` endpoint has brute-force protection. The `/my-account/change-password` endpoint does not — it's considered a post-authentication feature. By moving the brute-force attack to the change-password endpoint and injecting Carlos's username via the hidden field, the login protection is completely bypassed.

```
/login         → brute-force protected (rate limiting / lockout)
/change-password → no brute-force protection → attack here
```

---

## Methodology

```
Discover hidden username field → Observe error message differences →
Identify oracle condition → Intruder attack with grep match →
Find correct password → Login as carlos
```

---

## 1. Reconnaissance

### Step 1 — Investigate Change Password Form

Logged in as `wiener:peter`. Navigated to My account → Change password. Intercepted `POST /my-account/change-password` in Burp:

```http
POST /my-account/change-password HTTP/2
Content-Type: application/x-www-form-urlencoded

username=wiener&current-password=peter&new-password-1=test1&new-password-2=test2
```

**Key finding:** `username` is submitted as a hidden field — it can be modified to target any user.

### Step 2 — Map Error Message Behaviour

Tested three scenarios:

**Scenario A — Wrong current password, matching new passwords:**
```
current-password=wrong&new-password-1=abc&new-password-2=abc
→ Account gets locked
```

**Scenario B — Wrong current password, different new passwords:**
```
current-password=wrong&new-password-1=abc&new-password-2=xyz
→ "Current password is incorrect"
```

**Scenario C — Correct current password, different new passwords:**
```
current-password=peter&new-password-1=abc&new-password-2=xyz
→ "New passwords do not match"
```

**Oracle identified:** "New passwords do not match" = current password is correct.

---

## 2. Exploitation — Burp Intruder Attack

### Step 1 — Configure Request

Sent the change-password request to Burp Intruder. Modified:
- `username` → `carlos` (changed from wiener)
- `current-password` → payload position `§`
- `new-password-1` and `new-password-2` → intentionally different values

```http
POST /my-account/change-password HTTP/2
Host: <lab-id>.web-security-academy.net
Cookie: session=<wiener-session>

username=carlos&current-password=§candidate§&new-password-1=abc&new-password-2=xyz
```

**Note:** The session cookie is wiener's — we are authenticated as wiener but targeting carlos via the hidden username field.

### Step 2 — Payload List

Added PortSwigger candidate password list as payload set.

### Step 3 — Grep Match Rule

Added grep match rule to flag responses containing:
```
New passwords do not match
```

This automatically highlights the one response where Carlos's correct password was submitted.

### Step 4 — Results

Started attack. After completion — one response flagged with "New passwords do not match" match.

**Carlos's password identified** from the payload column of the flagged response.

---

## 3. Login as Carlos

Logged out of wiener's account. Logged in with:
```
Username: carlos
Password: <identified password>
```

Navigated to My account → lab solved.

---

## 4. Attack Flow Summary

```
Login as wiener → intercept POST /my-account/change-password
        ↓
Discover: username is a hidden field (can be modified)
        ↓
Test error messages:
  wrong pwd + different new = "Current password is incorrect"
  correct pwd + different new = "New passwords do not match"
        ↓
Intruder: change username=carlos, current-password=§§
          new-password-1=abc, new-password-2=xyz
Payload: candidate password list
Grep: "New passwords do not match"
        ↓
One flagged response → carlos's password found
        ↓
Login as carlos → My account → solved
```

---

## 5. Why This Attack Is Significant

| Attack Surface | Login Endpoint | Change-Password Endpoint |
|----------------|---------------|-------------------------|
| Brute-force protection | Usually present | Usually absent |
| Rate limiting | Common | Rare |
| Account lockout | Common | Rare |
| Username control | Fixed to session user | Via hidden field |
| Error oracle | Generic messages | Different messages reveal password validity |

Password change functionality is often overlooked in security testing because it's a "post-authentication" feature. But as this lab shows, it can be weaponised against ANY user by manipulating the hidden username field — making it more dangerous than the main login.

---

## 6. Key Takeaways

- **Supplementary functionality is equally critical attack surface** — password change, reset, and update pages often lack the protections on the main login
- **Different error messages create password oracles** — the application intended to help users diagnose mistakes, but the message difference reveals when the current password is correct
- **Hidden fields are not security controls** — `username` in a hidden HTML field is completely attacker-controllable; never trust hidden fields for security decisions
- **Keeping new passwords different prevents lockout** — using identical new passwords locks the account; different values keep the endpoint open for unlimited attempts
- **The session belongs to the attacker — the username doesn't** — being authenticated as wiener but attacking carlos is possible because the change-password endpoint trusts the hidden field over the session
- **Always test error messages for differences** — even a single word difference between two error states can become an oracle

---

## 7. Real-World Relevance

This attack pattern appears when:
- Password change forms accept username as a parameter rather than inferring it from the session
- Different error messages are returned for wrong-username vs wrong-password scenarios
- No rate limiting is applied to password change requests

In bug bounty, always test:
- Can you change the username parameter to another user's account?
- Do error messages differ between "wrong current password" and "password mismatch"?
- Is there rate limiting on the change-password endpoint separately from login?

---

## 8. Remediation

| Finding | Risk | Fix |
|---------|------|-----|
| Username from hidden field not session | Critical | Infer username from authenticated session — never accept it as user input |
| Different error messages reveal password validity | High | Use identical generic error for all failure cases — never reveal which field was wrong |
| No brute-force protection on change-password | High | Apply same rate limiting and lockout to change-password as to login |
| Account lockout only on matching new passwords | Medium | Apply lockout consistently regardless of new password match status |

**Secure implementation:**
```python
def change_password(request):
    # WRONG — trusts user-supplied username
    username = request.POST.get('username')
    
    # CORRECT — get username from authenticated session
    username = request.session.get('authenticated_user')
    
    current = request.POST.get('current-password')
    
    if not verify_password(username, current):
        # Same generic message regardless of reason
        return error("Password change failed")
    
    # proceed with change
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite Professional | Proxy, request interception |
| Burp Intruder | Automated brute-force with grep match |

---

## References

- [PortSwigger — Authentication Vulnerabilities](https://portswigger.net/web-security/authentication)
- [PortSwigger — Other Authentication Mechanisms](https://portswigger.net/web-security/authentication/other-mechanisms)
- [OWASP — Testing for Weak Password Change Functionality](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities)

---

*Write-up by Neelesh Pandey — [GitHub](https://github.com/Neelesh707) | [LinkedIn](https://www.linkedin.com/in/neelesh-pandey021/)*
