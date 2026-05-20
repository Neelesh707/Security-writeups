# PortSwigger Lab Writeup: Low-Level Logic Flaw

**Difficulty:** Practitioner  
**Category:** Business Logic Vulnerabilities  
**Lab URL:** [Access Lab](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-low-level)

---

## 🎯 Objective

Exploit a low-level logic flaw in the purchasing workflow to buy a **"Lightweight l33t Leather Jacket"** for an unintended price.

**Credentials:** `wiener:peter`

---

## 🧠 Vulnerability Explanation

The application stores prices as integers (in cents). When a sufficiently large number of items are added to the cart, the cumulative price exceeds the maximum value of a signed 32-bit integer (`2,147,483,647`). This causes an **integer overflow**, wrapping the value around to the minimum (`-2,147,483,648`) and counting back up toward zero — resulting in a **negative total price**.

By carefully controlling the number of items added, we can make the total price land between **$0 and $100** (our store credit), allowing us to "buy" an expensive item essentially for free.

**Jacket price:** $1,337.00 (stored as `133700` cents)

---

## 🛠️ Tools Required

- Burp Suite (Community or Pro)
  - Proxy
  - Repeater
  - Intruder

---

## 📋 Step-by-Step Solution

### Step 1 — Observe the Normal Flow

1. Log in with `wiener:peter`.
2. Add the **Lightweight l33t Leather Jacket** to your cart and attempt to place the order.
3. The order is rejected — your store credit ($100) is far less than the jacket price ($1,337).
4. In **Proxy → HTTP History**, locate the `POST /cart` request and send it to **Repeater**.

---

### Step 2 — Identify the Input Constraint

In Burp Repeater, inspect the `POST /cart` request. The `quantity` parameter only accepts values up to **99** per request (2-digit max). This is a client-side/server-side constraint that limits how many items can be added in one shot — but there is no limit on *how many times* you can send the request.

Send the request to **Intruder**.

---

### Step 3 — Trigger the Integer Overflow (Phase 1)

**Goal:** Keep adding 99 jackets repeatedly until the total price overflows and goes negative.

1. In Intruder, click anywhere in the request body in an empty area (no parameter needs to be highlighted — we're using Null payloads).
2. In the **Payloads** panel:
   - Payload type: **Null payloads**
   - Under Payload configuration: select **Continue indefinitely**
3. Start the attack.
4. While the attack runs, open your cart in the browser and **keep refreshing**.
5. Watch the total price. Eventually it jumps to a **large negative number** (around `-$2,147,483.648`) and starts counting back up toward zero.
6. **Stop the Intruder attack** once you see a negative price.

> 💡 **Why this happens:** 99 jackets × 133700 cents = 13,236,300 cents per request. After enough requests, the cumulative total exceeds `2,147,483,647` (INT_MAX), wrapping around to the minimum signed integer value.

---

### Step 4 — Clear the Cart

Clear your cart completely. We need to start fresh and add a *precise* number of jackets to land the price in the $0–$100 range.

---

### Step 5 — Calculate the Exact Number of Payloads Needed

We need the final price to be between `0` and `10000` cents (i.e., $0.00–$100.00).

**The math:**

- INT_MAX = `2,147,483,647`
- INT_MIN = `-2,147,483,648`
- Full overflow range = `4,294,967,296` (2³²)
- Jacket price = `133700` cents
- Each Intruder payload adds `99 × 133700 = 13,236,300` cents

We want the total to land just above zero after overflow:

`4,294,967,296 / 133700 ≈ 32,127.xx jackets` needed for one full wrap

To get a manageable remainder, we use:

- **323 Intruder payloads** (each adding 99 jackets = 32,077 jackets total via Intruder)
- **+ 47 jackets manually** via Repeater

This gives us a negative total of approximately **-$1,221.96**.

---

### Step 6 — Run Phase 2 Intruder Attack (Controlled)

1. Re-add the jacket to your cart with `quantity=99` and send the `POST /cart` request to Intruder again.
2. In the **Payloads** panel:
   - Payload type: **Null payloads**
   - Under Payload configuration: generate exactly **`323` payloads**
3. Click **Resource pool** tab → Create a new resource pool with **Maximum concurrent requests = 1** (this ensures sequential, ordered requests to avoid race conditions).
4. Start the attack and wait for it to finish.

---

### Step 7 — Add the Final 47 Jackets

1. Go back to the `POST /cart` request in **Burp Repeater**.
2. Change `quantity=47` and send the request.
3. Check your cart — the total should now show approximately **-$1,221.96**.

---

### Step 8 — Bring the Total into the $0–$100 Range

The total is negative, so we need to add more items to bring it back up to between $0 and $100 (to match our store credit).

1. Find another cheap item in the store (e.g., a cheap product).
2. Use Burp Repeater to add the right quantity of that item so that the cart total lands **between $0.00 and $100.00**.
3. Keep adjusting the quantity until the total is just right.

---

### Step 9 — Place the Order

With the cart total between $0 and $100, click **Place Order**.

✅ **Lab Solved!**

---

## 📊 Summary Table

| Phase | Action | Tool |
|-------|--------|------|
| 1 | Observe cart request | Burp Proxy |
| 2 | Note 2-digit quantity limit | Burp Repeater |
| 3 | Overflow the integer (indefinite) | Burp Intruder |
| 4 | Clear cart | Browser |
| 5 | Controlled overflow (323 payloads, 1 thread) | Burp Intruder |
| 6 | Add final 47 jackets | Burp Repeater |
| 7 | Add cheap items to hit $0–$100 | Burp Repeater |
| 8 | Place order | Browser |

---

## 🔑 Key Takeaways

- **Integer overflow** is a real-world vulnerability in financial/e-commerce applications.
- Server-side validation must check for **cumulative totals**, not just per-request quantities.
- Prices should use **arbitrary-precision arithmetic** or safe integer libraries, not raw 32-bit signed integers.
- Always validate that a final order total is **positive and within expected bounds** before accepting payment.

---

## 📚 References

- [PortSwigger: Logic Flaws](https://portswigger.net/web-security/logic-flaws)
- [Integer Overflow – OWASP](https://owasp.org/www-community/vulnerabilities/Integer_overflow_error)
- [CWE-190: Integer Overflow](https://cwe.mitre.org/data/definitions/190.html)
