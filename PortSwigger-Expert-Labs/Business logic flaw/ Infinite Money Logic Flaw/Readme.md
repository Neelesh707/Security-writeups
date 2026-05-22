# Lab Writeup: Infinite Money Logic Flaw

**Platform:** PortSwigger Web Security Academy  
**Category:** Business Logic Vulnerabilities / Domain-Specific Flaws  
**Difficulty:** Practitioner  
**Status:** ✅ Solved

---

## Table of Contents

1. [Lab Overview](#lab-overview)
2. [Vulnerability Explanation](#vulnerability-explanation)
3. [The Core Logic Flaw](#the-core-logic-flaw)
4. [Step-by-Step Solution](#step-by-step-solution)
5. [Automating with Burp Intruder + Macro](#automating-with-burp-intruder--macro)
6. [Profit Calculation](#profit-calculation)
7. [Root Cause Analysis](#root-cause-analysis)
8. [Remediation](#remediation)
9. [Lessons Learned](#lessons-learned)

---

## Lab Overview

| Field | Details |
|---|---|
| **Objective** | Buy a "Lightweight l33t leather jacket" (~$1337) |
| **Starting Credit** | $100 |
| **Vulnerability Type** | Domain-specific business logic flaw |
| **Attack Method** | Exploit coupon + gift card loop to generate infinite store credit |
| **Credentials** | `wiener:peter` |

---

## Vulnerability Explanation

The application has two features that appear safe individually but are **dangerous when combined**:

| Feature | What it Does |
|---|---|
| `SIGNUP30` Coupon | Gives 30% off any order |
| $10 Gift Cards | Can be purchased and redeemed for store credit |

**The flaw:** The coupon can be applied to gift card purchases, meaning:

```
Buy $10 gift card with 30% off  →  pay $7
Redeem gift card                →  get $10 credit back
Net profit per cycle            →  +$3
```

This loop can be repeated infinitely — turning $100 into unlimited store credit.

---

## The Core Logic Flaw

### What the Developer Assumed
> "Gift cards and discount coupons are independent features — no harm in combining them."

### What Actually Happens

```
Cycle 1:
  Pay $7 (gift card with 30% off)
  Redeem for $10
  Credit: $100 → $103  (+$3)

Cycle 2:
  Pay $7 again
  Redeem for $10
  Credit: $103 → $106  (+$3)

Cycle N (repeated 412 times):
  Credit: $100 + (412 × $3) = $1,336
  Enough to buy the jacket! ✅
```

### Why This is a Domain-Specific Flaw

You only spot this if you understand:
- Gift cards are essentially **cash equivalents**
- Discounting cash equivalents creates a **money printing loop**
- The coupon has **no restriction** on what it can be applied to

---

## Step-by-Step Solution

### Phase 1 — Discover the Flaw Manually

**Step 1** — Sign up for the newsletter to get coupon code:
```
Coupon: SIGNUP30  (30% off any order)
```

**Step 2** — Add a $10 gift card to cart, apply `SIGNUP30`:
```
Gift card price:     $10.00
After 30% discount:   $7.00
You pay:              $7.00
```

**Step 3** — Complete checkout, copy the gift card code from the order confirmation.

**Step 4** — Go to My Account → redeem the gift card code:
```
Credit added: $10.00
Net gain:     +$3.00 per cycle
```

**Step 5** — Study the proxy history and identify the key requests:

```
POST /cart                                    ← add gift card to cart
POST /cart/coupon                             ← apply SIGNUP30
POST /cart/checkout                           ← place order
GET  /cart/order-confirmation?order-confirmed=true  ← get gift card code
POST /gift-card                               ← redeem gift card code
```

---

### Phase 2 — Automate with Burp Macro + Intruder

#### Set Up the Session Handling Macro

**Step 6** — Go to **Settings → Sessions → Session Handling Rules → Add**

**Step 7** — Under **Scope tab** → set URL scope to **"Include all URLs"**

**Step 8** — Under **Details tab → Rule Actions → Add → Run a macro → Add**

**Step 9** — In the Macro Recorder, select these 5 requests in order:
```
1. POST /cart
2. POST /cart/coupon
3. POST /cart/checkout
4. GET  /cart/order-confirmation?order-confirmed=true
5. POST /gift-card
```

**Step 10** — Configure the order confirmation request:
```
Select: GET /cart/order-confirmation?order-confirmed=true
→ Click "Configure item"
→ Click "Add" to create a custom parameter
→ Name: gift-card
→ Highlight the gift card code in the response
→ Click OK
```

**Step 11** — Configure the gift-card redemption request:
```
Select: POST /gift-card
→ Click "Configure item"
→ Parameter handling: set "gift-card" to derive from prior response (response 4)
→ Click OK
```

**Step 12** — Click **"Test macro"** and verify:
```
✅ GET /cart/order-confirmation returns a gift card code
✅ POST /gift-card uses that exact code
✅ POST /gift-card returns a 302 response (success)
```

#### Run the Attack

**Step 13** — Send `GET /my-account` to **Burp Intruder**

**Step 14** — Configure the attack:
```
Attack type:  Sniper
Payload type: Null payloads
Payload count: 412
```

**Step 15** — Configure the resource pool:
```
Maximum concurrent requests: 1  ← IMPORTANT: must be 1 to avoid race conditions
```

**Step 16** — Start the attack and wait for it to complete.

---

## Profit Calculation

| Item | Value |
|---|---|
| Gift card cost (with 30% off) | $7.00 |
| Gift card redemption value | $10.00 |
| Profit per cycle | **+$3.00** |
| Starting credit | $100.00 |
| Cycles needed to buy jacket (~$1337) | ~413 |
| Cycles run (412) | 412 |
| Final credit | $100 + (412 × $3) = **$1,336** |
| Jacket price | ~$1,337 |

> 412 null payloads × $3 profit = $1,236 gained on top of $100 starting credit.

---

## Root Cause Analysis

```
┌─────────────────────────────────────────────────────────────┐
│                    THE FLAW CHAIN                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Gift cards = cash equivalent                               │
│       +                                                     │
│  Coupon applies to ALL products (no exclusions)             │
│       +                                                     │
│  Coupon can be reused (no single-use enforcement)           │
│       =                                                     │
│  INFINITE MONEY LOOP  🚨                                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Individual Features (Each Looks Safe)

```
Gift cards alone:    Buy $10, redeem $10  → zero profit, harmless
Coupon alone:        30% off real goods   → costs the store money but intended
Combined:            30% off gift card    → store loses $3 per cycle, forever
```

### What the Developer Missed

- No check: *"Is this coupon being applied to a cash-equivalent product?"*
- No check: *"Has this coupon already been used by this user?"*
- No rate limiting on gift card purchases or redemptions

---

## Remediation

| Fix | Description |
|---|---|
| **Exclude gift cards from discounts** | Coupons should not apply to cash-equivalent products |
| **Single-use coupon enforcement** | `SIGNUP30` should be usable only once per account |
| **Rate limiting** | Limit gift card purchases/redemptions per time period |
| **Audit coupon applicability** | Define an explicit whitelist of products coupons can apply to |
| **Monitor for abuse patterns** | Alert when store credit grows unusually fast |

---

## Lessons Learned

- Two individually safe features can be **dangerous when combined** — always test feature interactions
- **Cash equivalents** (gift cards, store credit, vouchers) need special protection from discounts
- Domain knowledge is critical — you need to understand that *discounting cash = printing money*
- **Automation** is necessary for slow-burn attacks that require hundreds of repetitions
- Burp Macros are powerful for chaining multi-step workflows into a single automated loop
- Always set concurrent requests to **1** when order of operations matters to avoid race conditions

---

*Writeup by: Neele+sh Pandey*  
*Date: 2026*  
*Reference: https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-infinite-money*
