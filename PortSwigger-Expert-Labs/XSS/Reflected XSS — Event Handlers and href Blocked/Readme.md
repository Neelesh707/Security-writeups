# PortSwigger Expert Lab: Reflected XSS — Event Handlers and href Blocked

**Author:** Neelesh Pandey  
**Platform:** PortSwigger Web Security Academy  
**Difficulty:** Expert  
**Category:** Cross-Site Scripting (XSS) / Filter Bypass / SVG Injection  
**Lab:** Reflected XSS with event handlers and href attributes blocked  

---

## Overview

This Expert lab blocks all event handler attributes (`onclick`, `onmouseover`, `onfocus`, `onload` etc.) AND blocks the `href` attribute on anchor tags — the two most common XSS vectors. The bypass uses SVG's `<animate>` element to **dynamically set the `href` attribute** of an `<a>` tag at render time, injecting a `javascript:` URI without ever having the `href` attribute in the HTML source. When the victim clicks the "Click me" text, `alert(1)` executes.

---

## The Vulnerability

The application uses an allowlist of tags but strips all event handlers and `href` attributes. The flaw is that it checks attributes **statically in the source** but does not account for SVG's `<animate>` element which can **modify attributes dynamically during rendering** — after the static filter has already run.

---

## The Bypass Technique — SVG animate attributeName

### Core Concept

SVG's `<animate>` element can animate (set/change) any attribute of its parent element. By placing `<animate>` inside `<a>`, it sets the `href` of the `<a>` to `javascript:alert(1)` — but this happens during SVG rendering, not in the static HTML that the filter scans.

```
Filter scans HTML source → sees <a> with no href → passes
SVG renderer processes <animate> → sets href=javascript:alert(1) → link now executes JS
```

### Full Payload

```html
<svg>
  <a>
    <animate attributeName=href values=javascript:alert(1) />
    <text x=20 y=20>Click me</text>
  </a>
</svg>
```

**URL-encoded version:**
```
?search=%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E
```

---

## Component Breakdown

| Component | Purpose |
|-----------|---------|
| `<svg>` | Creates SVG context — required for `<animate>` to work |
| `<a>` | Anchor element — no href in source, passes filter |
| `<animate attributeName=href>` | Tells SVG to animate (set) the href attribute of parent `<a>` |
| `values=javascript:alert(1)` | The value to set — javascript: URI executes JS on click |
| `<text x=20 y=20>Click me</text>` | Visible clickable text — lab requires "Click" word to trigger victim |

---

## Why Each Filter Is Bypassed

### Event handlers blocked:
No event handlers used at all. The payload uses SVG animation — a completely different mechanism. `onclick`, `onfocus`, `onerror` — none needed.

### href attribute blocked:
The `<a>` tag in the source has **no href attribute** — it passes the filter. The `<animate>` element sets it dynamically during rendering. The filter never sees `href=javascript:alert(1)` in the source.

### javascript: URI:
Once `<animate>` sets `href=javascript:alert(1)` on the `<a>` tag at render time, clicking the link executes the JavaScript — same as a normal `<a href="javascript:alert(1)">` would.

---

## Attack Flow

```
Standard event handlers → blocked
href attribute on <a>  → blocked
        ↓
Use SVG <animate> to set href dynamically at render time
<animate attributeName=href values=javascript:alert(1) />
        ↓
Filter scans HTML source → no href, no event handler → passes
SVG renderer sets href=javascript:alert(1) on <a>
        ↓
Victim sees "Click me" text
Victim clicks → javascript:alert(1) executes
        ↓
Lab solved
```

---

## How SVG animate Works

The `<animate>` element is part of the SVG specification for creating animations. Key attributes:

- `attributeName` — which attribute of the parent element to animate
- `values` — the value(s) to set (semicolon-separated for multiple frames)
- Without `dur` or `repeatCount` — the animation fires once immediately on load

In this case, the "animation" is a one-time immediate set of `href` to `javascript:alert(1)`. The browser's SVG renderer applies this before the user interacts with the element.

---

## Key Takeaways

- **SVG animate bypasses static attribute filtering** — filters check the source HTML; SVG animate sets attributes at render time after filtering
- **javascript: URI in href executes on click** — once the href is set dynamically, it behaves exactly like a hardcoded `href="javascript:alert(1)"`
- **No event handlers needed** — this payload uses zero event handler attributes, bypassing the entire event handler blocklist
- **SVG context enables powerful attacks** — SVG has its own DOM manipulation capabilities (`<animate>`, `<set>`, `<animateTransform>`) that operate differently from HTML
- **Allowlists can still be bypassed** — even with a tag allowlist, the interaction between allowed tags (SVG + animate + a) creates unexpected behaviour
- **User interaction required here** — this is click-based XSS, not automatic like onfocus + tabindex. The victim must click "Click me"

---

## Comparison — Expert vs Practitioner Tag Blocking Bypass

| Lab | Filter | Bypass | Interaction |
|-----|--------|--------|-------------|
| All tags blocked except custom | Standard tags blocked | Custom tag + onfocus + tabindex + #fragment | None (auto) |
| Event handlers + href blocked | Events + href blocked | SVG animate sets href dynamically | Click required |

---

## Real-World Testing

When event handlers and href are blocked, try:

```html
<!-- SVG animate to set href -->
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click</text></a></svg>

<!-- SVG animate to set other attributes -->
<svg><a><animate attributeName=xlink:href values=javascript:alert(1) /><text>Click</text></a></svg>

<!-- SVG set element (non-animated version) -->
<svg><a><set attributeName=href to=javascript:alert(1) /><text x=20 y=20>Click</text></a></svg>
```

Also worth testing `xlink:href` — older SVG attribute that may be treated differently by filters.

---

## Remediation

| Finding | Risk | Fix |
|---------|------|-----|
| SVG animate bypasses attribute filter | Critical | Parse and sanitise SVG content — strip `<animate>` and `<set>` elements, or block SVG entirely |
| javascript: URI injectable via dynamic attribute | Critical | Block javascript: URI scheme in all href contexts including dynamically set ones |
| Static filter only — no render-time check | Critical | Use a DOM-based sanitiser (DOMPurify) that sanitises after parsing, not just on raw HTML |
| No CSP | High | `script-src 'self'` blocks javascript: URI execution |

**Use DOMPurify — sanitises after parsing:**
```javascript
// WRONG — regex/string filter on raw HTML
const safe = input.replace(/<script/gi, '');

// CORRECT — DOM-based sanitiser processes after parsing
const safe = DOMPurify.sanitize(input);
// DOMPurify removes <animate> elements and javascript: URIs
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite Professional | Proxy, URL encoding |
| Browser | Confirming payload execution |

---

## References

- [PortSwigger — XSS Contexts](https://portswigger.net/web-security/cross-site-scripting/contexts)
- [PortSwigger — XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [SVG animate element — MDN](https://developer.mozilla.org/en-US/docs/Web/SVG/Element/animate)

---

*Write-up by Neelesh Pandey — [GitHub](https://github.com/Neelesh707) | [LinkedIn](https://www.linkedin.com/in/neelesh-pandey021/)*
