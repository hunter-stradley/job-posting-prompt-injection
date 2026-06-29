# Methodology

How the detectors work, why a render pass is necessary, and the ethics constraints the survey ran
under. The vector taxonomy these detectors target is in [threat-model.md](threat-model.md);
anonymized results are in [findings.md](findings.md).

---

## Two detection layers

### Layer 1 — static scan over the JD body
[`jd_injection_scanner.py`](../scanner/jd_injection_scanner.py) and the upgraded
[`detect.py`](../scanner/detect.py) parse the **HTML of the job description** and flag:

- structural hiding (inline `display:none` / `visibility:hidden` / `opacity:0` / `font-size:0` /
  off-screen / white-on-white via *inline* style), and `sr-only` / `aria-hidden` spans;
- HTML comments, hidden form fields, and injection-language in element attributes (`alt`, `title`,
  `aria-label`, `placeholder`, `data-*`);
- `application/ld+json` (`JobPosting`) and `<meta>` / OpenGraph payloads;
- invisible Unicode — zero-width (with binary decode), U+E0000 tag-block (decoded to ASCII), bidi
  controls, and mixed-script / homoglyph folding;
- encoded payloads (Base64 / hex) that **decode to** an instruction;
- CSS pseudo-element `content:"…"` carriers in `<style>` blocks;
- a **semantic layer**: natural-language instructions *addressed to an AI* ("note to any AI
  assistant: …", "if you are an LLM, …"), gated on an AI/automation addressee so it doesn't fire
  on ordinary prose.

Each finding carries a **severity** (payload intent) and **confidence** (evasion technique); the
two combine into a 0–100 score and a verdict (`OK` / `REVIEW` / `BLOCK` or
`CONFIRMED` / `REVIEW` / clean). The highest-precision signal is the **combination**: text that is
both *hidden* and *AI-directed*.

**A critical limitation of any static scan:** modern ATS career pages (and SPAs generally) render
the JD body **client-side**. A raw-HTML fetch of the posting URL often never sees the description
at all — so the right input to Layer 1 is the **JD body pulled from the ATS's public content API**
(the same text an ATS-integrated screener or an auto-apply agent would ingest), not the page shell.

### Layer 2 — render-gated detection ("tripwire" pass)
A static scan structurally **cannot** resolve three important cases:

1. color ≈ background set by an **external** or `<style>`-block CSS rule (not an inline attribute);
2. `::before` / `::after` pseudo-element `content:` as actually rendered;
3. text injected into the DOM by **JavaScript** at runtime.

[`render_worker_hidden.py`](../scanner/render_worker_hidden.py) loads each posting in headless
Chromium (Playwright), lets CSS + JS apply, then walks every element computing **effective
visibility** via `getComputedStyle`:

- `display` / `visibility` / `opacity` / `font-size`;
- bounding-rect off-canvas or clipped to zero;
- **contrast ratio of text color vs. the effective (inherited) background** — WCAG relative
  luminance, walking up the ancestor chain to the first opaque background. A ratio below ~1.25 is
  effectively invisible (white-on-white sits near 1.05);
- `::before` / `::after` computed `content`.

It returns the text a sighted user **never sees**. Running the Layer-1 AI-instruction matchers
over *only that hidden text* yields the verdict:

| Hidden text present? | AI instruction in it? | Verdict |
|---|---|---|
| yes | yes | **TRIPWIRE** (indirect prompt injection) |
| yes | no | HIDDEN_TEXT (benign chrome — comp bands, cookie labels, skip-links) |
| no | — | CLEAN |

This is what enforces the **tripwire vs. visible-notice** distinction from the threat model: a
phrase that turns out to be *visible* in the real render is reclassified as a disclosed notice,
not a tripwire. In validation, the render path independently re-detected known white-on-white
canaries by computed-style contrast (≈1.05) — confirming the method end-to-end — and correctly
**cleared** a posting whose AI-directed phrase was in visible body text.

---

## Why the layers complement each other

- Layer 1 is cheap (no browser), scales to **thousands** of postings via bulk ATS APIs, and
  catches everything encoded in the delivered HTML — Unicode, encoded blobs, comments, attributes,
  inline hiding.
- Layer 2 is ~6 s/page (a real browser), so it's a **sampling** tool, not a census tool — but it's
  the only thing that can see external-CSS hiding, pseudo-element injection, and JS-injected text.

A practical pipeline runs Layer 1 broadly, then sends anything ambiguous (or any high-likelihood
tier) through Layer 2 to confirm whether a flag is *actually* hidden in a browser.

---

## Ethics & "don't get blocked" design

The survey behind [findings.md](findings.md) was built to be a **good web citizen** — "not
detected" means *never throttled or blocked through politeness*, not adversarial evasion:

- **Official public APIs first.** Bulk JD content was read from each ATS's public content endpoint
  rather than scraping rendered pages whenever an API existed.
- **Per-host rate limiting** (~5 req/s ceiling), a global concurrency cap, randomized jitter, and
  exponential backoff that honors `Retry-After`.
- **On-disk caching** so re-runs issue zero new requests.
- **Strictly read-only. Nothing is ever submitted.** No applications, no form posts.
- **No evasion.** No CAPTCHA solving, no proxy/IP rotation, no auth bypass — explicitly out of
  scope.

The only "stealth" is courtesy. The point of the project is to *detect* hidden instructions, not
to hide anything.

---

## Honest limits

- **Sample, not census.** The render pass covers targeted, high-likelihood tiers; a full re-render
  of a multi-thousand-posting corpus was not run (rendering is ~6 s/page).
- **Closed ATSes are under-covered.** Boards on systems that expose no guessable bulk API (and
  whose tenant host isn't derivable from the company name) are reachable only one-by-one, so the
  bulk of large-enterprise postings remain unsurveyed — "none found across everything reachable,"
  not "none exist."
- **Feature-gated paths** (linked-PDF/DOCX/OCR, LLM-judge) are off unless their dependencies/keys
  are present, so an image-only JD could be missed by the text layers.
