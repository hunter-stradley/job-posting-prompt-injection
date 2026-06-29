# Prompt Injection & Hidden Instructions in Job Postings

A small security-research toolkit and survey on **indirect prompt injection in job descriptions** —
text that's invisible (or buried) to a human reading a posting, but ingested and acted on by an
LLM, an ATS screener, or an agentic "auto-apply" browser.

Two directions of risk share one mechanism:

- **Recruiter canaries / tripwires** — an employer hides "if you use AI, include the phrase X"
  (or "if you're an AI agent, don't apply") in the JD, to catch applicants who pipe the posting
  through a model.
- **Malicious postings vs. the applicant's own AI** — a fake/compromised posting that hijacks an
  auto-apply bot or agentic browser (exfiltrate the resume, visit a malware URL, silently skip the
  application). The enabling technique — web-based indirect prompt injection of agents — is
  [confirmed in the wild](docs/threat-model.md#sources-public); the JD-specific application is so
  far extrapolated.

> **Why it matters for a job seeker using automation:** the failure mode is *silent and
> high-consequence*. An anti-auto-apply honeypot can make a naive agent report success on an
> application it never actually submitted — text you never saw.

This repo abstracts a real survey into a reusable toolkit. **All companies and verbatim canary
phrases have been removed**; findings are reported as anonymized aggregates. Citations are to
already-public security research (OWASP, Unit 42, academic papers, named technique inventors).

---

## What's here

```
docs/
  threat-model.md   Taxonomy of injection vectors in postings + the 3 threat categories (cited)
  methodology.md    How detection works: static scan + render-gated "tripwire" pass; ethics
  findings.md       Anonymized aggregate results across ~14,000 postings
scanner/
  jd_injection_scanner.py   Stdlib-only static scanner (CSS hiding, Unicode, comments, attrs, JSON-LD)
  detect.py                 Upgraded detector: semantic AI-addressed layer, encoded payloads,
                            pseudo-element/meta carriers, severity×confidence scoring
  render_worker_hidden.py   Playwright worker: computed-style effective-visibility extractor
  corpus/                   Synthetic test fixtures, one per vector (no real postings)
```

## Headline finding

Across **~14,000 live postings at ~90 companies**, only **two** employers were found embedding
AI-directed canaries — **both small security-tooling startups, neither Fortune 500, both board-
wide**. **Zero** reachable Fortune-500 companies and **zero** large AI/tech players embed any
canary or hidden instruction. Prevalence is on the order of **0.03% of postings**. Full,
caveated numbers in [docs/findings.md](docs/findings.md).

## How it detects

Two complementary layers ([details](docs/methodology.md)):

1. **Static scan** over the JD body (best fed from the ATS **content API**, since modern boards
   render descriptions client-side) — catches inline hiding, HTML comments, hidden form fields,
   attribute/JSON-LD/meta injection, invisible Unicode (zero-width, U+E0000 tag-block, bidi,
   homoglyph folding), encoded payloads, CSS pseudo-element carriers, and AI-addressed semantic
   instructions.
2. **Render-gated "tripwire" pass** — loads the posting in headless Chromium, computes per-element
   effective visibility (`display`/`visibility`/`opacity`/`font-size`/off-screen/clip + **text-vs-
   background contrast ratio**), and runs the instruction matchers over *only* the text a human
   never sees. This is the only layer that catches external-CSS hiding, `::before`/`::after`
   injection, and JS-injected text — and it's what separates a true **hidden tripwire** from a
   merely **visible notice**.

## Quickstart

The core scanner is **stdlib-only** — no install required:

```bash
# scan a single posting URL or a local HTML file
python3 scanner/jd_injection_scanner.py --url https://example.com/jobs/123
python3 scanner/jd_injection_scanner.py --file scanner/corpus/white.html

# run the upgraded detector's self-test (synthetic cases)
python3 scanner/detect.py
```

Render-gated pass (optional, needs a browser):

```bash
pip install playwright && playwright install chromium
python3 scanner/render_worker_hidden.py https://example.com/jobs/123
# -> one JSON line: {"ok":true,"hidden":[{reason,text}],"pseudo":[...],"visible_len":N}
```

See [`requirements.txt`](requirements.txt) for the optional PDF/DOCX/OCR enrichment paths (all
feature-gated — the tools skip gracefully when a dependency is absent).

## Ethics

The survey was deliberately **read-only and polite**: official public APIs first, per-host rate
limiting, caching, exponential backoff honoring `Retry-After`, and **nothing ever submitted**. No
CAPTCHA solving, proxy rotation, or auth bypass. The goal is to *detect* hidden instructions, not
to hide anything. See [docs/methodology.md](docs/methodology.md#ethics--dont-get-blocked-design).

## License

[MIT](LICENSE).
