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

> [!IMPORTANT]
> **Detection is triage, not a guarantee.** 2026 research is clear that text-level detection and
> guardrails can be bypassed; they reduce risk and surface the obvious cases, but the durable fix
> for an agent that ingests untrusted postings is *architectural* — deny it the capability to act
> on injected instructions (capability/sandboxing, dual-LLM à la CaMeL, human-in-the-loop for
> sensitive actions). Use this scanner to triage and [sanitize](docs/methodology.md), not as a
> safety guarantee. See [docs/roadmap.md](docs/roadmap.md).

---

## What's here

```
docs/
  threat-model.md   Taxonomy of injection vectors in postings + the 3 threat categories (cited)
  methodology.md    How detection works: static scan + render-gated "tripwire" pass; ethics; triage caveat
  findings.md       Anonymized aggregate results across ~14,000 postings
  roadmap.md        2026 threat trajectory (agentic browsers, multimodal, MCP, CaMeL) + next steps
scanner/
  scan.py                   Unified CLI: file / url / board / render / image / pdf / docx / sanitize
  jd_injection_scanner.py   Stdlib static scanner (CSS hiding, Unicode incl. variation-selector, confusables, comments, attrs, JSON-LD)
  detect.py                 Upgraded detector: semantic AI-addressed layer, encoded payloads, structured-data pass, scoring
  multimodal.py             Image (OCR + contrast + LSB stego) and PDF/DOCX hidden-text detection (feature-gated)
  ingestion_diff.py         Generalized human-visible vs machine-ingested text diff
  sanitize.py               Pre-ingestion sanitizer: strip hidden/AI-directed text + spotlight-wrap (job-seeker tool)
  report.py                 SARIF 2.1.0 / JSON serializer, mapped to OWASP LLM01:2025
  render_worker_hidden.py   Playwright worker: computed-style effective-visibility extractor
  httpclient.py             Polite, cached, rate-limited stdlib HTTP core
  ats.py                    Bulk connectors for public ATS content APIs (you supply the token)
  sweep.py                  Drive ats→detect across many boards from a manifest/TSV → JSON+CSV
  corpus/                   Synthetic test fixtures, one per vector (no real postings)
harness/                    Simulated, offline agent-hijack rig (AgentDojo-style BU/UA/ASR metrics)
benchmark/                  Labeled synthetic dataset + metrics runner → results.md
tests/                      pytest suite (detectors, multimodal, vectors, harness, benchmark, sanitizer, SARIF)
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

## Usage

The core is **stdlib-only** — no install required. `scan.py` is the single entry point:

```bash
cd scanner

# static scan a local HTML file or a live posting URL
python3 scan.py file corpus/white.html
python3 scan.py url https://example.com/jobs/123

# scan a whole board via its public ATS content API (you supply the board's own token).
# ats in: greenhouse | ashby | lever | recruitee | smartrecruiters | workday | workable
python3 scan.py board greenhouse <board-token>

# render-gated "tripwire" pass (needs a browser; see below)
python3 scan.py render https://example.com/jobs/123

# multimodal / document postings (feature-gated deps; see requirements.txt)
python3 scan.py image posting.png      # OCR + contrast pass + LSB-stego heuristic
python3 scan.py pdf   posting.pdf      # white/tiny/off-page text + metadata
python3 scan.py docx  posting.docx     # hidden/vanish/white runs + properties

# emit OWASP-LLM01-mapped SARIF (or json) for code-scanning dashboards / CI
python3 scan.py file corpus/white.html --format sarif

# job-seeker protection: emit a SAFE, spotlighted JD to feed an auto-apply/agent tool
python3 scan.py sanitize --file posting.html
```

Exit codes are CI/hook-friendly: `0` clean, `1` REVIEW / hidden-text, `2` CONFIRMED / TRIPWIRE,
`3` could-not-fetch/render. Modern boards render the JD client-side, so prefer `board` (reads the
ATS **content API** — the same text an agent or screener ingests) over `url` (raw page fetch).

**Prove the consequence** — the offline agent-hijack harness shows a hidden instruction actually
changing a (simulated) agent's behavior, and that a guard stops it:

```bash
python3 harness/harness_run.py     # AgentDojo-style benign-utility / utility-under-attack / attack-success-rate
```

**Benchmark** the detector against the labeled synthetic dataset (writes `benchmark/results.md`):

```bash
python3 benchmark/run_benchmark.py   # precision / recall / F1 + per-vector confusion
```

**Bulk survey** across many boards — supply your own targets (the repo ships no company lists):

```bash
# TSV on stdin: "ats<TAB>token<TAB>label"
printf 'greenhouse\t<token>\tExample Co\n' | python3 sweep.py --out results
# or a JSON manifest: [{"company","ats","token"}, ...]
python3 sweep.py --manifest boards.json --out results
# -> results.json (summary + hits) and results.csv (one row per finding)
```

**Render-gated pass** (optional, needs a headless browser):

```bash
pip install playwright && playwright install chromium
```

The `render` subcommand drives [`render_worker_hidden.py`](scanner/render_worker_hidden.py), which
computes per-element effective visibility (incl. text-vs-background contrast) and returns the text
a human never sees; it degrades gracefully with an install hint if Playwright is absent. See
[`requirements.txt`](requirements.txt) for the other optional (feature-gated) PDF/DOCX/OCR paths.

**Tests:**

```bash
pip install pytest && python3 -m pytest      # offline suite, no network/browser (some multimodal tests need optional deps)
```

## Ethics

The survey was deliberately **read-only and polite**: official public APIs first, per-host rate
limiting, caching, exponential backoff honoring `Retry-After`, and **nothing ever submitted**. No
CAPTCHA solving, proxy rotation, or auth bypass. The goal is to *detect* hidden instructions, not
to hide anything. See [docs/methodology.md](docs/methodology.md#ethics--dont-get-blocked-design).

## License

[MIT](LICENSE).
