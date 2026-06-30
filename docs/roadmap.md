# Roadmap & 2026 threat trajectory

Where posting/agent prompt-injection is heading, and how this toolkit tracks it. Grounded in
public 2025–2026 research (cited inline). This is a living document.

## The shift: from tripwire to live exploitation

The original survey in [findings.md](findings.md) found employer canaries to be *rare* and the
"malicious posting vs. the applicant's agent" threat to be *theoretical*. That second condition is
closing fast:

- **Indirect prompt injection is now observed in the wild and rising.** Google reported a ~32%
  relative increase in malicious web-based injection activity between late 2025 and early 2026.
- **Agentic browsers are being actively exploited** with the exact hidden-text vectors this scanner
  targets: independent researchers showed an agentic browser executing cross-site actions (reading
  one-time passwords from email, hitting banking portals) from instructions hidden in invisible
  page elements on a "summarize this page" request; another class ("WebPromptTrap") hides
  instructions in off-screen / low-opacity HTML the agent ingests during summarization.
- **Auto-apply bots and agentic browsers read posting text and act with the user's privileges** —
  so the job-seeker-using-automation risk is no longer hypothetical. The high-consequence failure
  is silent (an anti-auto-apply honeypot making an agent *report* a submission it never made).

## Where the modality is going

- **Multimodal / image postings.** Vision models cannot separate visual content from instructions
  painted into it (CSA, 2026); typographic image injection reached high black-box success rates
  against frontier multimodal models. → covered by [`multimodal.py`](../scanner/multimodal.py)
  (OCR + contrast pass + best-effort LSB stego).
- **Documents (PDF/DOCX).** Hidden-prompt detection in structured documents is an active research
  target (PhantomLint, arXiv 2508.17884). → covered by `multimodal.py` (white/tiny/off-page text +
  metadata).
- **MCP / tool-use.** Tool-poisoning (CVE-2025-54136; OWASP MCP Top 10, 2025) plants instructions
  in tool *descriptions* that carry developer-level authority. Adjacent channel as job tools gain
  MCP integrations. → *watch-list, not yet covered.*
- **Newer text smuggling.** Unicode variation-selector smuggling and fuller homoglyph/confusable
  evasion. → covered by the extended vectors in [`jd_injection_scanner.py`](../scanner/jd_injection_scanner.py).

## Where the defenses are going

- **OWASP LLM01:2025** keeps prompt injection at #1 and now flags multimodal injection; the OWASP
  "LLM Prompt Injection Prevention" cheat sheet pushes data-marking / spotlighting and segregating
  untrusted content. → the [sanitizer](../scanner/sanitize.py) implements data-marking;
  [`report.py`](../scanner/report.py) maps findings to LLM01:2025 in SARIF.
- **The hard consensus: detection is not a solution.** A 2026 study evaded six commercial guardrail
  detectors up to 100% via character injection; an SoK concluded no guardrail category reliably
  stops prompt injection. The "real" fix is architectural — capability-based / dual-LLM designs
  (CaMeL, "Defeating Prompt Injections by Design," arXiv 2503.18813) and agent sandboxing — measured
  on benchmarks like **AgentDojo** (arXiv 2406.13352). → this informs our framing (below) and the
  [agent-hijack harness](../harness/harness_run.py), which is modeled on AgentDojo's metrics.
- **Content provenance (C2PA)** added unstructured-text/LLM-output manifests in v2.3 (Dec 2025);
  major vendors aligned on C2PA + watermarking in 2026. Promising but round-tripping through the web
  is unsolved — too nascent to depend on. → *watch-list.*

## Detection is triage, not a guarantee

This toolkit is a **detection / triage** layer. The research above is clear that text-level
detection and guardrails can be bypassed; they reduce risk and surface the obvious cases, but the
durable fix for an agent that ingests untrusted postings is **architectural** — give the agent no
capability to act on injected instructions (capability/sandboxing, dual-LLM, human-in-the-loop for
sensitive actions). Use this scanner to *triage and sanitize*, not as a safety guarantee.

## Candidate next steps (not yet built)

- MCP tool-description scanning (apply the same matchers to tool manifests).
- Audio posting OCR/ASR path; richer stego (DCT/DWT) beyond LSB.
- A real-LLM mode for the harness (currently mock/offline) against AgentDojo-style tasks.
- C2PA-for-text read/verify hook once web round-tripping stabilizes.
- Expand the benchmark with adversarially-mutated variants (character injection, paraphrase).
