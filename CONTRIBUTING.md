# Contributing

Thanks for your interest. This is a small, focused security-research toolkit; contributions that
add detection coverage, reduce false positives, or sharpen the docs are very welcome.

## Ground rules (please read)

This project has two hard constraints baked into its design. PRs that violate either won't be
merged:

1. **Read-only and polite — never adversarial.** The tools fetch and analyze; they **never submit
   an application, post a form, or take any write action**. Network access goes through
   [`httpclient.py`](scanner/httpclient.py): per-host rate limiting, jitter, exponential backoff
   that honors `Retry-After`, on-disk caching, official public APIs first. Do **not** add CAPTCHA
   solving, proxy/IP rotation, auth bypass, or anything whose purpose is evasion. "Not getting
   blocked" here means *courtesy*, not stealth.
2. **No company lists or real postings in the repo.** This is a methodology + tooling repo, not a
   name-and-shame list. Don't commit company names, board tokens tied to a named employer, scraped
   JD bodies, scan-result dumps (`*.json` / `*.csv`), or HTTP caches. The `board` / `sweep` tools
   take targets you supply at runtime. Test fixtures must be **synthetic** (see `scanner/corpus/`).

## Dev setup

The core detectors are stdlib-only. For tests and the render pass:

```bash
pip install pytest                       # tests
pip install playwright && playwright install chromium   # render-gated pass (optional)
```

## Running the suite

```bash
python3 -m pytest            # offline: corpus regression + HTTP-core unit tests
python3 scanner/detect.py    # detector self-test on synthetic cases
python3 scanner/httpclient.py  # HTTP-core self-test (fake clock, no network)
```

## Adding a detection vector

1. Add the matcher to [`detect.py`](scanner/detect.py) (or the base
   [`jd_injection_scanner.py`](scanner/jd_injection_scanner.py) for structural/Unicode vectors).
   Keep the **severity (payload intent) × confidence (evasion technique)** model; gate anything
   that could fire on ordinary prose (require an AI/automation addressee).
2. Add a **synthetic** fixture to `scanner/corpus/` demonstrating the vector — and, if it's a
   "hidden" technique, ideally a benign near-twin so the precision tests have something to bite on.
3. Categorize the new fixture in `tests/test_detectors.py` (the `test_every_corpus_file_is_covered`
   guard will fail until you do) and make the suite pass.
4. If it's a new technique class, add a row to [docs/threat-model.md](docs/threat-model.md) with a
   public citation where one exists.

## Style

- Match the surrounding code: stdlib-first, small functions, no new hard dependencies in the core.
- Keep optional capabilities **feature-gated** (import inside the function; print an install hint
  and degrade gracefully when a dependency is missing).
