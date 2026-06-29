#!/usr/bin/env python3
"""
scan.py -- one entry point for the job-posting injection toolkit.

Subcommands
-----------
    scan.py file   <path>          static scan of a local HTML file
    scan.py url    <url>           fetch (polite/cached) + static scan one posting
    scan.py board  <ats> <token>   pull a whole board via its public API + scan every JD
    scan.py render <url>           render-gated "tripwire" pass (needs playwright)

`file`/`url`/`board` run the static + semantic detectors ([detect.py]). `render` loads the
page in a headless browser ([render_worker_hidden.py]), extracts the text a human never sees,
and runs the AI-instruction matchers over ONLY that hidden text -> TRIPWIRE / HIDDEN_TEXT / CLEAN.

The toolkit ships no company lists: for `board`, you supply the board's own slug/token.
Everything is read-only; nothing is ever submitted.
"""
import sys, os, json, argparse, subprocess

import detect as DET
import jd_injection_scanner as S


# --------------------------------------------------------------------- static
def _scan_html(html_text, source):
    findings = DET.detect(html_text)
    label, top = DET.classify(findings)
    score = DET.score(findings)
    print(f"{source}")
    print(f"  score={score}  label={label or 'CLEAN'}  findings={len(findings)}")
    if top:
        print(f"  top: vector={top[0]} severity={top[2]} confidence={top[3]}")
        print(f"       evidence={top[1][:160]!r}")
    # exit non-zero when something instruction-shaped was confirmed (handy in CI/hooks)
    return 2 if label == "CONFIRMED" else (1 if label == "REVIEW" else 0)


def cmd_file(args):
    with open(args.path, encoding="utf-8", errors="replace") as f:
        return _scan_html(f.read(), args.path)


def cmd_url(args):
    from httpclient import Client
    c = Client(cache_dir=args.cache, rate_per_host=args.rate, max_concurrency=2)
    r = c.get(args.url)
    if r["status"] != 200 or not r["text"]:
        print(f"{args.url}\n  fetch failed (status={r['status']}) -- "
              f"note: many boards render the JD client-side; try `board` with the ATS token.")
        return 3
    return _scan_html(r["text"], args.url)


# ---------------------------------------------------------------------- board
def cmd_board(args):
    from httpclient import Client
    import ats as ATS
    c = Client(cache_dir=args.cache, rate_per_host=args.rate, max_concurrency=args.workers)
    recs = ATS.fetch_board(c, args.ats, args.token, max_jobs=args.max_jobs)
    errs = [r for r in recs if "_error" in r]
    good = [r for r in recs if "_error" not in r]
    if errs and not good:
        print(f"board {args.ats}:{args.token} -- error: {errs[0]['_error']}")
        return 3
    hits = []
    for r in good:
        scanned = DET.scan_record(r)         # drops jd_html, adds label/score/top_finding
        if scanned["label"]:
            hits.append(scanned)
    print(f"board {args.ats}:{args.token}  jobs_scanned={len(good)}  flagged={len(hits)}")
    for h in sorted(hits, key=lambda x: -x["score"]):
        tf = h.get("top_finding") or {}
        print(f"  [{h['label']:9} score={h['score']:3}] {h['title'][:60]}")
        print(f"      {tf.get('vector','')}: {(tf.get('evidence','') or '')[:120]!r}")
        if h.get("url"):
            print(f"      {h['url']}")
    print(f"http stats: {c.report()}")
    return 2 if any(h["label"] == "CONFIRMED" for h in hits) else (1 if hits else 0)


# --------------------------------------------------------------------- render
def _classify_hidden(hidden, pseudo):
    """A hidden text node that is ALSO AI-instruction-shaped == an indirect-injection tripwire."""
    def is_instruction(t):
        return bool(S.INJECTION_RE.search(t) or DET.SEMANTIC_RE.search(t))
    tripwires = [h for h in hidden if is_instruction(h.get("text", ""))]
    tripwires += [p for p in pseudo if is_instruction(p.get("text", ""))]
    if tripwires:
        return "TRIPWIRE", tripwires
    if hidden or pseudo:
        return "HIDDEN_TEXT", (hidden + pseudo)
    return "CLEAN", []


def cmd_render(args):
    worker = os.path.join(os.path.dirname(os.path.abspath(__file__)), "render_worker_hidden.py")
    try:
        proc = subprocess.run([sys.executable, worker, args.url],
                              capture_output=True, text=True, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        print(f"{args.url}\n  render timed out after {args.timeout}s")
        return 3
    try:
        out = json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        print(f"{args.url}\n  render worker produced no JSON. stderr:\n{proc.stderr[:300]}")
        return 3
    if not out.get("ok"):
        print(f"{args.url}\n  render failed: {out.get('error')}\n"
              f"  (need: pip install playwright && playwright install chromium)")
        return 3
    hidden, pseudo = out.get("hidden", []), out.get("pseudo", [])
    verdict, evidence = _classify_hidden(hidden, pseudo)
    print(f"{args.url}")
    print(f"  verdict={verdict}  hidden_nodes={len(hidden)}  pseudo={len(pseudo)}  "
          f"visible_len={out.get('visible_len', 0)}")
    for e in evidence[:8]:
        print(f"    [{e.get('reason') or e.get('pe','pseudo')}] {e['text'][:140]!r}")
    return 2 if verdict == "TRIPWIRE" else (1 if verdict == "HIDDEN_TEXT" else 0)


def main():
    ap = argparse.ArgumentParser(description="Scan job postings for hidden / AI-directed instructions.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("file", help="static scan of a local HTML file")
    p.add_argument("path"); p.set_defaults(func=cmd_file)

    p = sub.add_parser("url", help="fetch + static scan one posting URL")
    p.add_argument("url"); p.add_argument("--cache", default="cache"); p.add_argument("--rate", type=float, default=2.0)
    p.set_defaults(func=cmd_url)

    p = sub.add_parser("board", help="pull a whole board via its public API + scan every JD")
    p.add_argument("ats"); p.add_argument("token")
    p.add_argument("--max-jobs", type=int, default=None); p.add_argument("--workers", type=int, default=4)
    p.add_argument("--cache", default="cache"); p.add_argument("--rate", type=float, default=4.0)
    p.set_defaults(func=cmd_board)

    p = sub.add_parser("render", help="render-gated tripwire pass (needs playwright)")
    p.add_argument("url"); p.add_argument("--timeout", type=int, default=60)
    p.set_defaults(func=cmd_render)

    args = ap.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
