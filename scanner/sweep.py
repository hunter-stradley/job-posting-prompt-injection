#!/usr/bin/env python3
"""
sweep.py -- drive ats -> detect across a set of boards and aggregate results.

You supply the targets (this repo ships no company lists). Input is either a boards
manifest (JSON list of {company, ats, token[, status]}) OR a simple TSV on stdin
("ats<TAB>token<TAB>company"). For each reachable board, pull every posting (full JD)
and run the upgraded detector. Emit:
  * <out>.json  -- per-company summary + every CONFIRMED/REVIEW hit
  * <out>.csv   -- flat one-row-per-hit table

Honest accounting: companies with no reachable board are recorded as coverage gaps.
"""
import sys, json, csv, argparse, concurrent.futures as cf
from httpclient import Client
import ats as ATS
import detect as DET


def scan_board(client, company, ats_name, token, max_jobs):
    recs = ATS.fetch_board(client, ats_name, token, company=company, max_jobs=max_jobs)
    errs = [r for r in recs if "_error" in r]
    good = [r for r in recs if "_error" not in r]
    hits = []
    for r in good:
        scanned = DET.scan_record(r)          # drops jd_html
        if scanned["label"]:                  # CONFIRMED or REVIEW
            hits.append(scanned)
    return {
        "company": company, "ats": ats_name, "token": token,
        "jobs_scanned": len(good),
        "error": errs[0]["_error"] if errs else None,
        "hits": hits,
    }


def load_targets(args):
    targets = []
    if args.manifest:
        for r in json.load(open(args.manifest)):
            if r.get("ats") and r.get("token"):
                targets.append((r["company"], r["ats"], r["token"]))
    else:
        for line in sys.stdin:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                ats_name, token = parts[0], parts[1]
                company = parts[2] if len(parts) > 2 else token
                targets.append((company, ats_name, token))
    return targets


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest")
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-jobs", type=int, default=None, help="cap per board (None=all for bulk ATS)")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--rate", type=float, default=4.0)
    a = ap.parse_args()

    targets = load_targets(a)
    client = Client(cache_dir="cache", rate_per_host=a.rate, max_concurrency=a.workers)
    results, done = [], 0
    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = {ex.submit(scan_board, client, c, ats_n, tok, a.max_jobs): c for c, ats_n, tok in targets}
        for fut in cf.as_completed(futs):
            r = fut.result()
            results.append(r)
            done += 1
            flag = ""
            if r["hits"]:
                conf = sum(1 for h in r["hits"] if h["label"] == "CONFIRMED")
                flag = f"  <<< {len(r['hits'])} hit(s) ({conf} CONFIRMED)"
            elif r["error"]:
                flag = f"  (err: {r['error'][:40]})"
            print(f"[{done:4}/{len(targets)}] {r['company']:28} {r['ats']:14} jobs={r['jobs_scanned']:<5}{flag}", file=sys.stderr)

    # aggregate
    total_jobs = sum(r["jobs_scanned"] for r in results)
    reachable = [r for r in results if r["jobs_scanned"] > 0]
    with_hits = [r for r in results if r["hits"]]
    confirmed = [r for r in results if any(h["label"] == "CONFIRMED" for h in r["hits"])]
    summary = {
        "companies_targeted": len(targets),
        "companies_reachable": len(reachable),
        "total_jobs_scanned": total_jobs,
        "companies_with_hits": len(with_hits),
        "companies_confirmed": len(confirmed),
        "confirmed_companies": sorted(r["company"] for r in confirmed),
    }
    json.dump({"summary": summary, "results": sorted(results, key=lambda r: (-len(r["hits"]), r["company"]))},
              open(a.out + ".json", "w"), indent=2, ensure_ascii=False)
    with open(a.out + ".csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["company", "ats", "label", "score", "title", "vector", "confidence", "evidence", "url"])
        for r in sorted(results, key=lambda r: -len(r["hits"])):
            for h in r["hits"]:
                tf = h["top_finding"] or {}
                w.writerow([r["company"], r["ats"], h["label"], h["score"], h["title"],
                            tf.get("vector", ""), tf.get("confidence", ""), (tf.get("evidence", "") or "")[:300], h["url"]])
    print("\n=== SUMMARY ===", file=sys.stderr)
    print(json.dumps(summary, indent=2), file=sys.stderr)
    print("http stats:", client.report(), file=sys.stderr)


if __name__ == "__main__":
    main()
