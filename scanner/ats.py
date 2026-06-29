#!/usr/bin/env python3
"""
ats.py -- normalized bulk connectors for the major public ATS APIs.

Each connector returns a list of normalized records:
    {company, ats, board, job_id, title, url, jd_html}

Bulk-friendly (1 call returns every posting WITH full JD):
    greenhouse, ashby, lever, recruitee
List + per-posting detail (N+1; capped by max_jobs to stay polite):
    smartrecruiters, workday, workable

All network I/O goes through httpclient.Client (rate-limited, cached, retrying).
"""
import html, re
from urllib.parse import urlparse

# ---------------------------------------------------------------- bulk-friendly

def greenhouse(client, token, company=None, max_jobs=None):
    d = client.get_json(f"https://boards-api.greenhouse.io/v1/boards/{token}/jobs?content=true")
    if not d:
        return []
    out = []
    for j in d.get("jobs", []):
        out.append(_rec(company or token, "greenhouse", token, j.get("id"),
                        j.get("title", ""), j.get("absolute_url", ""),
                        html.unescape(j.get("content", "") or "")))
        if max_jobs and len(out) >= max_jobs:
            break
    return out


def ashby(client, token, company=None, max_jobs=None):
    d = client.get_json(f"https://api.ashbyhq.com/posting-api/job-board/{token}?includeCompensation=true")
    if not d:
        return []
    out = []
    for j in d.get("jobs", []):
        body = j.get("descriptionHtml") or j.get("descriptionPlain", "") or ""
        out.append(_rec(company or token, "ashby", token, j.get("id"),
                        j.get("title", ""), j.get("jobUrl") or j.get("applyUrl", ""), body))
        if max_jobs and len(out) >= max_jobs:
            break
    return out


def lever(client, token, company=None, max_jobs=None):
    d = client.get_json(f"https://api.lever.co/v0/postings/{token}?mode=json")
    if not isinstance(d, list):
        return []
    out = []
    for j in d:
        body = j.get("description", "") or j.get("descriptionPlain", "") or ""
        for s in j.get("lists", []):
            if isinstance(s, dict):
                body += " " + s.get("text", "") + " " + (s.get("content", "") or "")
        body += " " + (j.get("additional", "") or "")
        out.append(_rec(company or token, "lever", token, j.get("id"),
                        j.get("text", ""), j.get("hostedUrl") or j.get("applyUrl", ""), body))
        if max_jobs and len(out) >= max_jobs:
            break
    return out


def recruitee(client, token, company=None, max_jobs=None):
    d = client.get_json(f"https://{token}.recruitee.com/api/offers/")
    if not d:
        return []
    out = []
    for j in d.get("offers", []):
        out.append(_rec(company or token, "recruitee", token, j.get("id"),
                        j.get("title", ""), j.get("careers_url", ""),
                        j.get("description", "") or ""))
        if max_jobs and len(out) >= max_jobs:
            break
    return out


# ---------------------------------------------------------------- list + detail

def smartrecruiters(client, token, company=None, max_jobs=120):
    out = []
    offset = 0
    ids = []
    while True:
        d = client.get_json(f"https://api.smartrecruiters.com/v1/companies/{token}/postings?limit=100&offset={offset}")
        if not d:
            break
        batch = d.get("content", [])
        ids += [p.get("id") for p in batch if p.get("id")]
        offset += len(batch)
        if len(batch) < 100 or (max_jobs and len(ids) >= max_jobs):
            break
    for pid in ids[:max_jobs] if max_jobs else ids:
        det = client.get_json(f"https://api.smartrecruiters.com/v1/companies/{token}/postings/{pid}")
        if not det:
            continue
        sections = ((det.get("jobAd") or {}).get("sections") or {})
        parts = []
        for key in ("jobDescription", "qualifications", "additionalInformation", "companyDescription"):
            sec = sections.get(key) or {}
            if sec.get("text"):
                parts.append(sec["text"])
        out.append(_rec(company or token, "smartrecruiters", token, pid,
                        det.get("name", ""),
                        ((det.get("applyUrl")) or ""), " ".join(parts)))
    return out


def workday(client, token, company=None, max_jobs=120):
    """token encoded as 'host::tenant::site' (e.g. 'company.wd1.myworkdayjobs.com::company::Careers')."""
    try:
        host, tenant, site = token.split("::")
    except ValueError:
        return []
    base = f"https://{host}/wday/cxs/{tenant}/{site}"
    out = []
    offset = 0
    paths = []
    while True:
        d = client.post_json(f"{base}/jobs",
                             {"appliedFacets": {}, "limit": 20, "offset": offset, "searchText": ""})
        if not d:
            break
        posts = d.get("jobPostings", [])
        paths += [p.get("externalPath") for p in posts if p.get("externalPath")]
        offset += 20
        total = d.get("total", 0)
        if not posts or offset >= total or (max_jobs and len(paths) >= max_jobs):
            break
    for path in paths[:max_jobs] if max_jobs else paths:
        det = client.get_json(f"{base}{path}")
        if not det:
            continue
        info = det.get("jobPostingInfo") or {}
        out.append(_rec(company or tenant, "workday", token, info.get("id") or path,
                        info.get("title", ""), info.get("externalUrl", ""),
                        info.get("jobDescription", "") or ""))
    return out


def workable(client, token, company=None, max_jobs=120):
    listing = client.post_json(f"https://apply.workable.com/api/v3/accounts/{token}/jobs", {"query": "", "location": []})
    codes = []
    if listing:
        codes = [j.get("shortcode") for j in listing.get("results", []) if j.get("shortcode")]
    out = []
    for code in codes[:max_jobs] if max_jobs else codes:
        det = client.get_json(f"https://apply.workable.com/api/v3/accounts/{token}/jobs/{code}")
        if not det:
            continue
        body = " ".join(filter(None, [det.get("description", ""), det.get("requirements", ""), det.get("benefits", "")]))
        out.append(_rec(company or token, "workable", token, code,
                        det.get("title", ""), det.get("url") or det.get("application_url", ""), body))
    return out


# ---------------------------------------------------------------- dispatch

CONNECTORS = {
    "greenhouse": greenhouse, "ashby": ashby, "lever": lever, "recruitee": recruitee,
    "smartrecruiters": smartrecruiters, "workday": workday, "workable": workable,
}
BULK = {"greenhouse", "ashby", "lever", "recruitee"}


def fetch_board(client, ats, token, company=None, max_jobs=None):
    fn = CONNECTORS.get(ats)
    if not fn:
        raise ValueError(f"unknown ATS: {ats}")
    # heavy (N+1) connectors get a default cap; bulk ones fetch everything.
    # 60 samples per board is ample to detect a COMPANY-WIDE canary and is polite to
    # single-host APIs (SmartRecruiters/Workday/Workable do one request per posting).
    if ats not in BULK and max_jobs is None:
        max_jobs = 60
    try:
        return fn(client, token, company=company, max_jobs=max_jobs)
    except Exception as e:
        return [{"_error": f"{type(e).__name__}: {e}", "ats": ats, "board": token, "company": company or token}]


def _rec(company, ats, board, job_id, title, url, jd_html):
    return {"company": company, "ats": ats, "board": board, "job_id": str(job_id),
            "title": (title or "")[:160], "url": url or "", "jd_html": jd_html or ""}


if __name__ == "__main__":
    import sys
    from httpclient import Client
    # Usage: python ats.py <ats> <token>   (token is the board's own slug on that ATS)
    if len(sys.argv) < 3:
        print("usage: python ats.py <ats> <token>")
        print("       ats in:", ", ".join(sorted(CONNECTORS)))
        sys.exit(2)
    ats_name, tok = sys.argv[1], sys.argv[2]
    c = Client(cache_dir="cache", rate_per_host=2.0, max_concurrency=4)
    recs = fetch_board(c, ats_name, tok)
    n = len([r for r in recs if "_error" not in r])
    withbody = len([r for r in recs if r.get("jd_html")])
    sample = next((r["title"] for r in recs if r.get("title")), "")
    print(f"{ats_name:16} {tok:16} jobs={n:<4} with_jd={withbody:<4} e.g. {sample[:50]}")
    print("stats:", c.report())
