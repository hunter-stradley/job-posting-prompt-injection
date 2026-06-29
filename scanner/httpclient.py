#!/usr/bin/env python3
"""
httpclient.py -- polite, low-footprint HTTP core for the job-posting defense survey.

Design goal: be a good web citizen so the sweep is never throttled or blocked, achieved
through POLITENESS, not evasion. No proxy rotation, no CAPTCHA solving, no auth bypass.

Features
--------
* Per-host token-bucket rate limiting (default ~1 req/host/sec) with random jitter.
* Global concurrency cap (semaphore) so we never fan out hard against any infra.
* Exponential backoff + retry on 429/5xx, honoring Retry-After when present.
* Realistic browser-like headers with a small rotating User-Agent pool.
* On-disk response cache keyed by (method,url,body) so re-runs never re-fetch.
* stdlib-only (urllib) to match the rest of the toolkit; no third-party deps.

Usage
-----
    from httpclient import Client
    c = Client(cache_dir="cache", rate_per_host=1.0, max_concurrency=6)
    text = c.get_text("https://example.com")
    data = c.get_json("https://api.example.com/x")
    data = c.post_json("https://api.example.com/y", {"q": 1})
"""
import os, sys, json, time, hashlib, random, threading, gzip, io
import urllib.request, urllib.error
from collections import defaultdict
from urllib.parse import urlparse

# A small pool of real, current desktop UA strings. We rotate per-request to look like
# ordinary organic traffic rather than a single hammering script.
USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]

DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}


class _HostRateLimiter:
    """Token-bucket-ish: enforce a minimum interval between requests per host, with jitter."""
    def __init__(self, rate_per_host):
        self.min_interval = 1.0 / rate_per_host if rate_per_host > 0 else 0.0
        self._next_ok = defaultdict(float)
        self._locks = defaultdict(threading.Lock)
        self._master = threading.Lock()

    def wait(self, host, clock, sleep):
        with self._master:
            lock = self._locks[host]
        with lock:
            now = clock()
            wait_for = self._next_ok[host] - now
            if wait_for > 0:
                sleep(wait_for)
                now = clock()
            jitter = random.uniform(0, self.min_interval * 0.4) if self.min_interval else 0.0
            self._next_ok[host] = now + self.min_interval + jitter


class Client:
    def __init__(self, cache_dir="cache", rate_per_host=1.0, max_concurrency=6,
                 max_retries=4, timeout=30, clock=time.monotonic, sleep=time.sleep,
                 use_cache=True, min_sleep_between=0.0):
        self.cache_dir = cache_dir
        self.use_cache = use_cache
        if use_cache:
            os.makedirs(cache_dir, exist_ok=True)
        self.rl = _HostRateLimiter(rate_per_host)
        self.sem = threading.Semaphore(max_concurrency)
        self.max_retries = max_retries
        self.timeout = timeout
        self._clock = clock
        self._sleep = sleep
        self.min_sleep_between = min_sleep_between
        self.stats = defaultdict(int)
        self._stats_lock = threading.Lock()

    # ---- cache ----
    def _cache_path(self, method, url, body):
        key = f"{method}\n{url}\n{(body or b'') if isinstance(body, (bytes, bytearray)) else (body or '')}"
        h = hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()
        return os.path.join(self.cache_dir, h + ".json")

    def _cache_get(self, path):
        if not self.use_cache or not os.path.exists(path):
            return None
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _cache_put(self, path, record):
        if not self.use_cache:
            return
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(record, f)
            os.replace(tmp, path)
        except Exception:
            pass

    def _bump(self, k):
        with self._stats_lock:
            self.stats[k] += 1

    # ---- core request ----
    def request(self, method, url, body=None, headers=None, accept_json=False):
        """Returns dict {status, url, text, from_cache} or raises on terminal failure."""
        cache_path = self._cache_path(method, url, body)
        cached = self._cache_get(cache_path)
        if cached is not None:
            self._bump("cache_hit")
            return {"status": cached["status"], "url": url, "text": cached["text"], "from_cache": True}

        host = urlparse(url).netloc
        hdrs = dict(DEFAULT_HEADERS)
        hdrs["User-Agent"] = random.choice(USER_AGENTS)
        if accept_json:
            hdrs["Accept"] = "application/json, text/plain, */*"
        if headers:
            hdrs.update(headers)
        data = body
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        elif isinstance(body, str):
            data = body.encode("utf-8")

        attempt = 0
        while True:
            attempt += 1
            with self.sem:
                self.rl.wait(host, self._clock, self._sleep)
                if self.min_sleep_between:
                    self._sleep(self.min_sleep_between)
                req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
                try:
                    with urllib.request.urlopen(req, timeout=self.timeout) as r:
                        raw = r.read()
                        if r.headers.get("Content-Encoding") == "gzip":
                            try:
                                raw = gzip.decompress(raw)
                            except Exception:
                                pass
                        text = raw.decode("utf-8", "replace")
                        self._bump("ok")
                        self._cache_put(cache_path, {"status": r.status, "text": text})
                        return {"status": r.status, "url": url, "text": text, "from_cache": False}
                except urllib.error.HTTPError as e:
                    code = e.code
                    # Retry transient throttling/server errors; give up on 4xx (except 429).
                    if code in (429, 500, 502, 503, 504) and attempt <= self.max_retries:
                        retry_after = e.headers.get("Retry-After") if e.headers else None
                        delay = self._backoff(attempt, retry_after)
                        self._bump(f"retry_{code}")
                        self._sleep(delay)
                        continue
                    self._bump(f"http_{code}")
                    # Cache hard 404/403/410 so we don't re-probe dead boards next run.
                    if code in (403, 404, 410):
                        self._cache_put(cache_path, {"status": code, "text": ""})
                    return {"status": code, "url": url, "text": "", "from_cache": False}
                except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                    if attempt <= self.max_retries:
                        self._bump("retry_neterr")
                        self._sleep(self._backoff(attempt, None))
                        continue
                    self._bump("neterr")
                    return {"status": 0, "url": url, "text": "", "from_cache": False, "error": str(e)}

    def _backoff(self, attempt, retry_after):
        if retry_after:
            try:
                return min(60.0, float(retry_after))
            except (ValueError, TypeError):
                pass
        base = min(30.0, (2 ** (attempt - 1)))
        return base + random.uniform(0, base * 0.3)  # full-ish jitter

    # ---- convenience ----
    def get_text(self, url, headers=None):
        return self.request("GET", url, headers=headers)["text"]

    def get(self, url, headers=None):
        return self.request("GET", url, headers=headers)

    def get_json(self, url, headers=None):
        r = self.request("GET", url, headers=headers, accept_json=True)
        if r["status"] != 200 or not r["text"]:
            return None
        try:
            return json.loads(r["text"])
        except (ValueError, json.JSONDecodeError):
            return None

    def post_json(self, url, payload, headers=None):
        r = self.request("POST", url, body=payload, headers=headers, accept_json=True)
        if r["status"] != 200 or not r["text"]:
            return None
        try:
            return json.loads(r["text"])
        except (ValueError, json.JSONDecodeError):
            return None

    def report(self):
        with self._stats_lock:
            return dict(self.stats)


if __name__ == "__main__":
    # smoke test with a fake clock/sleep so it runs offline & instantly
    fake_t = [0.0]
    def clock():
        return fake_t[0]
    def sleep(s):
        fake_t[0] += s
    c = Client(cache_dir="/tmp/hc_test_cache", clock=clock, sleep=sleep, use_cache=False)
    rl = _HostRateLimiter(1.0)
    for _ in range(3):
        rl.wait("example.com", clock, sleep)
    assert fake_t[0] >= 2.0, fake_t[0]  # 3 requests, ~1s apart -> >=2s elapsed
    # backoff monotonic-ish
    b = [c._backoff(i, None) for i in range(1, 5)]
    assert b[0] < b[-1], b
    # Retry-After honored
    assert c._backoff(1, "5") == 5.0
    print("httpclient self-test OK; backoff samples:", [round(x, 2) for x in b])
