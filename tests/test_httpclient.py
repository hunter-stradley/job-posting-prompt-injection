"""Offline tests for the polite HTTP core -- no network, fake clock/sleep."""
import httpclient


def test_rate_limiter_spaces_requests():
    t = [0.0]
    clock = lambda: t[0]
    def sleep(s):
        t[0] += s
    rl = httpclient._HostRateLimiter(1.0)  # 1 req/sec
    for _ in range(3):
        rl.wait("example.com", clock, sleep)
    # 3 requests at ~1s apart -> at least ~2s of enforced waiting
    assert t[0] >= 2.0


def test_backoff_grows_with_attempts():
    c = httpclient.Client(use_cache=False)
    samples = [c._backoff(i, None) for i in range(1, 5)]
    assert samples[0] < samples[-1]


def test_backoff_is_capped():
    c = httpclient.Client(use_cache=False)
    # base caps at 30s; jitter adds up to 30% -> never wildly unbounded
    assert c._backoff(50, None) <= 30.0 * 1.31


def test_retry_after_is_honored():
    c = httpclient.Client(use_cache=False)
    assert c._backoff(1, "5") == 5.0
    # a garbage Retry-After falls back to exponential, not a crash
    assert c._backoff(1, "not-a-number") > 0
