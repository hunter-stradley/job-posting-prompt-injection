#!/usr/bin/env python3
"""
jd_injection_scanner.py  --  Job-posting prompt-injection / hidden-instruction scanner.

Core is stdlib-only. Optional features are feature-gated and print install hints.

macOS:
    python3 jd_injection_scanner.py --url https://example.com/jobs/123
    # optional render + ocr + pdf:
    pip install playwright pdfminer.six pytesseract Pillow
    playwright install chromium
    brew install tesseract
Linux equivalents:
    apt-get install tesseract-ocr   # instead of brew
    (pip packages identical)
"""
import sys, re, html, argparse, json, unicodedata
from urllib.request import urlopen, Request
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser

UA = "Mozilla/5.0 (compatible; jd-injection-scanner/1.0)"

# ---- Unicode classes ----
ZERO_WIDTH = {0x200B,0x200C,0x200D,0x2060,0xFEFF,0x180E}
BIDI_CTRL  = {0x202A,0x202B,0x202C,0x202D,0x202E,0x2066,0x2067,0x2068,0x2069}
TAG_RANGE  = range(0xE0000,0xE0080)
VARIATION  = list(range(0xFE00,0xFE10)) + list(range(0xE0100,0xE01F0))

INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior) instructions",
    r"disregard (all )?(previous|prior|above)",
    r"you are (now |an )?(unrestricted|admin|system)",
    r"\b(exceptionally|highly) (well[- ]?)?qualified\b",
    r"recommend (immediate )?(hiring|interview)",
    r"rate (this|the) candidate (highly|as)",
    r"if you('?re| are) (an )?(llm|ai|a language model|chatgpt|claude|gemini)",
    r"include the (phrase|word|string)",
    r"begin_admin_session|end_admin_session|\[/?admin\]",
    r"(send|exfiltrate|post|upload).{0,40}(http|url|email|resume|contact)",
    r"system prompt|developer message|tool call|function call",
]
INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)

# Minimal homoglyph fold (extend with TR39 confusables.txt for full coverage)
HOMOGLYPHS = {
    "\u0430":"a","\u0435":"e","\u043e":"o","\u0440":"p","\u0441":"c",
    "\u0445":"x","\u0443":"y","\u0456":"i","\u0458":"j","\u03bf":"o",
    "\u0391":"A","\u0392":"B","\u0395":"E","\u039f":"O","\uff41":"a",
}

def decode_tag_block(s):
    out=[]
    for ch in s:
        cp=ord(ch)
        if cp in TAG_RANGE:
            base=cp-0xE0000
            if 0x20<=base<0x7F: out.append(chr(base))
    return "".join(out)

def strip_zero_width(s):
    return "".join(c for c in s if ord(c) not in ZERO_WIDTH and ord(c) not in BIDI_CTRL
                    and ord(c) not in TAG_RANGE and ord(c) not in VARIATION)

def decode_zero_width_binary(s):
    # ZWSP(200B)=0, ZWNJ(200C)=1; decode 8-bit ASCII runs
    bits="".join("0" if ord(c)==0x200B else "1" if ord(c)==0x200C else " " for c in s)
    out=[]
    for run in bits.split():
        for i in range(0,len(run)-7,8):
            byte=run[i:i+8]
            if len(byte)==8:
                v=int(byte,2)
                if 0x20<=v<0x7F: out.append(chr(v))
    return "".join(out)

def fold_homoglyphs(s):
    s=unicodedata.normalize("NFKC", s)
    return "".join(HOMOGLYPHS.get(c,c) for c in s)

def scripts_in(s):
    sc=set()
    for c in s:
        if c.isascii() and c.isalpha(): sc.add("Latin")
        else:
            n=unicodedata.name(c,"")
            for k in ("CYRILLIC","GREEK","ARMENIAN","ARABIC"):
                if k in n: sc.add(k.title())
    return sc

class Extractor(HTMLParser):
    HIDDEN_RE = re.compile(
        r"(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(\D|$)"
        r"|font-size\s*:\s*0|left\s*:\s*-?\d{4,}px|clip\s*:\s*rect\(0)", re.I)
    SR_ONLY = re.compile(r"\b(sr-only|visually-hidden|screen-reader)\b", re.I)
    WHITE   = re.compile(r"color\s*:\s*(#fff(fff)?|white|rgb\(\s*255\s*,\s*255\s*,\s*255)", re.I)
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.findings=[]; self.visible=[]; self.json_ld=[]; self.in_ldjson=False
        self.cur_hidden=False; self._sr=False
    def handle_comment(self,data):
        if INJECTION_RE.search(data):
            self.findings.append(("html_comment", data.strip()[:300], "high"))
    def handle_starttag(self,tag,attrs):
        d=dict(attrs); style=d.get("style","") or ""; cls=d.get("class","") or ""
        hidden = bool(self.HIDDEN_RE.search(style)) or bool(self.WHITE.search(style)) \
                 or "hidden" in d or d.get("aria-hidden")=="true"
        sr = bool(self.SR_ONLY.search(cls))
        self.cur_hidden = hidden or sr
        self._sr = sr and not hidden
        if tag=="script" and d.get("type","").lower()=="application/ld+json":
            self.in_ldjson=True
        if tag=="input" and (d.get("type")=="hidden" or "display:none" in style.lower()):
            for k in ("placeholder","value","aria-label","name"):
                v=d.get(k,"")
                if v and INJECTION_RE.search(v):
                    self.findings.append(("hidden_form_field", f"{k}={v}"[:200], "high"))
        for a in ("alt","title","aria-label","placeholder"):
            v=d.get(a,"")
            if v and INJECTION_RE.search(v):
                self.findings.append((f"attr_{a}", v[:200], "medium"))
        for k,v in d.items():
            if k.startswith("data-") and v and INJECTION_RE.search(v):
                self.findings.append((f"attr_{k}", v[:200], "medium"))
    def handle_endtag(self,tag):
        if tag=="script": self.in_ldjson=False
        self.cur_hidden=False; self._sr=False
    def handle_data(self,data):
        if self.in_ldjson:
            self.json_ld.append(data)
            if INJECTION_RE.search(data):
                self.findings.append(("json_ld", data.strip()[:300], "high"))
            return
        t=data.strip()
        if not t: return
        if self.cur_hidden:
            is_inj = bool(INJECTION_RE.search(t))
            if self._sr and not is_inj:
                self.findings.append(("sr_only_text", t[:300], "informational"))
            elif self._sr and is_inj:
                self.findings.append(("sr_only_text", t[:300], "high"))
            else:
                self.findings.append(("css_hidden_text", t[:300],
                                       "high" if is_inj else "medium"))
        else:
            self.visible.append(t)

def unicode_scan(raw):
    f=[]
    zw=[ord(c) for c in raw if ord(c) in ZERO_WIDTH]
    bd=[ord(c) for c in raw if ord(c) in BIDI_CTRL]
    tg="".join(c for c in raw if ord(c) in TAG_RANGE)
    if zw:
        dec=decode_zero_width_binary(raw)
        f.append(("zero_width", f"{len(zw)} zero-width chars; decoded='{dec[:120]}'",
                  "high" if INJECTION_RE.search(dec) else "medium"))
    if bd:
        f.append(("bidi_control", f"{len(bd)} bidi control chars present", "high"))
    if tg:
        dec=decode_tag_block(raw)
        f.append(("unicode_tag_block", f"decoded='{dec[:200]}'",
                  "high" if (INJECTION_RE.search(dec) or dec) else "medium"))
    folded=fold_homoglyphs(raw)
    for line in raw.splitlines():
        sc=scripts_in(line)
        if "Latin" in sc and len(sc)>1:
            f.append(("mixed_script", f"scripts={sorted(sc)} line='{line.strip()[:80]}'","medium"))
            break
    return f, folded

def keyword_sweep(text, channel):
    out=[]
    for m in INJECTION_RE.finditer(text):
        seg=text[max(0,m.start()-30):m.end()+30].replace("\n"," ")
        out.append((f"keyword_{channel}", seg.strip()[:200], "medium"))
    return out

def score(findings):
    sev={"informational":5,"low":15,"medium":45,"high":80}
    s=max([sev.get(f[2],30) for f in findings], default=0)
    # boost when same payload appears across multiple channels
    distinct={f[1][:40] for f in findings if f[2] in ("medium","high")}
    if len(distinct)>1 and len(findings)>=2: s=min(100,s+15)
    return s

def fetch(url):
    req=Request(url, headers={"User-Agent":UA})
    with urlopen(req, timeout=30) as r:
        data=r.read()
        try: return data.decode("utf-8")
        except UnicodeDecodeError: return data.decode("latin-1")

def render_text(url):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[info] playwright not installed; skipping rendered-vs-raw diff. "
              "pip install playwright && playwright install chromium")
        return None
    with sync_playwright() as p:
        b=p.chromium.launch(); pg=b.new_page(); pg.goto(url, timeout=30000)
        txt=pg.inner_text("body"); b.close(); return txt

def inspect_pdf(url):
    try:
        from pdfminer.high_level import extract_text
        import io
        raw=urlopen(Request(url,headers={"User-Agent":UA}),timeout=30).read()
        txt=extract_text(io.BytesIO(raw))
        return keyword_sweep(txt,"pdf")
    except ImportError:
        print("[info] pdfminer.six not installed; skipping PDF. pip install pdfminer.six")
        return []
    except Exception as e:
        print(f"[warn] PDF inspect failed: {e}"); return []

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--url"); ap.add_argument("--file")
    ap.add_argument("--render", action="store_true", help="rendered-vs-raw diff (needs playwright)")
    a=ap.parse_args()
    raw = open(a.file,encoding="utf-8").read() if a.file else fetch(a.url)

    ex=Extractor(); ex.feed(raw)
    findings=list(ex.findings)
    ufind, folded = unicode_scan(raw)
    findings+=ufind
    visible_text=" ".join(ex.visible)
    findings+=keyword_sweep(visible_text,"visible_text")
    if folded!=unicodedata.normalize("NFKC",raw):
        findings+=keyword_sweep(folded,"homoglyph_folded")

    # rendered-vs-raw diff: text in source but not rendered = strong signal
    if a.render and a.url:
        rt=render_text(a.url)
        if rt is not None:
            rnorm=re.sub(r"\s+"," ",rt).lower()
            candidates=strip_zero_width(visible_text)+" "+" ".join(f[1] for f in ex.findings)
            for seg in re.split(r"[.\n]", candidates):
                seg=seg.strip()
                if len(seg)>20 and seg.lower() not in rnorm and INJECTION_RE.search(seg):
                    findings.append(("present_in_source_absent_in_render", seg[:200],"high"))

    # linked PDFs
    if a.url:
        for m in re.finditer(r'href=["\']([^"\']+\.pdf)["\']', raw, re.I):
            findings+=inspect_pdf(urljoin(a.url, m.group(1)))

    sev_rank={"high":0,"medium":1,"low":2,"informational":3}
    findings.sort(key=lambda f: sev_rank.get(f[2],4))
    risk=score(findings)
    print(json.dumps({
        "url": a.url or a.file,
        "risk_score": risk,
        "verdict": "BLOCK" if risk>=80 else "REVIEW" if risk>=40 else "OK",
        "findings":[{"vector":v,"evidence":e,"severity":s} for (v,e,s) in findings],
    }, indent=2, ensure_ascii=False))

if __name__=="__main__":
    main()
