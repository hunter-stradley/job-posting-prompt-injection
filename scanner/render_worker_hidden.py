#!/usr/bin/env python3
"""
render_worker_hidden.py -- Playwright worker that extracts EFFECTIVELY-HIDDEN text.

Run under a venv with playwright installed. Usage: python render_worker_hidden.py <url>
Emits one JSON line: {"ok":bool, "hidden":[{reason,text}], "pseudo":[...], "visible_len":int, "error":...}

Unlike a static HTML scan, this resolves text hidden by COMPUTED style after CSS+JS apply:
  * display:none / visibility:hidden / opacity:0 / font-size:0
  * color ~= effective background color (white-on-white, set via external or <style> CSS)
  * positioned off-screen / clipped to zero
  * ::before / ::after pseudo-element `content` injection
  * text nodes present in DOM that a sighted user never sees
This is the render-gated class the API-HTML detector structurally cannot reach.
"""
import sys, json

JS = r"""
() => {
  const out = {hidden: [], pseudo: []};
  const seen = new Set();

  function parseRGB(s){
    const m = (s||'').match(/rgba?\(([^)]+)\)/);
    if(!m) return null;
    const p = m[1].split(',').map(x=>parseFloat(x));
    return {r:p[0], g:p[1], b:p[2], a:(p.length>3?p[3]:1)};
  }
  function lum(c){
    const f = v => { v/=255; return v<=0.03928 ? v/12.92 : Math.pow((v+0.055)/1.055,2.4); };
    return 0.2126*f(c.r)+0.7152*f(c.g)+0.0722*f(c.b);
  }
  function contrast(a,b){
    if(!a||!b) return 21;
    const L1=lum(a), L2=lum(b);
    return (Math.max(L1,L2)+0.05)/(Math.min(L1,L2)+0.05);
  }
  function effectiveBg(el){
    let n = el;
    while(n && n.nodeType===1){
      const c = parseRGB(getComputedStyle(n).backgroundColor);
      if(c && c.a>0.5) return c;
      n = n.parentElement;
    }
    return {r:255,g:255,b:255,a:1}; // assume white page
  }
  function directText(el){
    let t='';
    for(const ch of el.childNodes) if(ch.nodeType===3) t += ch.nodeValue;
    return t.replace(/\s+/g,' ').trim();
  }
  function add(reason, text){
    text = (text||'').replace(/\s+/g,' ').trim();
    if(text.length < 6) return;
    const k = reason+'|'+text.slice(0,120);
    if(seen.has(k)) return;
    seen.add(k);
    out.hidden.push({reason, text: text.slice(0,400)});
  }

  const all = document.querySelectorAll('body *');
  for(const el of all){
    const tag = el.tagName;
    if(tag==='SCRIPT'||tag==='STYLE'||tag==='NOSCRIPT') continue;
    const st = getComputedStyle(el);

    // pseudo-element content injection
    for(const pe of ['::before','::after']){
      const c = getComputedStyle(el, pe).content;
      if(c && c!=='none' && c!=='normal' && c!=='""' && c.length>3){
        const txt = c.replace(/^["']|["']$/g,'');
        if(txt.length>5){
          const k='pseudo|'+txt.slice(0,120);
          if(!seen.has(k)){ seen.add(k); out.pseudo.push({el:tag, pe, text: txt.slice(0,400)}); }
        }
      }
    }

    const txt = directText(el);
    if(!txt) continue;

    // structural hiding
    if(st.display==='none'){ add('display:none', txt); continue; }
    if(st.visibility==='hidden'||st.visibility==='collapse'){ add('visibility:hidden', txt); continue; }
    if(parseFloat(st.opacity)===0){ add('opacity:0', txt); continue; }
    if(parseFloat(st.fontSize)===0){ add('font-size:0', txt); continue; }

    // off-screen / clipped
    const r = el.getBoundingClientRect();
    const docW = Math.max(document.documentElement.scrollWidth, window.innerWidth);
    if(r.width>0 && r.height>0){
      if(r.right < -50 || r.bottom < -50 || r.left > docW+50){ add('offscreen', txt); continue; }
    } else if((r.width===0||r.height===0) && (st.overflow==='hidden'||st.clip!=='auto'||st.clipPath!=='none')){
      add('clipped-zero', txt); continue;
    }

    // color ~= background (white-on-white etc.), set by ANY css (inline/external/<style>)
    const fg = parseRGB(st.color);
    const bg = effectiveBg(el);
    if(fg && fg.a>0.3 && contrast(fg,bg) < 1.25){
      add('low-contrast('+Math.round(contrast(fg,bg)*100)/100+')', txt);
      continue;
    }
  }
  out.visible_len = (document.body.innerText||'').length;
  return out;
}
"""

def main():
    url = sys.argv[1]
    out = {"ok": False, "hidden": [], "pseudo": [], "visible_len": 0, "error": None}
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True)
            try:
                pg = b.new_page(user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                                           "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
                pg.goto(url, timeout=30000, wait_until="domcontentloaded")
                try:
                    pg.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass
                pg.wait_for_timeout(3500)
                res = pg.evaluate(JS)
                out.update(res)
                out["ok"] = True
            finally:
                b.close()
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    sys.stdout.write(json.dumps(out))

if __name__ == "__main__":
    main()
