// DownHit — Your links. Your downloads.
// One Cloudflare Worker: serves the page + /api/analyze + /api/download.

interface Env {
  RATE_LIMITER?: { limit(o: { key: string }): Promise<{ success: boolean }> };
}

const MAX_BYTES = 100 * 1024 * 1024; // 100 MB
const MAX_REDIRECTS = 4;
const TIMEOUT_MS = 10_000;
const UA = { "User-Agent": "DownHit/1.0 (+link-analyzer)" };
const BLOCKED_EXT = new Set([
  "exe", "msi", "bat", "cmd", "com", "scr", "pif", "vbs", "ps1", "jar", "dll", "sh", "apk",
]);

class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

// ---------- URL validation & SSRF protection ----------

function isBlockedHost(host: string): boolean {
  if (host.startsWith("[")) return true; // no IPv6 literals
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true; // no IPv4 literals
  if (!host.includes(".")) return true; // single-label names (localhost, intranet)
  const badSuffix = [".localhost", ".local", ".internal", ".localdomain", ".lan", ".home.arpa", ".corp"];
  return badSuffix.some((s) => host.endsWith(s));
}

function validateUrl(raw: string): URL {
  if (!raw || raw.length > 2048) throw new HttpError(400, "Enter a valid URL (max 2048 characters).");
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    throw new HttpError(400, "That doesn't look like a valid URL.");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:")
    throw new HttpError(400, "Only http and https links are supported.");
  if (u.username || u.password)
    throw new HttpError(400, "Links with embedded credentials are not allowed.");
  if (u.port && u.port !== "80" && u.port !== "443")
    throw new HttpError(400, "Only standard ports (80/443) are allowed.");
  if (isBlockedHost(u.hostname.toLowerCase()))
    throw new HttpError(400, "This address is not allowed. Use a public domain name.");
  const last = u.pathname.split("/").pop() || "";
  const ext = last.includes(".") ? last.split(".").pop()!.toLowerCase() : "";
  if (BLOCKED_EXT.has(ext))
    throw new HttpError(400, "Executable and installer files (." + ext + ") are not allowed.");
  return u;
}

// Follow redirects manually so every hop is re-validated.
async function fetchFollow(start: URL, init: RequestInit, ctl: AbortController) {
  let current = start;
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    let res: Response;
    try {
      res = await fetch(current.toString(), { ...init, redirect: "manual", signal: ctl.signal });
    } catch {
      throw new HttpError(502, "Could not reach that server (timeout or connection error).");
    }
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      res.body?.cancel();
      if (!loc) throw new HttpError(502, "The server sent a broken redirect.");
      let next: URL;
      try {
        next = new URL(loc, current);
      } catch {
        throw new HttpError(502, "The server sent an invalid redirect.");
      }
      current = validateUrl(next.toString());
      continue;
    }
    return { res, finalUrl: current };
  }
  throw new HttpError(502, "Too many redirects.");
}

// ---------- Helpers ----------

function cleanFilename(name: string): string {
  const n = name
    .replace(/[\u0000-\u001f\u007f"\\/:*?<>|]/g, "_")
    .replace(/^\.+/, "")
    .trim()
    .slice(0, 150);
  return n || "download";
}

function filenameFrom(disposition: string | null, url: URL): string {
  if (disposition) {
    const star = /filename\*\s*=\s*UTF-8''([^;]+)/i.exec(disposition);
    if (star) {
      try {
        return cleanFilename(decodeURIComponent(star[1]));
      } catch {}
    }
    const plain = /filename\s*=\s*"?([^";]+)"?/i.exec(disposition);
    if (plain) return cleanFilename(plain[1]);
  }
  const last = url.pathname.split("/").filter(Boolean).pop() || "";
  try {
    return cleanFilename(decodeURIComponent(last));
  } catch {
    return cleanFilename(last);
  }
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}

const mem = new Map<string, { n: number; reset: number }>();
async function allowed(req: Request, env: Env, bucket: string): Promise<boolean> {
  const ip = req.headers.get("cf-connecting-ip") || "unknown";
  const key = bucket + ":" + ip;
  if (env.RATE_LIMITER) {
    try {
      const { success } = await env.RATE_LIMITER.limit({ key });
      if (!success) return false;
    } catch {}
  }
  // Fallback limiter (per isolate): 30 requests / minute
  const now = Date.now();
  if (mem.size > 5000) mem.clear();
  const rec = mem.get(key);
  if (!rec || rec.reset < now) {
    mem.set(key, { n: 1, reset: now + 60_000 });
    return true;
  }
  rec.n++;
  return rec.n <= 30;
}

// ---------- API: analyze ----------

async function analyze(url: URL) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    let { res, finalUrl } = await fetchFollow(url, { method: "HEAD", headers: UA }, ctl);
    if (!res.ok || !res.headers.get("content-type")) {
      res.body?.cancel();
      ({ res, finalUrl } = await fetchFollow(
        url,
        { method: "GET", headers: { ...UA, Range: "bytes=0-0" } },
        ctl,
      ));
    }
    if (!res.ok) {
      res.body?.cancel();
      throw new HttpError(502, "The remote server answered with status " + res.status + ".");
    }
    const type = (res.headers.get("content-type") || "application/octet-stream")
      .split(";")[0]
      .trim()
      .toLowerCase();
    let size: number | null = null;
    const cr = res.headers.get("content-range");
    if (cr) {
      const m = /\/(\d+)$/.exec(cr);
      if (m) size = Number(m[1]);
    } else {
      const cl = Number(res.headers.get("content-length"));
      if (res.headers.get("content-length") && Number.isFinite(cl)) size = cl;
    }
    const filename = filenameFrom(res.headers.get("content-disposition"), finalUrl);
    const acceptRanges = (res.headers.get("accept-ranges") || "").toLowerCase() === "bytes";
    res.body?.cancel();

    if (type === "text/html" || type === "application/xhtml+xml")
      throw new HttpError(422, "This link opens a web page, not a downloadable file. Paste a direct file link.");
    const ext = filename.includes(".") ? filename.split(".").pop()!.toLowerCase() : "";
    if (BLOCKED_EXT.has(ext))
      throw new HttpError(422, "Executable and installer files (." + ext + ") are not allowed.");
    if (size !== null && size > MAX_BYTES)
      throw new HttpError(413, "File is too large. The limit is " + MAX_BYTES / 1024 / 1024 + " MB.");

    return { filename, type, size, host: finalUrl.hostname, resumable: acceptRanges, maxMB: MAX_BYTES / 1024 / 1024 };
  } finally {
    clearTimeout(timer);
  }
}

// ---------- API: download (streamed through the Worker, never stored) ----------

async function download(url: URL): Promise<Response> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  let result;
  try {
    result = await fetchFollow(url, { method: "GET", headers: UA }, ctl);
  } finally {
    clearTimeout(timer); // timeout applies to connecting, not to the transfer
  }
  const { res, finalUrl } = result;
  if (!res.ok || !res.body) {
    res.body?.cancel();
    throw new HttpError(502, "The remote server answered with status " + res.status + ".");
  }
  const type = (res.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
  if (type === "text/html" || type === "application/xhtml+xml") {
    res.body.cancel();
    throw new HttpError(422, "This link is a web page, not a file.");
  }
  const cl = Number(res.headers.get("content-length"));
  if (res.headers.get("content-length") && cl > MAX_BYTES) {
    res.body.cancel();
    throw new HttpError(413, "File is too large (limit " + MAX_BYTES / 1024 / 1024 + " MB).");
  }
  const filename = filenameFrom(res.headers.get("content-disposition"), finalUrl);
  const ext = filename.includes(".") ? filename.split(".").pop()!.toLowerCase() : "";
  if (BLOCKED_EXT.has(ext)) {
    res.body.cancel();
    throw new HttpError(422, "Executable and installer files are not allowed.");
  }

  let seen = 0;
  const limiter = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      seen += chunk.byteLength;
      if (seen > MAX_BYTES) {
        controller.error(new Error("Size limit exceeded"));
        ctl.abort();
        return;
      }
      controller.enqueue(chunk);
    },
  });

  const ascii = filename.replace(/[^\x20-\x7e]/g, "_");
  return new Response(res.body.pipeThrough(limiter), {
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Disposition":
        'attachment; filename="' + ascii + "\"; filename*=UTF-8''" + encodeURIComponent(filename),
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'none'; sandbox",
      "Cache-Control": "no-store",
    },
  });
}

// ---------- Router ----------

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname, searchParams } = new URL(request.url);
    try {
      if (pathname === "/" && request.method === "GET") {
        return new Response(PAGE, {
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
          },
        });
      }

      if (pathname === "/api/analyze") {
        if (request.method !== "POST") throw new HttpError(405, "Use POST.");
        if (!(await allowed(request, env, "analyze")))
          throw new HttpError(429, "Too many requests. Please wait a minute and try again.");
        if (Number(request.headers.get("content-length") || 0) > 4096)
          throw new HttpError(413, "Request too large.");
        let body: { url?: string };
        try {
          body = await request.json();
        } catch {
          throw new HttpError(400, "Invalid request.");
        }
        const info = await analyze(validateUrl(String(body.url || "")));
        return json(info);
      }

      if (pathname === "/api/download") {
        if (request.method !== "GET") throw new HttpError(405, "Use GET.");
        if (!(await allowed(request, env, "download")))
          throw new HttpError(429, "Too many downloads. Please wait a minute and try again.");
        return await download(validateUrl(searchParams.get("url") || ""));
      }

      return json({ error: "Not found." }, 404);
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      return json({ error: "Unexpected error. Please try again." }, 500);
    }
  },
};

// ---------- Page ----------

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DownHit — Your links. Your downloads.</title>
<meta name="description" content="Paste a direct file link, check it, and download it.">
<meta name="theme-color" content="#F5F1E8">
<style>
:root{--bg:#F5F1E8;--ink:#171717;--accent:#D97745;--muted:rgba(23,23,23,.62);--line:rgba(23,23,23,.12);--card:#FBF9F3}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;min-height:100vh;display:flex;flex-direction:column}
.wrap{width:100%;max-width:640px;margin:0 auto;padding:0 22px}
header{padding:28px 0 0;font-weight:700;letter-spacing:-.02em;font-size:20px}
header span{color:var(--accent)}
main{flex:1}
.hero{padding:64px 0 28px}
h1{font-size:clamp(34px,9vw,52px);line-height:1.08;letter-spacing:-.035em;margin:0 0 16px;font-weight:700}
h1 em{font-style:normal;color:var(--accent)}
.lead{color:var(--muted);margin:0;max-width:46ch}
form{margin:28px 0 0;display:flex;flex-direction:column;gap:12px}
input{width:100%;font:inherit;padding:16px 18px;border-radius:16px;border:1px solid var(--line);background:var(--card);color:var(--ink);outline:none}
input:focus{border-color:var(--accent);box-shadow:0 0 0 4px rgba(217,119,69,.18)}
.btn{font:inherit;font-weight:650;border:0;border-radius:16px;padding:16px 20px;background:var(--accent);color:var(--ink);cursor:pointer;text-align:center;text-decoration:none;display:block}
.btn:active{transform:scale(.99)}
.btn[disabled]{opacity:.6;cursor:wait}
.hint{font-size:14px;color:var(--muted);margin:14px 0 0}
#out{margin-top:22px;min-height:8px}
.box{border:1px solid var(--line);background:var(--card);border-radius:20px;padding:20px}
.err{border-color:rgba(190,60,30,.35)}
.err b{color:#a63a16}
.load{display:flex;align-items:center;gap:12px;color:var(--muted)}
.spin{width:18px;height:18px;border-radius:50%;border:2px solid var(--line);border-top-color:var(--accent);animation:s .8s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}
.fname{font-weight:700;font-size:18px;word-break:break-all;margin:0 0 14px;letter-spacing:-.01em}
dl{display:grid;grid-template-columns:auto 1fr;gap:6px 18px;margin:0 0 18px;font-size:15px}
dt{color:var(--muted)}dd{margin:0;word-break:break-all}
.ok{margin:14px 0 0;font-size:14px;color:var(--muted)}
section{padding:44px 0 8px}
h2{font-size:14px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin:0 0 12px;font-weight:600}
details{border-top:1px solid var(--line);padding:14px 0}
details:last-of-type{border-bottom:1px solid var(--line)}
summary{cursor:pointer;font-weight:600;list-style:none}
summary::-webkit-details-marker{display:none}
summary::after{content:"+";float:right;color:var(--accent);font-weight:700}
details[open] summary::after{content:"–"}
details p{margin:10px 0 0;color:var(--muted);font-size:15px}
footer{padding:40px 0 34px;color:var(--muted);font-size:14px}
</style>
</head>
<body>
<div class="wrap">
<header>Down<span>Hit</span></header>
<main>
  <div class="hero">
    <h1>Your links.<br><em>Your downloads.</em></h1>
    <p class="lead">Paste a direct file link. DownHit checks it first, then lets you download it.</p>
    <form id="f" novalidate>
      <input id="u" type="url" inputmode="url" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="https://example.com/file.pdf" aria-label="File URL">
      <button class="btn" id="b" type="submit">Analyze Link</button>
    </form>
    <p class="hint">Direct file links only (http/https), up to 100 MB.</p>
    <div id="out" aria-live="polite"></div>
  </div>

  <section>
    <h2>FAQ</h2>
    <details><summary>Which links work?</summary><p>Direct links that point straight to a file, like a PDF, image, ZIP or audio file. Links to web pages, streaming sites or files behind a login are not supported.</p></details>
    <details><summary>Is it safe?</summary><p>DownHit blocks private and local addresses, re-checks every redirect, limits file size to 100 MB and rejects executable and installer files. It cannot scan a file for viruses, so only download from sources you trust.</p></details>
    <details><summary>Do you store my files?</summary><p>No. The file is streamed to your device and is not saved on our side.</p></details>
    <details><summary>Why was my link rejected?</summary><p>Usually because it is a web page, too large, blocked for safety, or the server refused the request. The error message tells you which.</p></details>
  </section>
</main>
<footer>© 2026 DownHit. Only download files you have the right to access.</footer>
</div>
<script>
(function(){
  var f=document.getElementById('f'),u=document.getElementById('u'),b=document.getElementById('b'),out=document.getElementById('out');
  function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}
  function clear(){while(out.firstChild)out.removeChild(out.firstChild)}
  function fmt(n){if(n==null)return 'Unknown';var k=['B','KB','MB','GB'],i=0;while(n>=1024&&i<3){n/=1024;i++}return (i?n.toFixed(1):n)+' '+k[i]}
  function loading(){clear();var d=el('div','box load');d.appendChild(el('div','spin'));d.appendChild(el('span',null,'Analyzing link…'));out.appendChild(d)}
  function error(m){clear();var d=el('div','box err');var p=el('p',null,'');p.appendChild(el('b',null,'Could not analyze. '));p.appendChild(document.createTextNode(m));p.style.margin='0';d.appendChild(p);out.appendChild(d)}
  function result(d,url){
    clear();var box=el('div','box');
    box.appendChild(el('p','fname',d.filename));
    var dl=el('dl');
    [['Type',d.type],['Size',fmt(d.size)],['Source',d.host]].forEach(function(r){dl.appendChild(el('dt',null,r[0]));dl.appendChild(el('dd',null,r[1]))});
    box.appendChild(dl);
    var a=el('a','btn','Download');
    a.href='/api/download?url='+encodeURIComponent(url);
    a.rel='noopener';
    var note=el('p','ok','');
    a.addEventListener('click',function(){note.textContent='Download requested. Check your browser\\u2019s downloads list for progress.'});
    box.appendChild(a);box.appendChild(note);
    if(d.size==null)box.appendChild(el('p','ok','Size is not reported by the server. The download stops automatically above '+d.maxMB+' MB.'));
    out.appendChild(box);
  }
  f.addEventListener('submit',function(e){
    e.preventDefault();
    var url=u.value.trim();
    if(!url){error('Paste a link first.');return}
    b.disabled=true;loading();
    fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:url})})
      .then(function(r){return r.json().catch(function(){return {}}).then(function(d){return {ok:r.ok,d:d}})})
      .then(function(x){if(!x.ok)throw new Error(x.d.error||'Something went wrong.');result(x.d,url)})
      .catch(function(err){error(err.message||'Network error.')})
      .then(function(){b.disabled=false});
  });
})();
</script>
</body>
</html>`;
                                                     
