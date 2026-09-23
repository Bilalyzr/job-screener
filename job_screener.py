#!/usr/bin/env python3
"""
Fresher SWE + Cyber Security job screener for product-based companies (India-first).

Sources:
  - Greenhouse public job boards (config below)
  - Phenom career sites via sitemap + JSON-LD (Mastercard)

Output:
  - daily-reports/YYYY-MM-DD.md  (also mirrored to daily-reports/latest.md)
  - screener-state.json          (seen-job tracker, marks NEW vs STILL OPEN)

Stdlib only. Run:  python job_screener.py
"""

import json
import re
import html as htmllib
import sys
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, date
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "daily-reports"
STATE_FILE = ROOT / "screener-state.json"
REPORTS.mkdir(exist_ok=True)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) JobScreener/1.0"

# ---------------------------------------------------------------- config ----
GREENHOUSE_BOARDS = {
    "stripe": "Stripe", "cloudflare": "Cloudflare", "elastic": "Elastic",
    "twilio": "Twilio", "dropbox": "Dropbox", "discord": "Discord",
    "netskope": "Netskope", "okta": "Okta", "pagerduty": "PagerDuty",
    "zscaler": "Zscaler", "datadog": "Datadog", "zoominfo": "ZoomInfo",
    "rubrik": "Rubrik",
}
PHENOM_SITES = {
    "mastercard": "https://careers.mastercard.com/us/en",
}
# top product-based targets: their roles sort first in mail + UI
PRIORITY_COMPANIES = {"mastercard", "stripe", "visa", "paypal"}
DOCS = ROOT / "docs"

# ------------------------------------------------------------- filters -----
INDIA = re.compile(r"(india|bangalore|bengaluru|hyderabad|chennai|pune|mumbai|"
                   r"gurugram|gurgaon|noida|mohali|ahmedabad|kolkata)", re.I)
FRESHER_TITLE = re.compile(
    r"(intern|graduate|trainee|campus|fresher|new grad|university|"
    r"entry[ -]level|apprentice|"
    r"(engineer|developer|analyst|scientist)\s*[- ]?(i|1)\b|"
    r"associate\s+(analyst|engineer|developer|consultant))", re.I)
ENTRY_DESC = re.compile(
    r"(entry[ -]level|fresher|recent graduate|new graduate|"
    r"0\s*[-\u2013to]+\s*[12]\s+years?|currently\s+(pursuing|enrolled)|"
    r"final year|penultimate)", re.I)
SENIOR_YEARS = re.compile(
    r"(([3-9]|1\d)\s*[-\u2013to ]*\s*\d*\s*\+?\s*years?[^.\n]{0,50}experience|"
    r"experience[^.\n]{0,50}([3-9]|1\d)\s*[-\u2013to ]*\s*\d*\s*\+?\s*years?)", re.I)
TECH = re.compile(r"(software|sde|swe|backend|frontend|full.?stack|developer|platform|"
                  r"devops|site reliability|sre|data engineer|qa|sdet|test automation|"
                  r"security|cyber|\bsoc\b|appsec|devsecops|grc|vulnerab|threat|"
                  r"penetration|identity|infosec)", re.I)
CYBER = re.compile(r"(security|cyber|\bsoc\b|appsec|devsecops|grc|vulnerab|threat|"
                   r"penetration|identity|infosec)", re.I)
SWE = re.compile(r"(software|sde|swe|backend|frontend|full.?stack|developer|platform|"
                 r"devops|site reliability|sre|data engineer|qa|sdet|test automation)", re.I)
SENIOR = re.compile(r"(senior|\bsr\b|staff|principal|manager|director|\blead\b|"
                    r"architect|head of|\bvp\b|president|"
                    r"\b(ii|iii|iv|v|vi)\b|\bl\s?[2-9]\b)", re.I)
EXCLUDE = re.compile(r"(account executive|\bsales\b|business development|\bmarketing\b|"
                     r"recruit(er|ing)|customer success|solutions? architect|"
                     r"pre.?sales|partner )", re.I)

SKILL_RADAR = ["python", "java", "javascript", "typescript", "go/golang", "sql",
               "aws", "azure", "gcp", "kubernetes", "docker", "terraform",
               "git", "ci/cd", "linux", "rest api", "react", "spring",
               "selenium", "pytest", "data structures", "algorithms",
               "siem", "burp", "wireshark", "owasp", "iso 27001", "soc 2",
               "networking", "tcp/ip", "penetration testing", "machine learning"]

SECTION_MARKERS = re.compile(
    r"(what we.{0,20}looking for|all about you|about you|qualifications|"
    r"requirements|what you.{0,20}need|skills? and|must have|essential skills)", re.I)

# ------------------------------------------------------------- http --------
def fetch(url, rng=None, timeout=25, retries=2):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    if rng:
        req.add_header("Range", f"bytes=0-{rng}")
    last = None
    for _ in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001 - one bad source must not kill run
            last = e
    raise last


def strip_html(text):
    text = htmllib.unescape(text or "")
    text = re.sub(r"<(br|/p|/li|/h\d)[^>]*>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n", text)
    return text.strip()


def extract_requirements(desc_text, limit=900):
    """Pull the requirements-ish section out of a cleaned JD text."""
    m = SECTION_MARKERS.search(desc_text)
    seg = desc_text[m.start():] if m else desc_text
    seg = re.split(r"(corporate security responsibility|equal opportunity|"
                   r"privacy notice|eeo )", seg, flags=re.I)[0]
    lines = [l.strip(" \u2022-\u2013\u2022") for l in seg.split("\n")]
    bullets = [l for l in lines if 20 < len(l) < 300][:10]
    out = "\n".join(f"    - {b}" for b in bullets)
    return out[:limit] if out else "    - (see posting link for full requirements)"


# ------------------------------------------------------- greenhouse --------
def fetch_greenhouse(board, company):
    url = f"https://boards-api.greenhouse.io/v1/boards/{board}/jobs"
    data = json.loads(fetch(url))
    out = []
    for j in data.get("jobs", []):
        out.append({
            "key": f"gh:{j['id']}",
            "company": company,
            "title": j.get("title", ""),
            "location": j.get("location", {}).get("name", ""),
            "url": j.get("absolute_url", ""),
            "posted": (j.get("first_published") or "")[:10],
            "desc": "",
        })
    return out


def greenhouse_detail(board, job):
    """Fetch full JD content for a matched job (adds 'desc')."""
    jid = job["key"].split(":", 1)[1]
    try:
        data = json.loads(fetch(
            f"https://boards-api.greenhouse.io/v1/boards/{board}/jobs/{jid}"))
        job["desc"] = strip_html(data.get("content", ""))
    except Exception:
        job["desc"] = ""
    return job


# ------------------------------------------------------------ phenom -------
def fetch_phenom(site_name, base):
    jobs = []
    idx = fetch(f"{base}/sitemap_index.xml").decode("utf-8", "replace")
    maps = re.findall(r"<loc>([^<]+sitemap\d+\.xml)</loc>", idx)
    urls = []
    for sm in maps:
        xml = fetch(sm).decode("utf-8", "replace")
        urls += re.findall(r"<loc>([^<]+/job/[^<]+)</loc>", xml)
    # pre-filter on URL slug to avoid fetching all pages
    for u in urls:
        slug = u.rsplit("/job/", 1)[1].split("/", 1)[1] if "/job/" in u else ""
        norm = slug.replace("-", " ").lower()
        if TECH.search(norm) and not SENIOR.search(norm):
            jobs.append({"key": f"ph:{u.split('/job/')[1].split('/')[0]}",
                         "company": site_name.title(), "title": "",
                         "location": "", "url": u, "posted": "",
                         "desc": "", "_fetch": True})
    def detail(j):
        try:
            raw = fetch(j["url"], rng=90000).decode("utf-8", "replace")
            for b in re.findall(
                    r'<script type="application/ld\+json">(.*?)</script>', raw, re.S):
                try:
                    d = json.loads(b)
                except Exception:
                    continue
                if isinstance(d, dict) and d.get("@type") == "JobPosting":
                    j["title"] = d.get("title", "")
                    jl = d.get("jobLocation", [])
                    jl = jl if isinstance(jl, list) else [jl]
                    j["location"] = "; ".join(
                        f"{l.get('address', {}).get('addressLocality','')}, "
                        f"{l.get('address', {}).get('addressCountry','')}".strip(", ")
                        for l in jl if isinstance(l, dict))
                    j["posted"] = (d.get("datePosted") or "")[:10]
                    j["desc"] = strip_html(d.get("description", ""))
                    break
        except Exception:
            pass
        return j
    with ThreadPoolExecutor(max_workers=8) as ex:
        jobs = list(ex.map(detail, jobs))
    return jobs


# ------------------------------------------------------------- notify ------
NOTIFY_FILE = ROOT / "mailer.json"


def load_notify():
    if NOTIFY_FILE.exists():
        try:
            return json.loads(NOTIFY_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def plain_text(md):
    txt = re.sub(r"^#{1,6}\s*", "", md, flags=re.M)
    txt = txt.replace("**", "")
    txt = re.sub(r"^\|---\|.*$", "", txt, flags=re.M)
    return txt


def send_email(subject, body):
    import smtplib
    from email.message import EmailMessage
    cfg = load_notify().get("email", {})
    sender, pw, to = cfg.get("sender"), cfg.get("app_password"), cfg.get("recipient")
    if not (sender and pw and to):
        return "email: not configured (fill mailer.json)"
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, sender, to
    msg.set_content(body)
    with smtplib.SMTP("smtp.gmail.com", 587, timeout=30) as s:
        s.starttls()
        s.login(sender, pw)
        s.send_message(msg)
    return f"email: sent to {to}"


def send_telegram(text):
    cfg = load_notify().get("telegram", {})
    tok, chat = cfg.get("bot_token"), cfg.get("chat_id")
    if not (tok and chat):
        return "telegram: not configured (fill mailer.json)"
    if len(text) > 4000:
        text = text[:4000] + "\n…(truncated — full report in daily-reports/)"
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{tok}/sendMessage",
        data=json.dumps({"chat_id": chat, "text": text}).encode(),
        headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=20).read()
    return f"telegram: sent to chat {chat}"


# ---------------------------------------------------------------- site ------
INDEX_TMPL = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Fresher Job Radar</title>
<style>
:root{
  --bg:#0b1020; --surface:#141b2e; --surface2:#0e1425;
  --line:#232d47; --line-hi:#33406a;
  --text:#e8ecf7; --muted:#9aa5c3;
  --primary:#4f8cff; --accent:#f7b32b; --ok:#3ecf8e; --warn:#ffb84d;
  --sp-1:4px; --sp-2:8px; --sp-3:12px; --sp-4:16px; --sp-6:24px; --sp-8:32px;
  --fs-12:12px; --fs-14:14px; --fs-16:16px; --fs-20:20px; --fs-28:28px;
  --rad:12px; --rad-s:8px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font:16px/1.5 'Segoe UI',system-ui,sans-serif;padding:var(--sp-6) var(--sp-4)}
.wrap{max-width:1120px;margin:0 auto}
header{display:flex;justify-content:space-between;align-items:baseline;gap:var(--sp-3);flex-wrap:wrap;margin-bottom:var(--sp-6)}
h1{font-size:var(--fs-28);font-weight:700;letter-spacing:-.02em}
h1 em{color:var(--accent);font-style:normal}
.updated{font-size:var(--fs-12);color:var(--muted)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:var(--sp-3);margin-bottom:var(--sp-6)}
.stat{background:var(--surface);border:1px solid var(--line);border-radius:var(--rad);padding:var(--sp-3) var(--sp-4)}
.stat b{display:block;font-size:var(--fs-28);font-weight:700;line-height:1.2}
.stat span{font-size:var(--fs-12);color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.stat.hl b{color:var(--ok)}
.toolbar{display:flex;flex-wrap:wrap;gap:var(--sp-2);margin-bottom:var(--sp-4)}
input,select{min-height:44px;background:var(--surface);border:1px solid var(--line);color:var(--text);border-radius:var(--rad-s);padding:0 var(--sp-3);font-size:var(--fs-14)}
input{min-width:240px}
input:hover,select:hover{border-color:var(--line-hi)}
:focus-visible{outline:2px solid var(--primary);outline-offset:2px}
.check{display:flex;align-items:center;gap:var(--sp-2);min-height:44px;padding:0 var(--sp-2);font-size:var(--fs-14);color:var(--muted);cursor:pointer;border-radius:var(--rad-s)}
.check:hover{color:var(--text)}
.check input{min-width:16px;min-height:16px;accent-color:var(--primary)}
.result-line{font-size:var(--fs-12);color:var(--muted);margin:0 0 var(--sp-3)}
.jobs{display:grid;gap:var(--sp-3)}
.job{background:var(--surface);border:1px solid var(--line);border-radius:var(--rad);padding:var(--sp-4);transition:border-color .15s,box-shadow .15s}
.job:hover{border-color:var(--line-hi);box-shadow:0 4px 16px rgba(0,0,0,.25)}
.job:focus-within{border-color:var(--primary)}
.job.pri{border-left:3px solid var(--accent)}
.top{display:flex;gap:var(--sp-2);align-items:center;flex-wrap:wrap}
.badge{font-size:var(--fs-12);font-weight:700;letter-spacing:.04em;padding:var(--sp-1) var(--sp-2);border-radius:999px}
.badge.new{background:#12331f;color:var(--ok)}
.badge.pri{background:#33270e;color:var(--accent)}
.badge.watch{background:#33250f;color:var(--warn)}
.chip{font-size:var(--fs-12);padding:2px var(--sp-2);border-radius:999px;border:1px solid}
.chip.swe{color:#7fabff;border-color:#2c4a86}
.chip.cyber{color:#6fe0ad;border-color:#1f5c41}
.chip.other{color:#c3b0ff;border-color:#4a3b86}
.who{font-size:var(--fs-12);color:var(--muted)}
.t{font-size:var(--fs-16);font-weight:600;margin:var(--sp-2) 0 var(--sp-1)}
.meta{font-size:var(--fs-14);color:var(--muted);margin-top:2px}
.act{margin-top:var(--sp-3)}
.btn{display:inline-flex;align-items:center;min-height:44px;padding:0 var(--sp-4);background:var(--primary);color:#081226;font-weight:600;font-size:var(--fs-14);border-radius:var(--rad-s);text-decoration:none;border:0;cursor:pointer}
.btn:hover{filter:brightness(1.1)}
.btn.ghost{background:var(--surface);color:var(--text);border:1px solid var(--line)}
details{margin-top:var(--sp-3)}
summary{cursor:pointer;color:var(--muted);font-size:var(--fs-14);min-height:32px;display:flex;align-items:center}
summary:hover{color:var(--text)}
pre{white-space:pre-wrap;max-width:75ch;font-family:inherit;font-size:var(--fs-14);color:#c6cfe6;background:var(--surface2);border:1px solid var(--line);border-radius:var(--rad-s);padding:var(--sp-3);margin-top:var(--sp-2)}
.empty{text-align:center;padding:var(--sp-8) var(--sp-4);background:var(--surface);border:1px dashed var(--line);border-radius:var(--rad)}
.empty h2{font-size:var(--fs-20);margin-bottom:var(--sp-2)}
.empty p{font-size:var(--fs-14);color:var(--muted);margin-bottom:var(--sp-4)}
.radar{margin-top:var(--sp-8);background:var(--surface);border:1px solid var(--line);border-radius:var(--rad);padding:var(--sp-4)}
.radar h2{font-size:var(--fs-20);margin-bottom:var(--sp-1)}
.radar .sub{font-size:var(--fs-12);color:var(--muted);margin-bottom:var(--sp-4)}
.focus{border-left:3px solid var(--ok);background:var(--surface2);border-radius:var(--rad-s);padding:var(--sp-3) var(--sp-4);margin-bottom:var(--sp-4);font-size:var(--fs-14)}
.focus b{color:var(--ok)}
.dom{margin-bottom:var(--sp-4)}
.dom-h{display:flex;justify-content:space-between;align-items:baseline;font-size:var(--fs-14);font-weight:600;margin-bottom:var(--sp-2)}
.dom-h .n{font-size:var(--fs-12);color:var(--muted);font-weight:400}
.dom-bar{height:4px;background:var(--surface2);border-radius:999px;margin-bottom:var(--sp-2);overflow:hidden}
.dom-bar i{display:block;height:100%;background:var(--primary);border-radius:999px}
.skill{display:grid;grid-template-columns:150px 1fr 40px;gap:var(--sp-2);align-items:center;font-size:var(--fs-14);margin-bottom:var(--sp-1)}
.skill .bar{height:8px;background:var(--surface2);border-radius:999px;overflow:hidden}
.skill .bar i{display:block;height:100%;background:var(--primary);opacity:.85;border-radius:999px}
.skill .c{text-align:right;color:var(--muted);font-size:var(--fs-12)}
footer{margin-top:var(--sp-8);color:var(--muted);font-size:var(--fs-12);text-align:center}
footer a{color:var(--primary)}
@media (max-width:640px){.toolbar{display:grid}input,select,.check{width:100%}}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>🎯 Fresher Job <em>Radar</em></h1>
  <div class="updated">Updated __UPDATED__</div>
</header>
<section class="stats" id="stats" aria-label="Summary statistics"></section>
<form class="toolbar" role="search" onsubmit="return false">
  <input id="q" type="search" aria-label="Search by title, company, or location" placeholder="Search title, company, location…">
  <select id="trk" aria-label="Filter by job track">
    <option value="">All tracks</option><option value="swe">Software Eng</option>
    <option value="cyber">Cyber Security</option><option value="other">Other tech</option>
  </select>
  <select id="tier" aria-label="Filter by experience level">
    <option value="">All levels</option><option value="fresher">Fresher (mailed)</option>
    <option value="watch">Watch — verify level</option>
  </select>
  <select id="cmp" aria-label="Filter by company"><option value="">All companies</option></select>
  <label class="check"><input type="checkbox" id="newonly"> New today only</label>
  <label class="check"><input type="checkbox" id="pri" checked> ⭐ Priority first</label>
</form>
<p class="result-line" id="count"></p>
<div class="jobs" id="list"></div>
<section class="radar" id="radar" aria-label="Tech stack demand across tracked roles"></section>
<footer>daily log · email shows only <b>new</b> fresher roles ·
<a href="https://github.com/Bilalyzr/job-screener">Bilalyzr/job-screener</a></footer>
</div>
<script>
const JOBS=__DATA__,TODAY="__TODAY__";
const $=id=>document.getElementById(id);
[...new Set(JOBS.map(j=>j.company))].sort().forEach(c=>{const o=document.createElement("option");o.textContent=c;$("cmp").appendChild(o);});
const esc=s=>(s||"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
function stats(){
  const n={total:JOBS.length,new:JOBS.filter(j=>j.first_seen===TODAY).length,
           fres:JOBS.filter(j=>j.tier!=="watch").length,
           watch:JOBS.filter(j=>j.tier==="watch").length,
           cyber:JOBS.filter(j=>j.track==="cyber").length};
  $("stats").innerHTML=[["Tracked",n.total],["New today",n.new,"hl"],["Fresher",n.fres],
                        ["Watch",n.watch],["Cyber",n.cyber]]
    .map(([k,v,hl])=>`<div class="stat ${hl||""}"><b>${v}</b><span>${k}</span></div>`).join("");
}
function render(){
  const q=$("q").value.toLowerCase(),trk=$("trk").value,cmp=$("cmp").value,
        no=$("newonly").checked,tier=$("tier").value;
  let js=JOBS.filter(j=>(!trk||j.track===trk)&&(!cmp||j.company===cmp)&&
        (!tier||j.tier===tier)&&(!no||j.first_seen===TODAY)&&
        (!q||(j.title+j.company+j.location).toLowerCase().includes(q)));
  js.sort((a,b)=>{
    if($("pri").checked&&!!b.priority!=!!a.priority)return a.priority?-1:1;
    if((a.tier==="watch")!==(b.tier==="watch"))return a.tier==="watch"?1:-1;
    return (b.first_seen||"").localeCompare(a.first_seen||"")||a.company.localeCompare(b.company);});
  $("count").textContent=`Showing ${js.length} of ${JOBS.length} tracked roles`;
  $("list").innerHTML=js.length?js.map(j=>`
   <article class="job ${j.priority?"pri":""}">
    <div class="top">
      ${j.first_seen===TODAY?'<span class="badge new">NEW</span>':""}
      ${j.priority?'<span class="badge pri">⭐ PRIORITY</span>':""}
      ${j.tier==="watch"?'<span class="badge watch">VERIFY LEVEL</span>':""}
      <span class="chip ${j.track}">${j.track==="cyber"?"CYBER":j.track==="swe"?"SWE":"TECH"}</span>
      <span class="who">${esc(j.company)} · first seen ${j.first_seen}</span>
    </div>
    <h2 class="t">${esc(j.title)}</h2>
    <p class="meta">📍 ${esc(j.location)} · posted ${esc(j.posted||"n/a")}</p>
    <div class="act"><a class="btn" href="${esc(j.url)}" target="_blank" rel="noopener">View &amp; apply →</a></div>
    ${j.reqs?`<details><summary>Key requirements</summary><pre>${esc(j.reqs)}</pre></details>`:""}
   </article>`).join("")
   :`<div class="empty"><h2>No jobs match your filters</h2>
     <p>Try a different keyword — or reset the filters to see every tracked role.</p>
     <button class="btn ghost" id="reset" type="button">Reset filters</button></div>`;
  const r=$("reset");
  if(r)r.onclick=()=>{$("q").value="";$("trk").value="";$("tier").value="";
    $("cmp").value="";$("newonly").checked=false;render();};
  stats();
  const ctx=[cmp?`company: ${cmp}`:"",trk?`track: ${trk}`:"",
             tier?`level: ${tier}`:"",no?"new today only":""]
    .filter(Boolean).join(" · ");
  buildRadar(js,ctx);
}
const SKILLS=[["python","Programming"],["java","Programming"],["javascript","Programming"],["typescript","Programming"],["golang","Programming"],
["sql","Data & Databases"],["machine learning","Data & Databases"],["data structures","CS Fundamentals"],["algorithms","CS Fundamentals"],
["react","Web & APIs"],["spring","Web & APIs"],["rest api","Web & APIs"],["microservices","Web & APIs"],
["aws","Cloud & DevOps"],["azure","Cloud & DevOps"],["gcp","Cloud & DevOps"],["kubernetes","Cloud & DevOps"],["docker","Cloud & DevOps"],["terraform","Cloud & DevOps"],["ci/cd","Cloud & DevOps"],["git","Cloud & DevOps"],["linux","Cloud & DevOps"],
["selenium","Testing & QA"],["pytest","Testing & QA"],["test automation","Testing & QA"],
["owasp","Security"],["siem","Security"],["penetration","Security"],["burp","Security"],["wireshark","Security"],["iso 27001","Security"],["soc 2","Security"],["networking","Security"]];
const STRENGTH=new Set(["Web & APIs","Programming"]);
const ADVICE={"Cloud & DevOps":"start with Docker + one cloud (AWS first) and wire a CI pipeline into a project",
"Security":"your cyber track — OWASP Top 10 hands-on, networking (TCP/IP, TLS) and Linux",
"CS Fundamentals":"keep the daily DSA habit in Python",
"Data & Databases":"SQL joins and aggregations first, then basic ML with scikit-learn",
"Testing & QA":"pytest + Selenium already map to Phase 2 of your prep plan",
"Programming":"deepen Python and stay Java-literate",
"Web & APIs":"already your strength from the internship — maintain it"};
function buildRadar(js,ctx){
  const w=js.filter(j=>j.reqs);
  const nJD=w.length;
  if(!nJD){$("radar").innerHTML=`<h2>📊 Tech stack demand</h2><p class="sub">No requirement text in this view${ctx?" · "+ctx:""}.</p><p class="sub">Clear the filters to see demand across every tracked role.</p>`;return;}
  const corpus=w.map(j=>((j.title||"")+" "+(j.reqs||"")).toLowerCase()).join(" ");
  const rows=SKILLS.map(([s,d])=>{const m=corpus.match(new RegExp("\\\\b"+s+"\\\\b","g"));return{s,d,c:m?m.length:0};}).filter(r=>r.c>0);
  if(!rows.length){$("radar").innerHTML=`<h2>📊 Tech stack demand</h2><p class="sub">${nJD} job description${nJD>1?"s":""} in view${ctx?" · "+ctx:""} — no tracked skills mentioned yet.</p>`;return;}
  const doms={};rows.forEach(r=>doms[r.d]=(doms[r.d]||0)+r.c);
  const order=Object.entries(doms).sort((a,b)=>b[1]-a[1]);
  let h=`<h2>📊 Tech stack demand</h2><p class="sub">${nJD} job description${nJD>1?"s":""} in view${ctx?" · "+ctx:" · full log"} — grows with the daily log</p>`;
  if(nJD>=3){
    const target=order.find(([d])=>!STRENGTH.has(d))||order[0];
    h+=`<div class="focus"><b>🎯 Improve next: ${target[0]}</b> — highest demand (${target[1]} mentions) in this view, outside your current strengths. ${ADVICE[target[0]]||"Keep building fundamentals."}</div>`;
  }
  const maxD=order[0][1];
  order.forEach(([d,tot])=>{
    const srows=rows.filter(r=>r.d===d).sort((a,b)=>b.c-a.c);
    const maxS=srows[0].c;
    h+=`<div class="dom"><div class="dom-h"><span>${d}${STRENGTH.has(d)?' <span class="who">· your strength</span>':""}</span><span class="n">${tot} mentions</span></div><div class="dom-bar"><i style="width:${Math.round(tot/maxD*100)}%"></i></div>`;
    srows.forEach(r=>{h+=`<div class="skill"><span>${r.s}</span><span class="bar"><i style="width:${Math.round(r.c/maxS*100)}%"></i></span><span class="c">${r.c}</span></div>`;});
    h+="</div>";
  });
  $("radar").innerHTML=h;
}
["q","trk","tier","cmp","newonly","pri"].forEach(id=>$(id).addEventListener("input",render));
render();
</script>
</body></html>
"""


def load_db():
    dbf = DOCS / "jobs.json"
    if dbf.exists():
        try:
            return json.loads(dbf.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"jobs": []}


def update_db(db, matched, watch, today):
    by_key = {j["key"]: j for j in db["jobs"]}
    for tier, jobs in (("fresher", matched), ("watch", watch)):
        for j in jobs:
            pri = j["company"].lower() in PRIORITY_COMPANIES
            rec = by_key.get(j["key"])
            if rec:
                rec.update(last_seen=today, title=j["title"], location=j["location"],
                           url=j["url"], posted=j["posted"], track=j["track"],
                           priority=pri, tier=tier)
            else:
                by_key[j["key"]] = {
                    "key": j["key"], "company": j["company"], "title": j["title"],
                    "location": j["location"], "url": j["url"], "posted": j["posted"],
                    "track": j["track"], "tier": tier,
                    "first_seen": today, "last_seen": today,
                    "priority": pri,
                    "reqs": extract_requirements(j.get("desc", "")) if j.get("desc") else "",
                }
    db["jobs"] = list(by_key.values())
    db["updated"] = datetime.now().strftime("%Y-%m-%d %H:%M")
    return db


def write_site(db, today):
    DOCS.mkdir(exist_ok=True)
    (DOCS / "jobs.json").write_text(
        json.dumps(db, indent=1, ensure_ascii=False), encoding="utf-8")
    page = (INDEX_TMPL
            .replace("__DATA__", json.dumps(db["jobs"], ensure_ascii=False))
            .replace("__UPDATED__", db.get("updated", ""))
            .replace("__TODAY__", today))
    (DOCS / "index.html").write_text(page, encoding="utf-8")
    return DOCS / "index.html"


def push_site(today):
    import subprocess
    if not load_notify().get("site", {}).get("push"):
        return "site push: disabled (set site.push=true in mailer.json)"
    for args in (["git", "add", "docs"],
                 ["git", "commit", "-m", f"daily log {today}"],
                 ["git", "push"]):
        r = subprocess.run(args, cwd=str(ROOT), capture_output=True,
                           text=True, timeout=120)
        out = (r.stdout or "") + (r.stderr or "")
        if r.returncode != 0 and "nothing to commit" not in out \
                and "nothing added to commit" not in out \
                and "no changes added" not in out:
            return f"site push: FAILED - {out.strip()[:140]}"
    return "site push: ok"


# ------------------------------------------------------------- pipeline ----
def classify(job):
    t = job["title"]
    if CYBER.search(t):
        return "cyber"
    if SWE.search(t):
        return "swe"
    return "other"


def is_fresher(job):
    """Strict fresher check: explicit title marker, or entry-level language in JD."""
    t = job.get("title") or ""
    if FRESHER_TITLE.search(t):
        return True
    desc = job.get("desc") or ""
    if desc and ENTRY_DESC.search(desc[:6000]):
        return True
    return False


def wants_senior_years(job):
    desc = job.get("desc") or ""
    return bool(desc) and bool(SENIOR_YEARS.search(desc[:6000]))


def base_match(job):
    t = job.get("title") or ""
    return (len(t) > 3
            and INDIA.search(job.get("location") or "")
            and TECH.search(t)
            and not SENIOR.search(t)
            and not EXCLUDE.search(t))


def is_match(job):
    return base_match(job) and is_fresher(job) and not wants_senior_years(job)


def main():
    today = date.today().isoformat()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    all_jobs, errors = [], []

    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = {ex.submit(fetch_greenhouse, b, c): (b, c)
                for b, c in GREENHOUSE_BOARDS.items()}
        for fu in as_completed(futs):
            b, c = futs[fu]
            try:
                all_jobs += fu.result()
            except Exception as e:
                errors.append(f"greenhouse/{b}: {e}")

    for name, base in PHENOM_SITES.items():
        try:
            all_jobs += fetch_phenom(name, base)
        except Exception as e:
            errors.append(f"phenom/{name}: {e}")

    matched = [j for j in all_jobs if j.get("title") and is_match(j)]

    # enrich greenhouse matches with full JD text
    gh_detail_futs = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        for j in matched:
            if j["key"].startswith("gh:"):
                board = [b for b, c in GREENHOUSE_BOARDS.items()
                         if c == j["company"]][0]
                gh_detail_futs.append(ex.submit(greenhouse_detail, board, j))
        for fu in as_completed(gh_detail_futs):
            fu.result()

    # drop roles whose full JD turns out to demand 3+ years experience
    matched = [j for j in matched if not wants_senior_years(j)]

    # watch tier: India tech roles without an explicit fresher marker.
    # Logged in the UI (never mailed); the JD check drops 3+ yrs demands and
    # can promote genuinely entry-level JDs into the fresher (mailed) tier.
    watch = [j for j in all_jobs
             if j.get("title") and base_match(j) and not is_fresher(j)
             and j["key"] not in {m["key"] for m in matched}]
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = [ex.submit(greenhouse_detail,
                          next(b for b, c in GREENHOUSE_BOARDS.items()
                               if c == j["company"]), j)
                for j in watch[:60] if j["key"].startswith("gh:")]
        for f in as_completed(futs):
            f.result()
    promoted, kept = [], []
    for j in watch:
        if wants_senior_years(j):
            continue
        (promoted if is_fresher(j) else kept).append(j)
    matched += promoted
    watch = kept
    near_miss = watch[:6]

    for j in matched + watch:
        j["track"] = classify(j)

    # state / diff
    state = {}
    if STATE_FILE.exists():
        try:
            state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            state = {}
    for j in matched:
        k = j["key"]
        if k not in state:
            state[k] = {"first": today, "title": j["title"]}
            j["is_new"] = True
        else:
            j["is_new"] = False
        state[k]["last"] = today
    horizon = date.today().toordinal() - 30
    state = {k: v for k, v in state.items()
             if not isinstance(v, dict)               # keep non-job markers (last_mail)
             or date.fromisoformat(v["last"]).toordinal() >= horizon}
    STATE_FILE.write_text(json.dumps(state, indent=1), encoding="utf-8")

    # skill radar over matched JD text
    corpus = " ".join(j.get("desc", "") + " " + j["title"] for j in matched).lower()
    radar = sorted(((s, len(re.findall(re.escape(s), corpus))) for s in SKILL_RADAR),
                   key=lambda x: -x[1])
    radar = [(s, c) for s, c in radar if c > 0][:12]

    # report
    def block(jobs):
        lines = []
        for j in sorted(jobs, key=lambda x: (not x["is_new"],
                                             x["company"].lower() not in PRIORITY_COMPANIES,
                                             x["company"])):
            tag = "🆕 NEW" if j["is_new"] else "still open"
            lines.append(f"### {j['title']}\n")
            lines.append(f"- **Company:** {j['company']}  |  **Location:** {j['location']}")
            lines.append(f"- **Posted:** {j['posted'] or 'n/a'}  |  **Status:** {tag}")
            lines.append(f"- **Apply:** {j['url']}")
            if j.get("desc"):
                lines.append(f"- **Key requirements:**\n{extract_requirements(j['desc'])}")
            lines.append("")
        return "\n".join(lines)

    new_cyber = [j for j in matched if j["track"] == "cyber" and j["is_new"]]
    new_swe = [j for j in matched if j["track"] == "swe" and j["is_new"]]
    new_other = [j for j in matched if j["track"] == "other" and j["is_new"]]
    open_cyber = [j for j in matched if j["track"] == "cyber" and not j["is_new"]]
    open_swe = [j for j in matched if j["track"] == "swe" and not j["is_new"]]

    rep = [f"# 🎯 Fresher SWE & Cyber Security Jobs — Daily Report",
           f"**Date:** {today}   |  **Generated:** {now}",
           f"**Sources:** {len(GREENHOUSE_BOARDS)} Greenhouse boards + "
           f"{len(PHENOM_SITES)} Phenom sites  |  "
           f"**Total postings scanned:** {len(all_jobs)}  |  "
           f"**India fresher-tech matches:** {len(matched)} "
           f"({len(new_cyber)+len(new_swe)+len(new_other)} new)\n"]
    if errors:
        rep.append(f"> ⚠️ Source errors today: {'; '.join(errors)}\n")
    rep.append("---\n## 🛡️ Cyber Security — NEW\n" + (block(new_cyber) or "_None today._\n"))
    rep.append("\n## 💻 Software Engineering — NEW\n" + (block(new_swe) or "_None today._\n"))
    if new_other:
        rep.append("\n## 🔧 Other tech fresher roles — NEW\n" + block(new_other))
    rep.append("\n## 📌 Still open from earlier\n")
    rep.append("### Cyber Security\n" + (block(open_cyber) or "_None._\n"))
    rep.append("### Software Engineering\n" + (block(open_swe) or "_None._\n"))
    if near_miss:
        rep.append("\n## 🔍 Near-miss (no explicit fresher marker — open link to verify)\n")
        rep += [f"- {j['company']} — {j['title']} — {j['location']} — {j['url']}"
                for j in near_miss]
    rep.append("\n## 📊 Tech-stack radar (mentions across today's matches)\n")
    if radar:
        rep.append("| Skill | Mentions |\n|---|---|")
        rep += [f"| {s} | {c} |" for s, c in radar]
    else:
        rep.append("_No matches today to build radar from._")
    rep.append("\n---\n_Tips: apply within 48h of posting; keep transcript ready; "
               "verify each role's eligibility windows before applying._\n")

    out = REPORTS / f"{today}.md"
    out.write_text("\n".join(rep), encoding="utf-8")
    (REPORTS / "latest.md").write_text("\n".join(rep), encoding="utf-8")

    # ---- UI: cumulative job log (docs/index.html) — every mailed job lands here
    try:
        db = update_db(load_db(), matched, watch, today)
        idx = write_site(db, today)
        print(f"[screener] ui: {idx} (fresher={len(matched)} watch={len(watch)})")
    except Exception as e:
        print(f"[screener] ui failed: {e}")

    # ---- deliver: NEW jobs only; explicit "no new jobs" mail otherwise
    new_jobs = [j for j in matched if j["is_new"]]
    if new_jobs:
        lines = [f"NEW FRESHER JOBS - {today}", ""]
        for track, label in (("cyber", "Cyber Security"),
                             ("swe", "Software Engineering"),
                             ("other", "Other tech fresher roles")):
            tjs = [j for j in new_jobs if j["track"] == track]
            if not tjs:
                continue
            lines.append(f"== {label} ==")
            for j in tjs:
                star = "  [PRIORITY]" if j["company"].lower() in PRIORITY_COMPANIES else ""
                lines.append(f"* {j['company']} - {j['title']}{star}")
                lines.append(f"  {j['location']} | posted {j['posted'] or 'n/a'}")
                lines.append(f"  {j['url']}")
                if j.get("desc"):
                    lines.append(extract_requirements(j["desc"]))
            lines.append("")
        lines.append(f"-- \n{len(matched)} role(s) tracked in total. "
                     f"Full log: docs/index.html in the job-screener repo.")
        body = "\n".join(lines)
        subject = f"NEW fresher jobs - {len(new_jobs)} found - {today}"
    else:
        body = (f"No new fresher jobs available today ({today}).\n\n"
                f"Still being tracked: {len(matched)} role(s) from earlier days "
                f"(view them in the UI: docs/index.html).\n"
                f"Keep prepping - new postings usually drop Mon-Wed.")
        subject = f"No new fresher jobs today - {today}"
    if "--no-mail" in sys.argv:
        print("[screener] mail skipped (--no-mail)")
    elif state.get("last_mail") == today:
        # a later run the same day (backup schedule / manual) must not re-mail
        print("[screener] email: sent earlier today (skipping duplicate)")
    else:
        try:
            result = send_email(subject, body)
            print("[screener]", result)
            if result.startswith("email: sent"):
                state["last_mail"] = today
                STATE_FILE.write_text(json.dumps(state, indent=1),
                                      encoding="utf-8")
        except Exception as e:
            print(f"[screener] email failed: {e}")
        try:
            print("[screener]", send_telegram(body))
        except Exception as e:
            print(f"[screener] telegram failed: {e}")
    try:
        print("[screener]", push_site(today))
    except Exception as e:
        print(f"[screener] site push failed: {e}")

    print(f"[screener] scanned={len(all_jobs)} matched={len(matched)} "
          f"new={len(new_cyber)+len(new_swe)+len(new_other)} "
          f"errors={len(errors)}")
    print(f"[screener] report: {out}")
    for j in matched:
        mark = "*" if j["is_new"] else " "
        print(f" {mark} [{j['track']:5}] {j['company']:12} {j['title'][:60]} | {j['location'][:40]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
