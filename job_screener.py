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
    near_miss = [j for j in all_jobs
                 if j.get("title") and base_match(j) and not is_fresher(j)
                 and j["key"] not in {m["key"] for m in matched}][:6]

    for j in matched:
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
             if date.fromisoformat(v["last"]).toordinal() >= horizon}
    STATE_FILE.write_text(json.dumps(state, indent=1), encoding="utf-8")

    # skill radar over matched JD text
    corpus = " ".join(j.get("desc", "") + " " + j["title"] for j in matched).lower()
    radar = sorted(((s, len(re.findall(re.escape(s), corpus))) for s in SKILL_RADAR),
                   key=lambda x: -x[1])
    radar = [(s, c) for s, c in radar if c > 0][:12]

    # report
    def block(jobs):
        lines = []
        for j in sorted(jobs, key=lambda x: (not x["is_new"], x["company"])):
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

    # deliver (email full report; telegram first 4000 chars) — never fatal
    new_count = len(new_cyber) + len(new_swe) + len(new_other)
    subject = (f"Daily Fresher Jobs - {new_count} new / {len(matched)} open - {today}")
    try:
        print("[screener]", send_email(subject, plain_text("\n".join(rep))))
    except Exception as e:
        print(f"[screener] email failed: {e}")
    try:
        print("[screener]", send_telegram(plain_text("\n".join(rep))))
    except Exception as e:
        print(f"[screener] telegram failed: {e}")

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
