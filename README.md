# 🎯 Job Screener — Fresher SWE & Cyber Security (India)

A daily job-screening agent that scans product-based companies' career boards for
**strictly fresher-level Software Engineer and Cyber Security roles in India**,
extracts the key requirements from each posting, and emails you a daily report.

## How it works

`job_screener.py` (Python 3, **stdlib only — no pip installs**):

1. **Scans 14 sources in parallel**
   - 13 Greenhouse job boards: Stripe, Cloudflare, Elastic, Twilio, Dropbox,
     Discord, Netskope, Okta, PagerDuty, Zscaler, Datadog, ZoomInfo, Rubrik
   - Mastercard's Phenom careers site (via sitemap + JSON-LD `JobPosting` blocks)
2. **Filters strictly to fresher roles** — a job qualifies only if its title
   carries an explicit marker (intern / graduate / trainee / campus / new grad /
   entry-level / Engineer I / Analyst I / Associate Analyst) or the JD text
   contains entry-level language ("entry-level", "fresher", "0–2 years",
   "currently pursuing"). Postings demanding 3+ years are hard-excluded, as are
   senior / level-II+ / sales roles.
3. **India-locations only** (configurable via the `INDIA` regex).
4. **Extracts requirements** from each matching posting (Greenhouse job API
   content; Phenom JSON-LD description).
5. **Tracks seen jobs** in `screener-state.json` → the report separates 🆕 NEW
   from *still open*; entries age out after 30 days.
6. **Writes the report** to `daily-reports/YYYY-MM-DD.md` (+ `latest.md`),
   including a tech-stack radar table (skill mentions across matched JDs) and a
   capped "near-miss" footer for plain-titled roles worth a manual check.
7. **Delivers it**: full report via Gmail SMTP and/or first 4000 chars via
   Telegram Bot API.

## Setup

```bash
cp mailer.example.json mailer.json   # then fill in your details
python job_screener.py
```

Email delivery uses a [Google App Password](https://myaccount.google.com/security)
(not your real password — never store that). Telegram is optional; empty fields
are silently skipped and delivery errors never break the report.

## Adding companies

One line in the config at the top of `job_screener.py`:

```python
GREENHOUSE_BOARDS["newco"] = "NewCo"          # any Greenhouse board slug
PHENOM_SITES["newco"] = "https://careers.newco.com/us/en"
```

## Scheduling

Run it daily however you like — Task Scheduler, cron, or an agent automation.
The report is idempotent per day and safe to re-run.

## Files

| File | Purpose |
|---|---|
| `job_screener.py` | the screener + report generator + mailer |
| `mailer.example.json` | delivery config template (copy to `mailer.json`) |
| `screener-state.json` | seen-job tracker (gitignored) |
| `daily-reports/` | generated reports (gitignored) |
