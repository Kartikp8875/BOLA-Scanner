# BOLA / IDOR Authorization Scanner

A Python tool that tests whether an application's object-level authorization actually holds up when an object is accessed by a direct, enumerable identifier, rather than just through its normal navigation path. Built to test [BookStack](https://www.bookstackapp.com/) (self-hosted wiki software) as a live target, but the approach applies to any app with role-based object permissions.

## Why this exists

Most quick authorization checks stop at "did the low-privilege user get a 200 or a 403?" That's not reliable on its own: some apps return HTTP 200 with an empty or generic-error body even when access is correctly denied, which makes a status-code-only check produce false negatives.

This tool instead:

1. Requests the object as an **owner** session (a user who legitimately has access) and confirms it's really there, capturing a distinctive content marker unique to that object.
2. Requests the *same* object as an **attacker** session (a low-privilege user who shouldn't have access).
3. Checks whether that marker shows up in the attacker's response, not just the status code.

If the marker leaks through to the attacker, that's a confirmed authorization bypass (BOLA). If it doesn't, access control held.

## How it's validated, not just built

Before trusting a "clean" result, the tool was tested against a known-positive case: temporarily granting the low-privilege role access, confirming the tool correctly reports it, then reverting the restriction and confirming the tool correctly reports the block. This is documented as **Section 5** in the [assessment report](./BOLA_Assessment_Report.docx). A scanner that can only ever say "secure" isn't proving anything; this one was checked both ways first.

## Files

| File | Purpose |
|---|---|
| `bola_scanner.py` | The tool itself |
| `config.example.json` | Template config, copy to `config.json` and fill in your own values |
| `BOLA_Assessment_Report.docx` | Full write-up: methodology, control tests, results, and a security observation on the target's 404-vs-403 behaviour |

## Setup

```bash
pip install requests
cp config.example.json config.json
```

Edit `config.json`:

- `base_url` — the target application's URL
- `owner_auth` / `attacker_auth` — session cookies for two separate authenticated identities. Get these from your browser's DevTools (Application/Storage → Cookies) after logging in as each user **in separate, isolated browser contexts** (e.g. a normal window and a private/incognito window). Using the same browser window for both will overwrite one session with the other.
- `endpoints` — the list of objects to test. Each entry needs:
  - `name` — a label for the test case
  - `path` — the URL path that references the object by ID (e.g. `/link/2` for BookStack)
  - `marker` — a short, distinctive string known to be present in that specific object's content, used to confirm real access versus a blocked/redirected response

**Never commit a real `config.json`** with actual session cookies to version control. It's already listed in `.gitignore`.

## Usage

```bash
python3 bola_scanner.py config.json
```

The tool first confirms both sessions are genuinely authenticated (not just that the cookies were accepted without error) before running any tests, then prints a report per endpoint: `OK` (access control held), `FINDING` (unauthorized access confirmed), or `SETUP ISSUE` (the owner session itself couldn't access the object, meaning the test config needs fixing, not the app).

## Current scope and limitations

- Tests read-level (GET) authorization only. Write/delete authorization testing (edit, delete routes) is a planned extension and requires handling CSRF token capture, which the current version doesn't do yet.
- Tested against a single object and access route (`/link/{id}`) during initial validation. Broader coverage across multiple objects, chapters, and books is future work.
- Built and tested against a local, self-hosted, non-production instance.

Full detail on scope and results: see [`BOLA_Assessment_Report.docx`](./BOLA_Assessment_Report.docx).
