"""
BOLA / IDOR Scanner — Stage 1: Config + Session Setup

Purpose: given two authenticated sessions against the same app (a low-privilege
"attacker" and a legitimate "owner"), test whether object-level authorization
is enforced correctly across a set of ID-referencing endpoints.

This stage only handles configuration and authenticated HTTP sessions.
No scanning logic yet — we build that in Stage 2.
"""

import json
import sys
import requests


class ScanConfig:
    """
    Holds everything the scanner needs to know about the target and both
    identities being tested.

    Config is loaded from a JSON file so nothing sensitive (tokens, cookies)
    ends up hardcoded in the script itself — you keep config.json out of
    version control.
    """

    def __init__(self, config_path: str):
        with open(config_path, "r") as f:
            data = json.load(f)

        self.base_url: str = data["base_url"].rstrip("/")
        self.owner_auth: dict = data["owner_auth"]      # e.g. {"cookie": "..."} or {"header": {...}}
        self.attacker_auth: dict = data["attacker_auth"]
        self.endpoints: list = data["endpoints"]         # filled in properly in Stage 2

    def __repr__(self):
        return f"<ScanConfig base_url={self.base_url} endpoints={len(self.endpoints)}>"


def build_session(auth: dict) -> requests.Session:
    """
    Builds a requests.Session pre-configured with the given identity's
    authentication. Using a Session (not raw requests.get calls) means
    cookies and headers persist automatically across every request made
    with it — important because BookStack (and most apps) use session
    cookies, not just a single bearer token.
    """
    session = requests.Session()

    if "cookie" in auth:
        # auth["cookie"] is expected as a raw "name=value" string,
        # e.g. "bookstack_session=abc123"
        name, _, value = auth["cookie"].partition("=")
        session.cookies.set(name, value)

    if "header" in auth:
        # For token/API-key based auth instead of cookies
        session.headers.update(auth["header"])

    return session


def verify_session(session: requests.Session, base_url: str, whoami_path: str) -> bool:
    """
    Sanity check before we do any real testing: confirm the session is
    actually authenticated, not silently logged out or hitting a login
    redirect. whoami_path should be an endpoint that only an authenticated
    user can reach (e.g. "/api/users/me" or a profile page for BookStack).

    This matters because a BOLA scanner running against a session that
    quietly expired will report every single endpoint as "blocked" —
    a false negative that looks like a clean bill of health but is actually
    a broken test.
    """
    resp = session.get(f"{base_url}{whoami_path}", allow_redirects=False)
    return resp.status_code == 200


def test_endpoint(owner_session, attacker_session, base_url, path, marker, endpoint_name):
    """
    Tests a single ID-referencing endpoint for broken object-level authorization.

    Logic:
      1. Fetch as owner (should have legitimate access) — confirms the object
         exists and the marker is actually present in a real response. If the
         marker isn't found even for the owner, something's wrong with our
         test setup, not the app's security, so we flag that separately.
      2. Fetch the same URL as attacker (should NOT have access, per our
         explicit permission restriction).
      3. If the marker shows up in the attacker's response too, that's a
         genuine finding: the restriction was bypassed via direct ID access.

    allow_redirects=True because /link/{id} is expected to redirect to the
    real page URL on success, or to a login/permission page on failure —
    we care about where you end up and what you see, not the redirect itself.
    """
    url = f"{base_url}{path}"

    owner_resp = owner_session.get(url, allow_redirects=True)
    attacker_resp = attacker_session.get(url, allow_redirects=True)

    owner_has_marker = marker in owner_resp.text
    attacker_has_marker = marker in attacker_resp.text

    result = {
        "endpoint": endpoint_name,
        "url": url,
        "owner_status": owner_resp.status_code,
        "owner_final_url": owner_resp.url,
        "owner_saw_content": owner_has_marker,
        "attacker_status": attacker_resp.status_code,
        "attacker_final_url": attacker_resp.url,
        "attacker_saw_content": attacker_has_marker,
    }

    if not owner_has_marker:
        result["verdict"] = "SETUP ISSUE — owner (who should have access) did not see expected content. Check the marker string and page ID."
    elif attacker_has_marker:
        result["verdict"] = "FINDING — attacker accessed restricted content via direct ID reference (BOLA)."
    else:
        result["verdict"] = "OK — access control held. Attacker was correctly blocked."

    return result


def run_scan(config: ScanConfig, owner_session, attacker_session):
    """
    Runs test_endpoint across every endpoint defined in config.endpoints.
    Each endpoint entry in config.json should look like:
      {
        "name": "Restricted page via /link/{id}",
        "path": "/link/14",
        "marker": "some unique text from that page's title or content"
      }
    """
    results = []
    for ep in config.endpoints:
        result = test_endpoint(
            owner_session, attacker_session, config.base_url,
            ep["path"], ep["marker"], ep["name"],
        )
        results.append(result)
    return results


def print_report(results):
    print("\n" + "=" * 60)
    print("BOLA SCAN RESULTS")
    print("=" * 60)
    for r in results:
        print(f"\n[{r['endpoint']}]")
        print(f"  URL: {r['url']}")
        print(f"  Owner    -> status={r['owner_status']}, saw_content={r['owner_saw_content']}, final_url={r['owner_final_url']}")
        print(f"  Attacker -> status={r['attacker_status']}, saw_content={r['attacker_saw_content']}, final_url={r['attacker_final_url']}")
        print(f"  Verdict: {r['verdict']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python bola_scanner.py <config.json>")
        sys.exit(1)

    config = ScanConfig(sys.argv[1])
    print(config)

    owner_session = build_session(config.owner_auth)
    attacker_session = build_session(config.attacker_auth)

    whoami_path = "/my-account/auth"
    owner_ok = verify_session(owner_session, config.base_url, whoami_path)
    attacker_ok = verify_session(attacker_session, config.base_url, whoami_path)
    print("Owner session valid:", owner_ok)
    print("Attacker session valid:", attacker_ok)

    if not (owner_ok and attacker_ok):
        print("One or both sessions are invalid. Fix cookies before scanning.")
        sys.exit(1)

    if not config.endpoints:
        print("\nNo endpoints configured yet. Add entries to config.json's 'endpoints' list.")
        sys.exit(0)

    results = run_scan(config, owner_session, attacker_session)
    print_report(results)
