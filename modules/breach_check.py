"""
breach_check.py
Checks an email against HaveIBeenPwned's breach database.
Requires an HIBP API key (paid, ~$4.39/month as of 2026) set as the
HIBP_API_KEY environment variable.
"""

import os
import requests

HIBP_BASE = "https://haveibeenpwned.com/api/v3"


def check_email_breaches(email: str, api_key: str | None = None, timeout: int = 15) -> dict:
    api_key = api_key or os.environ.get("HIBP_API_KEY")
    if not api_key:
        return {"tool": "hibp", "ok": False, "breaches": [],
                "error": "HIBP_API_KEY not set"}

    headers = {"hibp-api-key": api_key, "user-agent": "ep-osint-pipeline"}
    url = f"{HIBP_BASE}/breachedaccount/{email}"

    try:
        resp = requests.get(url, headers=headers, params={"truncateResponse": "false"},
                             timeout=timeout)
        if resp.status_code == 404:
            return {"tool": "hibp", "ok": True, "breaches": [], "error": None}
        resp.raise_for_status()
        data = resp.json()
        breaches = [
            {"name": b.get("Name"), "date": b.get("BreachDate"),
             "data_classes": b.get("DataClasses")}
            for b in data
        ]
        return {"tool": "hibp", "ok": True, "breaches": breaches, "error": None}
    except requests.RequestException as e:
        return {"tool": "hibp", "ok": False, "breaches": [], "error": str(e)}
