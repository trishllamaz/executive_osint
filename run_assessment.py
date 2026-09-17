#!/usr/bin/env python3
"""
run_assessment.py
Per-executive digital footprint assessment: personal exposure only
(social presence, email account discovery, breach exposure, paste/leak
sources tied to their specific email). This does NOT include company
domain / infrastructure exposure -- that's a separate, org-wide concern
that doesn't belong to any one person and shouldn't be re-run for every
executive. See run_domain_scan.py for that.

Usage:
    python run_assessment.py --name "Jane Doe" --email jane.doe@company.com \
        --phone "+14155550132" --username janedoe

What it does:
  1. Normalizes/validates the email and phone input.
  2. Runs each personal-exposure OSINT module.
  3. Saves a timestamped JSON snapshot to data/<subject>/<timestamp>.json
  4. Diffs against the most recent prior snapshot for the same subject.
  5. Renders a simple HTML report to reports/<subject>_<timestamp>.html
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "modules"))

from normalize import normalize_email, normalize_phone
from runners import run_maigret, run_holehe, run_spiderfoot, run_dehashed
from breach_check import check_email_breaches

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")


def slugify(name: str) -> str:
    return "".join(c.lower() if c.isalnum() else "_" for c in name).strip("_")


def run_pipeline(name: str, email: str | None, phone: str | None,
                  username: str | None, default_region: str = "US",
                  maigret_timeout: int = 600, include_dehashed: bool = False) -> dict:
    result = {
        "subject": name,
        "run_timestamp": datetime.now(timezone.utc).isoformat(),
        "inputs": {"email": email, "phone": phone, "username": username},
        "normalized": {},
        "modules": {},
    }

    # --- Normalize inputs ---
    if email:
        result["normalized"]["email"] = normalize_email(email)
    if phone:
        result["normalized"]["phone"] = normalize_phone(phone, default_region)

    # --- Social presence sweep (Maigret needs a username-like identifier) ---
    identifier = username or (email.split("@")[0] if email else None)
    if identifier:
        print(f"[*] Running Maigret against '{identifier}' (timeout={maigret_timeout}s) ...")
        result["modules"]["maigret"] = run_maigret(identifier, timeout=maigret_timeout)

    # --- Email account discovery + breach + leak checks (all keyed to this person's email) ---
    if email and result["normalized"].get("email", {}).get("valid"):
        print(f"[*] Running Holehe against '{email}' ...")
        result["modules"]["holehe"] = run_holehe(email)

        print(f"[*] Checking HIBP breach exposure for '{email}' ...")
        result["modules"]["hibp"] = check_email_breaches(email)

        print(f"[*] Running SpiderFoot (paste/leak sources) for '{email}' ...")
        result["modules"]["spiderfoot"] = run_spiderfoot(email)

        # --- DeHashed: opt-in only, sensitive data routed separately ---
        # DeHashed can return actual breached credentials (including
        # plaintext passwords), which is materially more sensitive than
        # everything else this pipeline collects. Its raw records are
        # NEVER put in `result["modules"]` (which becomes the normal,
        # widely-accessible snapshot/report) -- only a redacted summary
        # is. The raw records are stashed under `_dehashed_raw`, which
        # main() strips out and writes to a separate, clearly-labeled
        # restricted file before the normal snapshot is ever saved.
        if include_dehashed:
            print(f"[*] Running DeHashed for '{email}' (sensitive -- restricted storage) ...")
            dehashed_result = run_dehashed(email)
            result["modules"]["dehashed_summary"] = {
                "ok": dehashed_result.get("ok"),
                "record_count": len(dehashed_result.get("records", [])),
                "error": dehashed_result.get("error"),
            }
            result["_dehashed_raw"] = dehashed_result

    return result


def save_restricted_dehashed(subject: str, run_timestamp: str, dehashed_result: dict) -> str | None:
    """
    Writes DeHashed's raw findings (which may include plaintext breached
    passwords) to a SEPARATE, clearly-labeled restricted file -- never
    mixed into the normal data/<subject>/<timestamp>.json snapshot that
    the rest of this pipeline reads/diffs/reports from.

    This function does not itself enforce OS-level file permissions
    (that varies by platform) -- you are responsible for restricting
    access to the `restricted/` folder this writes into (e.g. via NTFS
    permissions on Windows, or chmod on macOS/Linux) as part of your
    program's data handling process.
    """
    if not dehashed_result or not dehashed_result.get("records"):
        return None

    subject_dir = os.path.join(DATA_DIR, slugify(subject), "restricted")
    os.makedirs(subject_dir, exist_ok=True)
    ts = run_timestamp.replace(":", "-")
    path = os.path.join(subject_dir, f"{ts}_dehashed.json")

    payload = {
        "WARNING": (
            "This file may contain actual breached credentials, including "
            "plaintext passwords. Restrict access to this file/folder per "
            "your data handling policy. Do not include its contents in "
            "shared reports."
        ),
        "subject": subject,
        "run_timestamp": run_timestamp,
        "record_count": len(dehashed_result["records"]),
        "records": dehashed_result["records"],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str, ensure_ascii=False)
    return path


def save_snapshot(result: dict) -> str:
    # Defense in depth: even if a caller forgets to pop it, never let
    # DeHashed's raw (potentially credential-containing) data leak into
    # the normal, widely-accessible snapshot file.
    result = {k: v for k, v in result.items() if k != "_dehashed_raw"}
    subject_dir = os.path.join(DATA_DIR, slugify(result["subject"]))
    os.makedirs(subject_dir, exist_ok=True)
    ts = result["run_timestamp"].replace(":", "-")
    path = os.path.join(subject_dir, f"{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str, ensure_ascii=False)
    return path


def load_previous_snapshot(subject: str, before_path: str) -> dict | None:
    subject_dir = os.path.join(DATA_DIR, slugify(subject))
    if not os.path.isdir(subject_dir):
        return None
    snapshots = sorted(
        f for f in os.listdir(subject_dir)
        if f.endswith(".json") and os.path.join(subject_dir, f) != before_path
    )
    if not snapshots:
        return None
    with open(os.path.join(subject_dir, snapshots[-1]), encoding="utf-8") as f:
        return json.load(f)


def diff_found_items(prev: dict | None, curr: dict) -> dict:
    """Compares 'found' lists (site names, breach names) between runs."""
    diffs = {}
    for module_name in ("maigret", "holehe"):
        curr_found = set(curr.get("modules", {}).get(module_name, {}).get("found", []))
        prev_found = set(
            (prev or {}).get("modules", {}).get(module_name, {}).get("found", [])
        )
        diffs[module_name] = {
            "new": sorted(curr_found - prev_found),
            "removed": sorted(prev_found - curr_found),
        }

    curr_breaches = {b["name"] for b in curr.get("modules", {}).get("hibp", {}).get("breaches", [])}
    prev_breaches = {b["name"] for b in (prev or {}).get("modules", {}).get("hibp", {}).get("breaches", [])}
    diffs["hibp"] = {
        "new": sorted(curr_breaches - prev_breaches),
        "removed": sorted(prev_breaches - curr_breaches),
    }
    return diffs


def render_html_report(result: dict, diffs: dict, out_path: str) -> None:
    from jinja2 import Template

    template = Template("""
    <html><head><meta charset="utf-8">
    <title>Digital Footprint Report - {{ result.subject }}</title>
    <style>
      body { font-family: -apple-system, Arial, sans-serif; margin: 40px; color: #222; }
      h1 { border-bottom: 2px solid #333; padding-bottom: 8px; }
      h2 { margin-top: 32px; color: #444; }
      h3 { margin-top: 16px; }
      .new { background: #fff3cd; padding: 2px 6px; border-radius: 4px; }
      .module { margin-bottom: 24px; }
      table { border-collapse: collapse; width: 100%; }
      td, th { border: 1px solid #ddd; padding: 6px 10px; text-align: left; }
      .error { color: #b00020; }
      .partial { color: #b45f06; background: #fef3e0; padding: 6px 10px; border-radius: 4px; }
      .warn { color: #b45f06; background: #fef3e0; padding: 10px 14px; border-radius: 4px; border: 1px solid #f0ad4e; }
      .note { font-size: 0.9em; color: #666; }
    </style></head><body>
    <h1>Digital Footprint Report: {{ result.subject }}</h1>
    <p>Run time: {{ result.run_timestamp }}</p>
    <p class="note">Personal exposure only. For company domain / infrastructure
    exposure, see the separate org-level report from run_domain_scan.py.</p>

    {% set phone = result.normalized.get('phone') %}
    {% if phone %}
    <h2>Phone Number</h2>
    {% if phone.valid %}
      <table>
        <tr><th>Number (E.164)</th><td>{{ phone.e164 }}</td></tr>
        <tr><th>Country</th><td>{{ phone.country }}</td></tr>
        <tr><th>Location</th><td>{{ phone.location or 'Unknown' }}</td></tr>
        <tr><th>Carrier</th><td>{{ phone.carrier or 'Unknown / not available for this number type' }}</td></tr>
      </table>
    {% else %}
      <p class="error">Invalid phone number: {{ phone.error }}</p>
    {% endif %}
    {% endif %}

    <h2>Social Presence (Maigret)</h2>
    {% set m = result.modules.get('maigret', {}) %}
    {% if m.get('ok') %}
      {% if m.get('error') %}
        <p class="partial">⚠ Partial results: {{ m.get('error') }}</p>
      {% endif %}
      {% set confidence = m.get('confidence', {}) %}
      <p>{{ m.found|length }} confirmed profile(s) found.</p>
      <p class="note">
        "Exact match" = found under the identifier you searched for directly (high confidence).
        "Derived match" = found under a related/generic identifier Maigret extracted along the way
        (e.g. a first name) -- verify manually before treating as confirmed, since a common name
        can easily belong to someone else.
      </p>
      <h3>Exact match ({{ confidence.values()|select('equalto','exact')|list|length }})</h3>
      <ul>{% for site in m.found %}{% if confidence.get(site) == 'exact' %}
        <li>{{ site }}{% if site in diffs.maigret.new %} <span class="new">NEW</span>{% endif %}</li>
      {% endif %}{% endfor %}</ul>
      <h3 style="color:#b45f06;">Derived match -- verify manually ({{ confidence.values()|select('equalto','derived')|list|length }})</h3>
      <ul>{% for site in m.found %}{% if confidence.get(site) == 'derived' %}
        <li>{{ site }}{% if site in diffs.maigret.new %} <span class="new">NEW</span>{% endif %}</li>
      {% endif %}{% endfor %}</ul>
    {% else %}
      <p class="error">Not run or failed: {{ m.get('error') }}</p>
    {% endif %}

    <h2>Email Account Discovery (Holehe)</h2>
    {% set h = result.modules.get('holehe', {}) %}
    {% if h.get('ok') %}
      <ul>{% for site in h.found %}
        <li>{{ site }}{% if site in diffs.holehe.new %} <span class="new">NEW</span>{% endif %}</li>
      {% endfor %}</ul>
    {% else %}
      <p class="error">Not run or failed: {{ h.get('error') }}</p>
    {% endif %}

    <h2>Breach Exposure (HIBP)</h2>
    {% set b = result.modules.get('hibp', {}) %}
    {% if b.get('ok') %}
      <table><tr><th>Breach</th><th>Date</th><th>Data Exposed</th></tr>
      {% for br in b.breaches %}
        <tr><td>{{ br.name }}{% if br.name in diffs.hibp.new %} <span class="new">NEW</span>{% endif %}</td>
        <td>{{ br.date }}</td><td>{{ br.data_classes|join(', ') }}</td></tr>
      {% endfor %}</table>
    {% else %}
      <p class="error">Not run or failed: {{ b.get('error') }}</p>
    {% endif %}

    <h2>Paste-Site &amp; Leak Sources (SpiderFoot)</h2>
    <p class="note">
      Checks paste-site dumps and leak databases beyond HIBP's public breach catalogue.
      An empty result here is a genuine "not found in these sources" -- not every leak
      shows up on paste sites, so this complements HIBP rather than replacing it.
    </p>
    {% set sf = result.modules.get('spiderfoot', {}) %}
    {% if sf.get('ok') %}
      <p>{{ sf.findings|length }} finding(s).</p>
      {% if sf.findings %}
      <table><tr><th>Type</th><th>Data</th><th>Module</th></tr>
      {% for f in sf.findings %}
        <tr><td>{{ f.get('type') }}</td><td>{{ f.get('data') }}</td><td>{{ f.get('module') }}</td></tr>
      {% endfor %}</table>
      {% endif %}
    {% else %}
      <p class="error">Not run or failed: {{ sf.get('error') }}</p>
    {% endif %}

    {% set dh = result.modules.get('dehashed_summary') %}
    {% if dh %}
    <h2>DeHashed Credential Exposure</h2>
    <p class="warn">
      ⚠ RESTRICTED -- results are NOT shown here. DeHashed can return actual breached
      credentials including plaintext passwords, so raw findings are written to a
      separate, restricted-access file rather than this report. Access that file only
      per your program's data handling policy.
    </p>
    {% if dh.ok %}
      <p>{{ dh.record_count }} record(s) found. See restricted file (not this report) for details.</p>
    {% else %}
      <p class="error">Not run or failed: {{ dh.error }}</p>
    {% endif %}
    {% endif %}

    </body></html>
    """)
    html = template.render(result=result, diffs=diffs)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)


def main():
    parser = argparse.ArgumentParser(
        description="Per-executive personal digital footprint assessment "
                    "(no company domain/infrastructure scanning -- see "
                    "run_domain_scan.py for that)")
    parser.add_argument("--name", required=True, help="Subject's full name (for labeling)")
    parser.add_argument("--email", help="Email address to check")
    parser.add_argument("--phone", help="Phone number to check")
    parser.add_argument("--username", help="Known username/handle, if any")
    parser.add_argument("--region", default="US", help="Default region for phone parsing")
    parser.add_argument("--maigret-timeout", type=int, default=600,
                         help="Seconds to let Maigret run before giving up (default: 600). "
                              "Use a small value like 120 for a quick test run.")
    parser.add_argument("--dehashed", action="store_true",
                         help="Also run DeHashed (paid, requires DEHASHED_API_KEY). "
                              "Opt-in only: can return actual breached credentials "
                              "including plaintext passwords. Results are written to "
                              "a separate restricted file, not the normal report.")
    args = parser.parse_args()

    if not any([args.email, args.phone, args.username]):
        parser.error("Provide at least one of --email, --phone, or --username")

    result = run_pipeline(args.name, args.email, args.phone, args.username,
                           args.region, args.maigret_timeout, args.dehashed)

    # Pull the raw DeHashed data out BEFORE the normal snapshot is saved,
    # and route it to the separate restricted file.
    dehashed_raw = result.pop("_dehashed_raw", None)
    if dehashed_raw:
        restricted_path = save_restricted_dehashed(
            args.name, result["run_timestamp"], dehashed_raw)
        if restricted_path:
            print(f"[+] DeHashed findings (RESTRICTED) saved: {restricted_path}")

    snapshot_path = save_snapshot(result)
    prev = load_previous_snapshot(args.name, snapshot_path)
    diffs = diff_found_items(prev, result)

    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = result["run_timestamp"].replace(":", "-")
    report_path = os.path.join(REPORTS_DIR, f"{slugify(args.name)}_{ts}.html")
    render_html_report(result, diffs, report_path)

    print(f"\n[+] Snapshot saved: {snapshot_path}")
    print(f"[+] Report saved:   {report_path}")
    if prev:
        print(f"[+] Diffed against previous run: {prev['run_timestamp']}")
        for module, d in diffs.items():
            if d["new"] or d["removed"]:
                print(f"    {module}: +{len(d['new'])} new, -{len(d['removed'])} removed")
    else:
        print("[i] No previous snapshot found for this subject -- this is the baseline run.")


if __name__ == "__main__":
    main()
