#!/usr/bin/env python3
"""
run_domain_scan.py
Company domain / infrastructure exposure scan. This is deliberately
SEPARATE from run_assessment.py (per-executive personal exposure),
because domain exposure isn't tied to any one person -- it's the same
underlying question ("is DupPont's infrastructure exposed?") regardless
of which executive you're currently assessing, so it doesn't need to be
re-run for every person. Run it once per assessment cycle per domain.

Covers:
  - theHarvester: subdomains/emails/hosts publicly tied to the domain
  - SpiderFoot (sfp_leakix, sfp_hunter): exposed infrastructure, open
    APIs, leaked config/service data tied to the domain's IP space

IMPORTANT CAVEAT ON SPIDERFOOT DOMAIN RESULTS: sfp_leakix in particular
can pivot from one of your domain's IPs into the broader cloud netblock
(e.g. shared Azure/AWS ranges) and surface findings that belong to a
DIFFERENT tenant sharing that infrastructure, not your actual domain.
Always manually verify a finding's hostname actually resolves to your
target domain before treating it as real exposure -- this script does
NOT do that filtering for you.

Usage:
    python run_domain_scan.py --domain dupont.com
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "modules"))

from runners import run_theharvester, run_spiderfoot

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")


def slugify(name: str) -> str:
    return "".join(c.lower() if c.isalnum() else "_" for c in name).strip("_")


def run_pipeline(domain: str, harvester_sources: str = "crtsh,otx,hackertarget,duckduckgo",
                  spiderfoot_modules: str = "sfp_leakix,sfp_hunter",
                  spiderfoot_timeout: int = 300) -> dict:
    result = {
        "domain": domain,
        "run_timestamp": datetime.now(timezone.utc).isoformat(),
        "modules": {},
    }

    print(f"[*] Running theHarvester against '{domain}' ...")
    result["modules"]["theharvester"] = run_theharvester(domain, sources=harvester_sources)

    print(f"[*] Running SpiderFoot ({spiderfoot_modules}) against '{domain}' ...")
    result["modules"]["spiderfoot"] = run_spiderfoot(
        domain, modules=spiderfoot_modules, timeout=spiderfoot_timeout)

    return result


def save_snapshot(result: dict) -> str:
    domain_dir = os.path.join(DATA_DIR, "_org_" + slugify(result["domain"]))
    os.makedirs(domain_dir, exist_ok=True)
    ts = result["run_timestamp"].replace(":", "-")
    path = os.path.join(domain_dir, f"{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str, ensure_ascii=False)
    return path


def load_previous_snapshot(domain: str, before_path: str) -> dict | None:
    domain_dir = os.path.join(DATA_DIR, "_org_" + slugify(domain))
    if not os.path.isdir(domain_dir):
        return None
    snapshots = sorted(
        f for f in os.listdir(domain_dir)
        if f.endswith(".json") and os.path.join(domain_dir, f) != before_path
    )
    if not snapshots:
        return None
    with open(os.path.join(domain_dir, snapshots[-1]), encoding="utf-8") as f:
        return json.load(f)


def diff_theharvester(prev: dict | None, curr: dict) -> dict:
    curr_th = curr.get("modules", {}).get("theharvester", {})
    prev_th = (prev or {}).get("modules", {}).get("theharvester", {})
    curr_emails = set(curr_th.get("emails", []))
    prev_emails = set(prev_th.get("emails", []))
    curr_hosts = set(curr_th.get("hosts", []))
    prev_hosts = set(prev_th.get("hosts", []))
    return {
        "emails": {"new": sorted(curr_emails - prev_emails), "removed": sorted(prev_emails - curr_emails)},
        "hosts": {"new": sorted(curr_hosts - prev_hosts), "removed": sorted(prev_hosts - curr_hosts)},
    }


def render_html_report(result: dict, diffs: dict, out_path: str) -> None:
    from jinja2 import Template

    template = Template("""
    <html><head><meta charset="utf-8">
    <title>Org Infrastructure Exposure - {{ result.domain }}</title>
    <style>
      body { font-family: -apple-system, Arial, sans-serif; margin: 40px; color: #222; }
      h1 { border-bottom: 2px solid #333; padding-bottom: 8px; }
      h2 { margin-top: 32px; color: #444; }
      .new { background: #fff3cd; padding: 2px 6px; border-radius: 4px; }
      table { border-collapse: collapse; width: 100%; }
      td, th { border: 1px solid #ddd; padding: 6px 10px; text-align: left; word-break: break-word; }
      .error { color: #b00020; }
      .warn { color: #b45f06; background: #fef3e0; padding: 10px 14px; border-radius: 4px; }
      .note { font-size: 0.9em; color: #666; }
    </style></head><body>
    <h1>Org Infrastructure Exposure: {{ result.domain }}</h1>
    <p>Run time: {{ result.run_timestamp }}</p>
    <p class="note">This is a company-wide infrastructure scan, not tied to any one
    executive. Run once per assessment cycle per domain -- see individual executive
    reports (from run_assessment.py) for personal exposure.</p>

    <h2>Subdomains &amp; Emails (theHarvester)</h2>
    {% set th = result.modules.get('theharvester', {}) %}
    {% if th.get('ok') %}
      <p>{{ th.emails|length }} email(s), {{ th.hosts|length }} host(s) found publicly tied to the domain.</p>
      {% if th.hosts %}
      <h3>Hosts</h3>
      <ul>{% for host in th.hosts %}
        <li>{{ host }}{% if host in diffs.hosts.new %} <span class="new">NEW</span>{% endif %}</li>
      {% endfor %}</ul>
      {% endif %}
      {% if th.emails %}
      <h3>Emails</h3>
      <ul>{% for e in th.emails %}
        <li>{{ e }}{% if e in diffs.emails.new %} <span class="new">NEW</span>{% endif %}</li>
      {% endfor %}</ul>
      {% endif %}
    {% else %}
      <p class="error">Not run or failed: {{ th.get('error') }}</p>
    {% endif %}

    <h2>Infrastructure Findings (SpiderFoot)</h2>
    <p class="warn">
      ⚠ Manually verify each hostname below actually belongs to {{ result.domain }} before
      treating it as real exposure. Modules like sfp_leakix can pivot into shared cloud
      infrastructure (e.g. a broad Azure/AWS IP range) and surface findings that belong to
      a completely different, unrelated tenant on the same netblock.
    </p>
    {% set sf = result.modules.get('spiderfoot', {}) %}
    {% if sf.get('ok') %}
      <p>{{ sf.findings|length }} finding(s).</p>
      {% if sf.findings %}
      <table><tr><th>Type</th><th>Module</th><th>Data</th></tr>
      {% for f in sf.findings %}
        <tr><td>{{ f.get('type') }}</td><td>{{ f.get('module') }}</td>
        <td>{{ (f.get('data') or '')|truncate(300) }}</td></tr>
      {% endfor %}</table>
      {% endif %}
    {% else %}
      <p class="error">Not run or failed: {{ sf.get('error') }}</p>
    {% endif %}

    </body></html>
    """)
    html = template.render(result=result, diffs=diffs)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)


def main():
    parser = argparse.ArgumentParser(
        description="Company domain / infrastructure exposure scan "
                    "(separate from per-executive personal exposure checks)")
    parser.add_argument("--domain", required=True, help="Company domain to scan, e.g. dupont.com")
    parser.add_argument("--harvester-sources", default="crtsh,otx,hackertarget,duckduckgo",
                         help="Comma-separated theHarvester sources (default: free sources only)")
    parser.add_argument("--spiderfoot-modules", default="sfp_leakix,sfp_hunter",
                         help="Comma-separated SpiderFoot modules to run against the domain")
    parser.add_argument("--spiderfoot-timeout", type=int, default=300,
                         help="Seconds to let SpiderFoot run before giving up (default: 300)")
    args = parser.parse_args()

    result = run_pipeline(args.domain, args.harvester_sources,
                           args.spiderfoot_modules, args.spiderfoot_timeout)

    snapshot_path = save_snapshot(result)
    prev = load_previous_snapshot(args.domain, snapshot_path)
    diffs = diff_theharvester(prev, result)

    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = result["run_timestamp"].replace(":", "-")
    report_path = os.path.join(REPORTS_DIR, f"org_{slugify(args.domain)}_{ts}.html")
    render_html_report(result, diffs, report_path)

    print(f"\n[+] Snapshot saved: {snapshot_path}")
    print(f"[+] Report saved:   {report_path}")
    if prev:
        print(f"[+] Diffed against previous run: {prev['run_timestamp']}")
        for category, d in diffs.items():
            if d["new"] or d["removed"]:
                print(f"    {category}: +{len(d['new'])} new, -{len(d['removed'])} removed")
    else:
        print("[i] No previous snapshot found for this domain -- this is the baseline run.")


if __name__ == "__main__":
    main()
