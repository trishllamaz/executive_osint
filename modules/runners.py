"""
runners.py
Thin wrappers that call external OSINT CLI tools (Maigret, Holehe,
theHarvester) as subprocesses and parse their JSON output into a
consistent Python structure. Keeping each tool in its own function
means you can swap, disable, or retry any single module without
touching the orchestrator.
"""

import json
import subprocess
import shutil
import tempfile
import os


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _utf8_env() -> dict:
    """
    Environment for subprocess calls that forces UTF-8 stdout/stderr.
    Without this, on Windows, tools that print unicode symbols (like
    Maigret's donate banner with a heart character) crash with
    UnicodeEncodeError when their output is captured through a pipe,
    because Windows defaults captured-pipe encoding to the system
    codepage (e.g. cp1252) instead of UTF-8.
    """
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env


def _collect_maigret_reports(tmpdir: str) -> list[str]:
    """
    Search recursively -- maigret's exact output location (cwd root vs a
    nested "reports" subfolder) has varied between versions, so don't
    assume either layout.
    """
    report_files = []
    for root, _dirs, files in os.walk(tmpdir):
        for fname in files:
            if fname.startswith("report_") and fname.endswith("_simple.json"):
                report_files.append(os.path.join(root, fname))
    return report_files


def _parse_maigret_reports(report_files: list[str], exact_identifier: str) -> tuple[list[str], dict, dict]:
    """
    Parses maigret's report_<identifier>_simple.json files. Each file's
    name tells us which identifier it came from -- the exact one the
    user searched for, or one Maigret derived along the way (e.g. a
    generic first name extracted from a bio). Matches on a derived
    generic identifier are far more likely to belong to a different
    person who just happens to share that handle, so we tag each
    finding with a confidence level instead of treating all hits the
    same way.

    Returns (found, raw_data, confidence) where confidence maps
    site_name -> "exact" | "derived".
    """
    found = []
    all_data = {}
    confidence = {}
    for fpath in report_files:
        fname = os.path.basename(fpath)
        # filename format: report_<identifier>_simple.json
        file_identifier = fname[len("report_"):-len("_simple.json")]
        level = "exact" if file_identifier == exact_identifier else "derived"

        with open(fpath, encoding="utf-8") as f:
            data = json.load(f)
        all_data[fname] = data
        for site, info in data.items():
            if info.get("status", {}).get("status") == "Claimed":
                found.append(site)
                # if a site was already found under an "exact" identifier,
                # don't downgrade it just because a later derived-identifier
                # pass also matched it
                if confidence.get(site) != "exact":
                    confidence[site] = level
    # dedupe while preserving order
    found = list(dict.fromkeys(found))
    return found, all_data, confidence


def run_maigret(username_or_email: str, timeout: int = 600) -> dict:
    """
    Maigret checks an identifier (username, sometimes email-derived
    username) against hundreds of sites, and recursively checks any
    additional usernames it extracts along the way (e.g. from a bio or
    linked profile) -- so a single run can produce several report files.
    Requires: pip install maigret

    Note: Maigret's --folderoutput flag is unreliable across versions;
    some versions ignore it and always write report_<id>_simple.json
    relative to the current working directory instead. To keep this
    contained, we run maigret with its cwd set to a temp folder and then
    collect every report_*_simple.json it wrote there, merging results
    across all identifier variants it discovered.

    IMPORTANT: results from Maigret's *derived* identifiers (generic
    names it extracts from a bio/profile, e.g. "ryan" from "ryan.rathbun")
    are much more likely to be false positives -- other people who happen
    to share that generic handle -- than results from the *exact*
    identifier you searched for. This function tags each finding's
    confidence accordingly; treat "derived" results as needing manual
    verification, not confirmed accounts.

    Returns {'tool': 'maigret', 'ok': bool, 'found': [...],
             'confidence': {site: 'exact'|'derived'}, 'raw': ..., 'error': ...}
    """
    if not _tool_available("maigret"):
        return {"tool": "maigret", "ok": False, "found": [], "confidence": {}, "raw": None,
                "error": "maigret not installed or not on PATH"}

    with tempfile.TemporaryDirectory() as tmpdir:
        cmd = [
            "maigret", username_or_email,
            "--json", "simple",
            "--timeout", "10",
            "--no-progressbar",
            "--dns-resolver", "threaded",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                                   text=True, check=False, cwd=tmpdir,
                                   env=_utf8_env(), encoding="utf-8", errors="replace")
            report_files = _collect_maigret_reports(tmpdir)
            if not report_files:
                return {"tool": "maigret", "ok": False, "found": [], "confidence": {}, "raw": None,
                        "error": f"No output file produced. stdout/stderr:\n{proc.stdout}\n{proc.stderr}"}
            found, all_data, confidence = _parse_maigret_reports(report_files, username_or_email)
            return {"tool": "maigret", "ok": True, "found": found, "confidence": confidence,
                    "raw": all_data, "error": None}
        except subprocess.TimeoutExpired:
            # Maigret writes a report file after each identifier it finishes
            # checking, before moving to the next one, so even a killed run
            # often has usable partial results sitting in tmpdir already.
            report_files = _collect_maigret_reports(tmpdir)
            if report_files:
                found, all_data, confidence = _parse_maigret_reports(report_files, username_or_email)
                return {"tool": "maigret", "ok": True, "found": found, "confidence": confidence,
                        "raw": all_data,
                        "error": (f"Timed out after {timeout}s -- results below are PARTIAL "
                                  f"(from {len(report_files)} identifier(s) checked before the "
                                  f"timeout hit; some sites/identifiers may be missing).")}
            return {"tool": "maigret", "ok": False, "found": [], "confidence": {}, "raw": None,
                    "error": f"Timed out after {timeout}s with no results produced yet."}
        except Exception as e:
            return {"tool": "maigret", "ok": False, "found": [], "confidence": {}, "raw": None, "error": str(e)}


def run_holehe(email: str, timeout: int = 120) -> dict:
    """
    Holehe checks whether an email is registered on ~120 platforms
    via password-reset/account-exists flows. Requires: pip install holehe
    Returns {'tool': 'holehe', 'ok': bool, 'found': [...], 'raw': ..., 'error': ...}
    """
    if not _tool_available("holehe"):
        return {"tool": "holehe", "ok": False, "found": [], "raw": None,
                "error": "holehe not installed or not on PATH"}

    cmd = ["holehe", email, "--only-used", "--no-color"]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                               text=True, check=False, env=_utf8_env(),
                               encoding="utf-8", errors="replace")
        lines = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
        # holehe prints a one-time legend line first: "[+] Email used, [-] Email
        # not used, [x] Rate limit" -- skip that, then take real "[+] sitename"
        # result lines. A real result's remainder after "[+]" is a single
        # token (a domain/site name) with no spaces or commas; the legend
        # line contains multiple comma-separated phrases, so filtering on
        # "no spaces" reliably excludes it.
        found = []
        for l in lines:
            if not l.startswith("[+]"):
                continue
            remainder = l.replace("[+]", "").strip()
            if remainder and " " not in remainder and "," not in remainder:
                found.append(remainder)
        return {"tool": "holehe", "ok": True, "found": found,
                "raw": proc.stdout, "error": None}
    except subprocess.TimeoutExpired:
        return {"tool": "holehe", "ok": False, "found": [], "raw": None, "error": "Timed out"}
    except Exception as e:
        return {"tool": "holehe", "ok": False, "found": [], "raw": None, "error": str(e)}


def run_theharvester(domain: str, timeout: int = 180, limit: int = 200,
                      repo_path: str | None = None,
                      sources: str = "crtsh,otx,hackertarget,duckduckgo") -> dict:
    """
    theHarvester pulls emails/subdomains tied to a company domain from
    public sources. Useful for mapping an exec's org-level exposure.

    As of the current theHarvester repo layout, it's installed and run
    via `uv` (not pip, not a standalone theHarvester.py script):
        cd <cloned-repo>
        uv sync
        uv run theHarvester -d example.com -b <sources>

    Set repo_path to the full path of your cloned theHarvester repo
    (the folder containing pyproject.toml / uv.lock), or set the
    THEHARVESTER_REPO environment variable, e.g. on Windows:
        C:\\OSINT\\ep-osint\\theHarvester

    `sources` defaults to free sources that need no API key (note: `bing`
    was removed as a source in recent theHarvester releases -- don't
    include it). Pass a different comma-separated list (or "all") once
    you've configured api-keys.yaml for paid sources you want included.
    Run `uv run theHarvester -h` in the repo to see the exact valid list
    for your installed version.

    Returns {'tool': 'theharvester', 'ok': bool, 'emails': [...], 'hosts': [...], 'error': ...}
    """
    repo_path = repo_path or os.environ.get("THEHARVESTER_REPO")

    if not repo_path:
        return {"tool": "theharvester", "ok": False, "emails": [], "hosts": [],
                "raw": None, "error": (
                    "THEHARVESTER_REPO not set. Set it to the folder containing "
                    "theHarvester's pyproject.toml (e.g. C:\\OSINT\\ep-osint\\theHarvester)."
                )}
    if not os.path.isdir(repo_path):
        return {"tool": "theharvester", "ok": False, "emails": [], "hosts": [],
                "raw": None, "error": f"repo_path does not exist: {repo_path}"}
    if not _tool_available("uv"):
        return {"tool": "theharvester", "ok": False, "emails": [], "hosts": [],
                "raw": None, "error": (
                    "'uv' not found on PATH. Activate the venv where you ran "
                    "'pip install uv', or install uv globally."
                )}

    with tempfile.TemporaryDirectory() as tmpdir:
        out_base = os.path.join(tmpdir, "result")
        cmd = ["uv", "run", "theHarvester", "-d", domain, "-b", sources,
               "-l", str(limit), "-f", out_base]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                                   text=True, check=False, cwd=repo_path,
                                   env=_utf8_env(), encoding="utf-8", errors="replace")
            json_path = out_base + ".json"
            if not os.path.exists(json_path):
                return {"tool": "theharvester", "ok": False, "emails": [], "hosts": [],
                        "raw": proc.stdout + proc.stderr,
                        "error": "No output file produced (see raw for tool output)"}
            with open(json_path) as f:
                data = json.load(f)
            return {
                "tool": "theharvester", "ok": True,
                "emails": data.get("emails", []),
                "hosts": data.get("hosts", []),
                "raw": data, "error": None,
            }
        except subprocess.TimeoutExpired:
            return {"tool": "theharvester", "ok": False, "emails": [], "hosts": [],
                    "raw": None, "error": "Timed out"}
        except Exception as e:
            return {"tool": "theharvester", "ok": False, "emails": [], "hosts": [],
                    "raw": None, "error": str(e)}


def run_spiderfoot(email: str, timeout: int = 180, repo_path: str | None = None,
                    modules: str = "sfp_citadel,sfp_leakix,sfp_hunter") -> dict:
    """
    Runs a SpiderFoot CLI scan against an email address using the given
    modules, and returns any leak-database / paste-site findings. This
    covers leak sources beyond HIBP's public breach catalogue, which is
    the main reason to run it alongside HIBP rather than instead of it.

    Default modules are sfp_citadel (Leak-Lookup.com), sfp_leakix
    (LeakIX), and sfp_hunter (Hunter.io) -- each needs its own free API
    key configured inside SpiderFoot's own settings first (via its web
    UI: `sf.py -l 127.0.0.1:5001`, then Settings > module name > paste
    the corresponding API key > Save). sfp_psbdmp and sfp_pastebin were
    tried first but proved unreliable: sfp_pastebin needs a separate
    Google Custom Search API key most people won't have configured, and
    psbdmp.cc's own API has been flaky/returning invalid responses.

    SpiderFoot is run headless via its own CLI (sf.py -s <target> -m
    <modules> -o json -q), using SpiderFoot's own venv python, from
    inside its cloned repo. Set repo_path to the folder containing
    sf.py, or set the SPIDERFOOT_REPO environment variable, e.g. on
    Windows: C:\\OSINT\\ep-osint\\spiderfoot

    IMPORTANT PARSING NOTE: SpiderFoot's final "-o json" summary array
    at the very end of a run is unreliable -- it can come back as an
    empty [] even when real findings clearly streamed through during
    the scan. So instead of relying on that final array, this parses
    every individual JSON event object emitted to stdout throughout the
    run (each finding is printed as its own single-line JSON object as
    it's discovered), and filters out the one that just echoes the
    input target (module: "SpiderFoot UI", not a real finding).

    Returns {'tool': 'spiderfoot', 'ok': bool,
             'findings': [{'type', 'data', 'module', 'source', 'generated'}, ...],
             'raw': ..., 'error': ...}
    """
    import re

    repo_path = repo_path or os.environ.get("SPIDERFOOT_REPO")

    if not repo_path:
        return {"tool": "spiderfoot", "ok": False, "findings": [], "raw": None,
                "error": (
                    "SPIDERFOOT_REPO not set. Set it to the folder containing "
                    "sf.py (e.g. C:\\OSINT\\ep-osint\\spiderfoot)."
                )}
    if not os.path.isdir(repo_path):
        return {"tool": "spiderfoot", "ok": False, "findings": [], "raw": None,
                "error": f"repo_path does not exist: {repo_path}"}

    # Must use SpiderFoot's OWN venv's python, not whatever "python" resolves
    # to in the caller's shell -- otherwise cherrypy and its other
    # dependencies (installed only inside spiderfoot/.venv) aren't found.
    venv_python_win = os.path.join(repo_path, ".venv", "Scripts", "python.exe")
    venv_python_posix = os.path.join(repo_path, ".venv", "bin", "python")
    if os.path.exists(venv_python_win):
        python_exe = venv_python_win
    elif os.path.exists(venv_python_posix):
        python_exe = venv_python_posix
    else:
        return {"tool": "spiderfoot", "ok": False, "findings": [], "raw": None,
                "error": (
                    f"Could not find a .venv python interpreter under {repo_path}. "
                    "Expected spiderfoot/.venv/Scripts/python.exe (Windows) or "
                    "spiderfoot/.venv/bin/python (macOS/Linux) -- make sure you "
                    "created a venv inside the spiderfoot folder and installed "
                    "requirements.txt into it."
                )}

    cmd = [python_exe, "sf.py", "-s", email, "-m", modules, "-o", "json", "-q"]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                               text=True, check=False, cwd=repo_path,
                               env=_utf8_env(), encoding="utf-8", errors="replace")
        stdout = proc.stdout or ""

        # Findings are printed as individual single-line JSON objects
        # throughout the run: {"generated": ..., "type": ..., "data": ...,
        # "module": ..., "source": ...}. Extract every one of these rather
        # than relying on the (unreliable) final summary array.
        findings = []
        for match in re.finditer(r'\{"generated":.*?\}', stdout):
            try:
                row = json.loads(match.group(0))
            except json.JSONDecodeError:
                continue
            if row.get("module") == "SpiderFoot UI":
                continue  # just echoes the input target, not a real finding
            findings.append(row)

        if not findings and not stdout.strip():
            return {"tool": "spiderfoot", "ok": False, "findings": [], "raw": stdout,
                    "error": f"No output produced. stderr:\n{proc.stderr}"}

        return {"tool": "spiderfoot", "ok": True, "findings": findings,
                "raw": stdout, "error": None}
    except subprocess.TimeoutExpired:
        return {"tool": "spiderfoot", "ok": False, "findings": [], "raw": None,
                "error": f"Timed out after {timeout}s"}
    except Exception as e:
        return {"tool": "spiderfoot", "ok": False, "findings": [], "raw": None, "error": str(e)}


def run_dehashed(email: str, api_key: str | None = None, timeout: int = 120,
                  size: int = 1000) -> dict:
    """
    Runs the DeHashed-API-Tool CLI (https://github.com/hmaverickadams/DeHashed-API-Tool)
    against an email address. This is used instead of SpiderFoot's built-in
    sfp_dehashed module, which targets DeHashed's old v1 API and fails
    against the current v2 API. This tool is purpose-built for v2.

    Requires: pip install git+https://github.com/hmaverickadams/DeHashed-API-Tool
    (installed into the SAME venv this script runs in, so `dehashapitool`
    resolves via subprocess).

    IMPORTANT -- SENSITIVE DATA: DeHashed can return actual breached
    credentials, including plaintext passwords, not just "this email was
    in breach X" like HIBP/Citadel. Callers of this function MUST NOT
    write the returned records into the same snapshot/report used for
    normal exposure findings. Route them through a separate, restricted
    storage path instead (see run_assessment.py's handling of this).

    Set the API key via the api_key parameter or the DEHASHED_API_KEY
    environment variable.

    Returns {'tool': 'dehashed', 'ok': bool,
             'records': [{<csv columns as returned by the tool>}, ...],
             'error': ...}
    """
    import csv
    import tempfile

    api_key = api_key or os.environ.get("DEHASHED_API_KEY")
    if not api_key:
        return {"tool": "dehashed", "ok": False, "records": [],
                "error": "DEHASHED_API_KEY not set"}

    if not _tool_available("dehashapitool"):
        return {"tool": "dehashed", "ok": False, "records": [],
                "error": (
                    "dehashapitool not found. Install with: "
                    "pip install git+https://github.com/hmaverickadams/DeHashed-API-Tool "
                    "(into the same venv this pipeline runs in)."
                )}

    with tempfile.TemporaryDirectory() as tmpdir:
        out_csv = os.path.join(tmpdir, "results.csv")
        cmd = [
            "dehashapitool", "-e", email,
            "--dehashed-key", api_key,
            "-s", str(size),
            "-oS", out_csv,  # silent CSV output -- avoids printing credentials to console/logs
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                                   text=True, check=False, env=_utf8_env(),
                                   encoding="utf-8", errors="replace")
            if not os.path.exists(out_csv):
                combined_output = f"{proc.stdout}\n{proc.stderr}"
                if "no results" in combined_output.lower():
                    # A genuine, successful "not found" -- dehashapitool doesn't
                    # write an output file at all when there's nothing to write,
                    # so no file existing here isn't necessarily a failure.
                    return {"tool": "dehashed", "ok": True, "records": [], "error": None}
                return {"tool": "dehashed", "ok": False, "records": [],
                        "error": f"No output file produced. stdout/stderr:\n{combined_output}"}

            records = []
            with open(out_csv, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    records.append(dict(row))

            return {"tool": "dehashed", "ok": True, "records": records, "error": None}
        except subprocess.TimeoutExpired:
            return {"tool": "dehashed", "ok": False, "records": [],
                    "error": f"Timed out after {timeout}s"}
        except Exception as e:
            return {"tool": "dehashed", "ok": False, "records": [], "error": str(e)}