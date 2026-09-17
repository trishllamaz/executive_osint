# Executive Digital Footprint Assessment Pipeline

A repeatable Python pipeline for executive protection (EP) teams to assess
an executive's public digital exposure: social media presence, email
account discovery, breach exposure, and org-domain exposure.

## Setup (in VS Code)

1. Open this folder in VS Code (`File > Open Folder`).
2. Open a terminal (`` Ctrl+` ``) and create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate      # macOS/Linux
   venv\Scripts\activate         # Windows
   ```
3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Install the CLI tools not on PyPI, or where you want the latest version:
   ```bash
   pip install maigret holehe
   ```

   **theHarvester** now ships via `uv` (a fast Python package manager),
   not plain pip -- attempting `pip install .` on it will fail with a
   flit build error, so don't use that route. Instead:

   ```bash
   pip install uv          # installs uv into your existing venv, simplest option
   git clone https://github.com/laramies/theHarvester.git
   cd theHarvester
   uv sync
   uv run theHarvester -h  # sanity check -- should print the help menu
   cd ..
   ```

   Note: theHarvester requires **Python 3.12+**; `uv sync` will fetch a
   compatible interpreter for its own use automatically if your system
   Python is older, so this step should still succeed either way.

   Then tell the pipeline where your cloned theHarvester repo lives, so
   `runners.py` can `cd` into it and call `uv run theHarvester` for you:

   **macOS/Linux:**
   ```bash
   export THEHARVESTER_REPO="$(pwd)/theHarvester"
   ```
   **Windows (PowerShell):**
   ```powershell
   $env:THEHARVESTER_REPO = "C:\OSINT\ep-osint\theHarvester"
   ```
   Set it permanently via System Properties > Environment Variables on
   Windows, or by adding the `export` line to `~/.bashrc`/`~/.zshrc` on
   macOS/Linux, so you don't have to re-set it every new terminal session.

   **API keys (optional):** theHarvester's free sources (`crtsh`,
   `otx`, `hackertarget`, `duckduckgo`) work with no configuration. Note
   that theHarvester's valid source list changes between releases (e.g.
   `bing` was removed in recent versions) -- run `uv run theHarvester -h`
   in the repo to confirm the exact list for your installed version. Some
   sources (Shodan, SecurityTrails, Hunter, etc.) need an API key added to
   `theHarvester/data/api-keys.yaml` inside the cloned repo -- leave those
   blank if you don't have accounts; theHarvester just skips them. The
   pipeline defaults to the free-source list; pass a different `sources`
   value to `run_theharvester()` in `modules/runners.py` once you've added
   keys for sources you want included.
5. (Optional but recommended) Get a HaveIBeenPwned API key
   (https://haveibeenpwned.com/API/Key, ~$3.50/month) for breach checks:
   ```bash
   export HIBP_API_KEY="your-key-here"
   ```
   Put this in a `.env` file locally and load it with `python-dotenv`, or
   set it in your shell profile -- don't hardcode it in the script.

In VS Code, select the `venv` interpreter (bottom-right corner or
`Cmd/Ctrl+Shift+P > Python: Select Interpreter`) so it uses your virtual
environment.

## Usage

```bash
python run_assessment.py \
  --name "Jane Doe" \
  --email "jane.doe@company.com" \
  --phone "+14155550132" \
  --username "janedoe" \
  --domain "company.com"
```

Only `--name` is required; provide whichever of email/phone/username you have.

Each run:
- Saves a timestamped JSON snapshot to `data/<subject_slug>/<timestamp>.json`
- Diffs against the most recent prior snapshot for that subject
- Renders an HTML report to `reports/<subject_slug>_<timestamp>.html`

Run it again later (e.g. on a weekly cron / scheduled task) and the console
output plus the report will show what's **new** since the last check --
that's the core of making this a monitoring process rather than a one-off.

## Project structure

```
ep-osint/
├── run_assessment.py      # main entry point / orchestrator
├── modules/
│   ├── normalize.py       # email/phone validation & parsing
│   ├── runners.py         # Maigret / Holehe / theHarvester wrappers
│   └── breach_check.py    # HaveIBeenPwned breach lookup
├── data/                  # JSON snapshots per subject, per run
├── reports/               # rendered HTML reports
└── requirements.txt
```

## Extending it

- **Add a module**: write a function in `modules/` that returns a dict with
  at least `{"tool": ..., "ok": bool, "error": str|None}` plus whatever
  data it collects, then call it from `run_pipeline()` in `run_assessment.py`
  and add a section to the HTML template in `render_html_report()`.
- **Scheduling**: wrap `run_assessment.py` in a cron job (Linux/macOS) or
  Task Scheduler (Windows), or a simple GitHub Actions workflow, to run it
  weekly/monthly per executive automatically.
- **Alerting**: since `diff_found_items()` already isolates what's new,
  you can pipe that into a Slack webhook or email alert instead of (or in
  addition to) the HTML report.
- **Paid data-broker APIs**: for deeper coverage (home address, relatives,
  property records), services like DeHashed, Intelligence X, or dedicated
  EP vendors (e.g. Ontic, Ambient.ai's OSINT partners) offer APIs you can
  add as another module following the same pattern.

## Legal / operational notes

- Get this activity explicitly authorized in writing (legal/security
  leadership sign-off), since you're aggregating PII even on your own
  executives.
- Respect each tool's rate limits and ToS; running these at scale without
  delays/proxies will get you temporarily or permanently blocked by target
  sites.
- Store `data/` and `reports/` securely (encrypted disk, restricted access)
  -- you're accumulating a pile of sensitive PII that itself becomes a
  liability if leaked.
- Define a retention policy: how long snapshots are kept, who can access
  them, and how they're purged for departed executives.
