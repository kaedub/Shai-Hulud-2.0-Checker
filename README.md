## Shai Hulud 2.0 Checker (for npm/yarn.lock)

Is your `yarn.lock` hiding a sandworm? This tiny script sniffs npm publish timestamps to spot versions released after a cutoff (the Shai Hulud 2.0 window). No spice required.

### TL;DR

- Checks each `package@version` in your `yarn.lock`
- Fetches publish time from the npm registry
- Flags anything published after your cutoff
- Caches results in `validate-dates.report.json` so re-runs are fast

### Run It

From this folder (next to your `yarn.lock`):

```bash
python3 main.py
```

Specify a different lockfile and/or cutoff:

```bash
python3 main.py -l /path/to/yarn.lock -c 2025-11-20
python3 main.py -l /path/to/yarn.lock -c 2025-11-20T00:00:00Z
```

Notes:
- Cutoff accepts date-only or ISO8601 with timezone.
- Needs network access. If you hit SSL weirdness:
  ```bash
  python3 -m pip install -U certifi
  ```

### What You’ll See

- ✅ `name@version — published YYYY-MM-DD` (safe, before cutoff)
- ⚠️ `name@version — published 2025-11-21T…` (after cutoff, suspicious)
- ❓ Errors (e.g., missing time info)

A JSON cache/report is written to `validate-dates.report.json` with statuses:
- `ok` or `after_cutoff`
- `publishedAtIso` / `publishedDate`

No actual sandworms were harmed. This tool checks timestamps, not code quality.
