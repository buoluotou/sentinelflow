# Scenario Runner

Implemented in Phase 1 Step 6 (`run.py`, stdlib-only, no third-party dependencies).

It:

- Loads scenario JSON files from the `scenarios/` directory
- Validates every event locally before sending (fail fast)
- Sends simulated security events to `POST /api/v1/alerts` (the unified
  entry point; `/normalize` is reserved for raw third-party feeds because
  the dedup fingerprint includes `source` and must not split)
- Prints real-time feedback for every send
- Finishes with a `GET /api/v1/events` summary (event count, alert_count,
  risk_score, risk_level) and exits non-zero if any send failed

## Usage

```powershell
python simulator/runner/run.py                          # all scenarios once
python simulator/runner/run.py --repeat 30              # dedup + risk demo
python simulator/runner/run.py --scenario ssh_failed_login
```

| Option | Default | Meaning |
|---|---|---|
| `--base-url` | `http://127.0.0.1:8000` | backend base URL |
| `--scenario` | all | one scenario directory name |
| `--repeat` | 1 | repetitions per event |
| `--interval` | 1.0 | seconds between sends |
| `--timestamps` | `now` | `now` rewrites each timestamp to current UTC; `file` replays stored timestamps deterministically |
