# HIDS/HIPS Event-Replay Agent

A lightweight host agent that reads a replayed JSON event stream, detects attacks and decides what
to block. It never runs anything: a block is a record in `blocklist.jsonl`.

The full design and the two-person work split are in
[HIDS_HIPS_Implementation_Plan.docx](HIDS_HIPS_Implementation_Plan.docx).

## Status

| Part | Contents | Status |
|---|---|---|
| A: detection | input adapters, normalizer, reorder/dedup buffer, process table, four rules, allow-list, stream approvals, baseline export | Done; has tests for pipe, file-follow, TCP and HTTP input |
| B: scoring and response | `engine.py` (scoring, alert grouping, incidents, blocks) | Written; exercised through the Part A tests, no dedicated scoring or incident tests |
| B: measurement | `evaluate.py` | Drafted, **never run or tested** |
| B: remaining | `gen_synthetic.py`, `tune.py`, dashboard | Not started |

All testing so far uses hand-made events. Nothing has been run against the organizers' stream.

## Run

Python 3.11 or newer, no packages required (PyYAML only if you want YAML config files).

```bash
# from the replay script (prevention mode is the default)
python provided_replay.py | python -m hids_agent.agent --out out/run1

# the bundled sample
python -m hids_agent.agent --input data/sample_stream.jsonl \
    --baseline data/baseline.example.json --allowlist data/allowlist.example.json --out out/sample

# tests
python -m unittest discover -s tests -t .
```

Useful options: `--mode detect|prevent`, `--config overrides.json` (defaults are in
`hids_agent/config.py`), `--learn-baseline`, `--save-baseline PATH`, `--follow` (JSON Lines only),
`--listen-tcp HOST:PORT`, `--listen-http HOST:PORT` (requires `Content-Length`; chunked uploads are
rejected). Followed files and network inputs run until Ctrl-C.

## Baseline

Learn it from the development stream only, review it, then reuse it:

```bash
python -m hids_agent.agent -i dev_stream.jsonl --learn-baseline --save-baseline data/baseline.json --out out/learn
python provided_replay.py | python -m hids_agent.agent --baseline data/baseline.json --out out/run1
```

The first hash seen for a path becomes its baseline. If the first event for a file is the tampering
itself, the tampered hash is learned, so check the saved file.

## Allow-list

See `data/allowlist.example.json`. Entries that are too loose are ignored with a warning:

- `process` needs `parent`, `child` and `cmdline_regex`; the regex must match the whole command line.
- `services` needs `path` (`name` is optional).
- `fim` needs `path` and `hash`, unless it sets `allow_unhashed`.
- Any entry may add `host` and `expires`.

## Optional settings (both off by default)

Pass these in a `--config` file.

```json
{"bruteforce": {"alert_without_success": true, "failures_without_success": 10},
 "approvals": {"from_stream": true, "trusted_approvers": ["change-board"]}}
```

- `alert_without_success`: failures from one source raise an alert (also for a spray with no
  success). A later success upgrades the same alert. It does not cover many sources failing against
  one account without a success. Turn it on only if the development labels count failed attacks.
- `approvals.from_stream`: accepts approval events (a category such as `change_approval`) with
  `approved_by`, optional `expires` and `ticket`, plus one of: `path` and hash; `ImagePath` with
  optional service name; `parent_image`, `image` and `cmdline`; or a single `src_ip`. Approvals apply
  from their own timestamp, to their own host (every host if they name none), for 1 hour by default
  and 24 hours at most. With this off, approval events are noted in `watch.jsonl` and ignored.
  **The organizers' format is unknown, so check these field names against the development stream.**
  The approver name is only text in the stream: it is not authenticated.

## Detection rules

| Rule | Fires on |
|---|---|
| `bruteforce` | 5+ failed logons in 300 s then a success (same source and user), password spray, or failures from 3+ sources |
| `temp_service` | `services.exe`/`systemd` starting a binary from temp, `sc create` / `New-Service` / unit files pointing at temp, service-install events |
| `office_shell` | A shell with an Office program as parent or ancestor (3 levels) |
| `fim` | A baselined file modified, deleted, renamed or re-permissioned without approval |

## First steps with the organizers' development stream

1. Run the agent on it and open `summary.json`. `by_category` shows how events were classified;
   a large `other` count means field names or event types need adding in `hids_agent/normalize.py`.
2. Check `errors.log` for malformed lines.
3. Check how a new service appears, and compare it with the signals in the `temp_service` rule.
4. Build a real baseline and allow-list. The files in `data/*.example.json` contain placeholder hashes.

## Interface for Part B

The agent writes these files to the `--out` folder:

| File | Contents |
|---|---|
| `alerts.json` | Final alerts: `id, rule, title, host, entity, first_seen, last_seen, score, severity, signals, mitre, evidence, hits, user, src_ip, context, blocks, would_block` |
| `alerts.jsonl` | The same as a live feed: `type` is `alert` or `alert_update` |
| `blocklist.jsonl` | `id, ts, host, action, target, reason, alert_ids, severity, ttl_s, evidence, status, simulated` (`alert_ids` is as of the time of writing) |
| `incidents.json` | Alerts grouped per host |
| `audit.jsonl` | Detections suppressed by the allow-list |
| `watch.jsonl` | Observations that are not alerts, such as failed logons with no success or ignored approvals |
| `summary.json` | Event counts, errors, throughput |

An `alert_update` can change an alert's `title` (a failed-only alert that later succeeds).

`evidence` entries are `id:<event id>`, or `line:<n>` for events without an ID. At most 500 are kept
per alert; `hits` counts every repeat.

## Measured performance

In-process on one Windows laptop: roughly 6,000 to 9,000 events per second on a mixed workload.
Numbers depend on the machine.

## Known limits

- Only the behaviors in the table above are detected.
- By default a brute force that never succeeds is recorded in `watch.jsonl` and is not an alert. In
  prevention mode, 10 or more failures also block the source.
- Several different users mistyping from one shared NAT address, followed by a success, can look
  like a password spray (threshold: `spray_users`).
- File integrity needs a baseline; without one (and without `--learn-baseline`) it stays silent.
