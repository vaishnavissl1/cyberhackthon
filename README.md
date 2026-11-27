# HIDS/HIPS Event-Replay Agent

A standard-library Python agent for replayed host telemetry. It detects brute force followed by a success, services running from temporary directories, Office spawning a shell, and file changes against a hash baseline. It records simulated prevention decisions and generates an HTML case dashboard. The replay never executes commands or changes the host.

See the [implementation plan](HIDS_HIPS_Implementation_Plan.docx) for the original scope and work split.

## Run a case

Use Python 3.11 or newer from the repository root.

~~~powershell
python -m hids_agent demo --out runs/demo
python -m hids_agent demo --split holdout --out runs/holdout
~~~

These commands run the detector on generated raw events with independent labels. Open `dashboard.html` in the run directory. A synthetic PASS describes that fixture. The organizer development and hidden streams still need separate evaluation.

For organizer input or the sample stream, use the same agent entry point:

~~~powershell
python provided_replay.py | python -m hids_agent.agent --labels data/dev_labels.json --out runs/organizer
python -m hids_agent.agent --input data/sample_stream.jsonl --baseline data/baseline.example.json --allowlist data/allowlist.example.json --out runs/sample
~~~

Omit `--labels` when ground truth is unavailable. Pass `--mode detect` to keep requested decisions on the alert and leave the block journal empty. For an organizer run, supply its baseline and allow-list if available. Inspect `summary.json` for unrecognized events and processing errors, then use `errors.log` to investigate failures. Record how service creation appears in the raw stream. If permitted, label sequences from the raw stream independently before evaluating.

## Generate, tune, and evaluate

~~~powershell
python -m hids_agent.gen_synthetic --split dev --mixed --out runs/dev-input
python -m hids_agent.gen_synthetic --split holdout --mixed --out runs/holdout-input
python -m hids_agent.tune --events runs/dev-input/events-mixed.jsonl --labels runs/dev-input/labels.json --baseline runs/dev-input/baseline.json --allowlist runs/dev-input/allowlist.json --failures 5 6 --windows 30 300 --success-delays 60 600 --spray-users 5 6 --cooldowns 900 --min-severities medium high --config-out runs/frozen.json --report-out runs/sweep.json
python -m hids_agent.agent --input runs/holdout-input/events-mixed.jsonl --baseline runs/holdout-input/baseline.json --allowlist runs/holdout-input/allowlist.json --labels runs/holdout-input/labels.json --config runs/frozen.json --sweep runs/sweep.json --out runs/frozen-holdout
python -m hids_agent.evaluate --out runs/frozen-holdout --labels runs/holdout-input/labels.json
~~~

The generator writes an ordered raw stream, labels, baseline and allow-list. Its optional mixed stream adds alternate field styles, a duplicate, a malformed line and, in holdout, out-of-order records. Tune on development only. A raw tuning sweep keeps full-recall trials, ranks by fewer false alarms and breaks ties using lower count and severity thresholds, longer correlation windows and a shorter grouping cooldown. With no full-recall setting the tuner exits with status 1 and writes no selected config.

Labels include `attack_id`, `type`, `host`, `start`, `end` and optional `event_ids`. `--stream` evaluates a saved run against embedded sequence annotations read with the same framing as detection. The detector drops label fields before running any rule. A scoped shared reference takes precedence. Time-only labels require a host, recognized rule and interval. Independent observations within one alert may match different sequences. Ambiguous observations are flagged. Recall counts distinct matched sequences. Precision counts matched alerts. With an undefined denominator, the metric is unavailable.

The labeled target is PASS when all sequences are found, there are at most two false alarms, and at least one active simulated decision is linked to a matching observation. `hids_agent.evaluate` exits 0 on PASS, 1 on FAIL or INCOMPLETE, and 2 on an input or usage error. Runs without labels show UNSCORED.

The `run` subcommand can also import a candidate JSONL handoff. The files in `examples/` give a three-event Office case, its candidate example and an independent label. Both entry points use the same scoring and response engine.

## Dashboard and journals

~~~powershell
python -m dashboard.server --root runs
~~~

Open [the local dashboard](http://127.0.0.1:8765/). Select development, holdout, or upload raw JSON/JSONL with optional labels, baseline and allow-list. The runner binds to loopback. Standalone `dashboard.html` files also open offline.

| Output | Contents |
| --- | --- |
| `alerts.jsonl`, `alerts.json` | Live alerts and updates, then final grouped alerts with score, severity and observation evidence |
| `blocklist.jsonl` | Simulated actions with final reverse links, protected status and time-to-live |
| `audit.jsonl`, `watch.jsonl` | Approved changes and observations that fall short of a confirmed alert |
| `incidents.json`, `summary.json` | Host incidents, event volume, input quality and throughput |
| `report.json`, `report.md`, `dashboard.html` | Evaluation and review |
| `sweep.json` | Development tuning trials when supplied through `--sweep` |

The default response records blocks after a confirmed detection. A failure-only IP block can be enabled through `bruteforce.preempt_block_factor`. It earns no evaluation credit by itself. A file change without a comparable hash can raise an unverified alert and receives no simulated block. Decision de-duplication is per host within the configured TTL.

## Verify and present

~~~powershell
python -m unittest discover -s tests -t .
python -m hids_agent.benchmark --raw --events 1000000
python -m hids_agent demo --live --out runs/presentation
~~~

During the demo, show a live alert and its block line. Open the finished dashboard and expand the Office alert to show its grouped evidence and score. Show the approved file change in the audit trail, then the evaluation and linked simulated blocks. Repeat with detect mode if time permits.

The raw benchmark reports wall-clock throughput and peak process working set on Windows or peak resident set size on supported Unix hosts. It covers reading raw JSONL, detection, simulated response, evaluation and dashboard publication. Its background traffic is deliberately ordinary. This exercises throughput with sparse alerts and does not bound memory for candidate-heavy workloads.

Wazuh documents an agent, server, indexer and dashboard. OSSEC documents host log analysis, integrity checking and active response. This project focuses on a local replay and simulated decisions. [Wazuh components](https://documentation.wazuh.com/current/getting-started/components/index.html) · [OSSEC overview](https://www.ossec.net/docs/)
