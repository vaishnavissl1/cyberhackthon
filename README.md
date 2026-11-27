# HIDS/HIPS Event-Replay Agent

A standard-library Python agent for replayed host telemetry. It detects brute force followed by a success, services running from temporary directories, Office spawning a shell, and file changes against a hash baseline. It records simulated prevention decisions and generates an HTML case dashboard. The replay never executes commands or changes the host.

See the [implementation plan](HIDS_HIPS_Implementation_Plan.docx) for the original scope and work split.

## Run a case

Use Python 3.11 or newer from the repository root.

~~~powershell
python -m hids_agent demo --out runs/demo
python -m hids_agent demo --split holdout --out runs/holdout
~~~

These commands run the detector on a small scripted fixture with independent labels. Open `dashboard.html` in the run directory. For the full development and hidden test streams, see the next section.

## Test data: build, replay and score

No dataset is supplied for this problem, so we build our own development and hidden streams. `build_dataset` writes about 31,000 events over 6 hours on 8 hosts in real log layouts (Windows Security 4624/4625/4688/7045, Sysmon 1/11/23, ECS-style JSON, Linux sshd syslog and a FIM agent format). Attacks are hidden among normal activity and look-alikes: users who mistype then log in, users behind one shared address, internet scanners that never succeed, admin-installed services, an approved patch service in a temp folder, an approved macro, PID reuse, same-hash rewrites and approved file changes. Attack details are randomized per seed, and the hidden split adds 7 variants that never appear in development. The answer key goes to `labels.json` and never into the stream.

~~~powershell
python -m hids_agent.build_dataset --split dev --seed 1 --out runs/ds/dev-1
python -m hids_agent.build_dataset --split hidden --seed 101 --out runs/ds/hidden-101
python -m hids_agent.tune --events runs/ds/dev-1/events.jsonl --labels runs/ds/dev-1/labels.json --baseline runs/ds/dev-1/baseline.json --allowlist runs/ds/dev-1/allowlist.json --failures 4 5 6 8 --windows 120 300 600 --success-delays 300 600 --spray-users 4 5 6 --cooldowns 900 --min-severities medium high --config-out runs/ds/frozen.json --report-out runs/ds/sweep.json
python -m hids_agent.replay_stream runs/ds/hidden-101/events.jsonl --speed 600 | python -m hids_agent.agent --config runs/ds/frozen.json --baseline runs/ds/hidden-101/baseline.json --allowlist runs/ds/hidden-101/allowlist.json --labels runs/ds/hidden-101/labels.json --sweep runs/ds/sweep.json --out runs/ds/hidden-101/out
~~~

`replay_stream` plays the role of the replay script: it writes the file to stdout line by line (`--speed N` plays N event-seconds per real second; 0 sends at once). The tuner keeps settings with full recall, then the fewest false alarms, then the setting closest to the defaults. Breaking ties toward the most lenient setting over-fitted in testing (see below).

## First run on any new dataset

Check that the agent understands the stream before trusting any result:

~~~powershell
python -m hids_agent.inspect_stream dev_stream.jsonl
~~~

It lists unclassified event types, missing key fields per category and raw fields the agent does not read, and exits 0 only when everything is understood. Fix any gap without code changes through a `schema` section in a `--config` file, then rerun the check with `--config`:

~~~json
{"schema": {"field_aliases": {"user": ["acct"], "src_ip": ["origin"]},
            "category_map": {"logon_evt": "auth", "svc_create": "service"},
            "outcome_map": {"0": "failure", "1": "success"},
            "action_map": {"spawn": "start"}}}
~~~

For any other stream or the sample stream, use the same agent entry point:

~~~powershell
python -m hids_agent.replay_stream events.jsonl | python -m hids_agent.agent --labels labels.json --out runs/new
python -m hids_agent.agent --input data/sample_stream.jsonl --baseline data/baseline.example.json --allowlist data/allowlist.example.json --out runs/sample
~~~

Omit `--labels` when ground truth is unavailable. Pass `--mode detect` to keep requested decisions on the alert and leave the block journal empty. Supply a baseline and allow-list if the dataset has them. Inspect `summary.json` for unrecognized events and processing errors, then use `errors.log` to investigate failures. Record how service creation appears in the raw stream. If permitted, label sequences from the raw stream independently before evaluating.

## Generate, tune, and evaluate

~~~powershell
python -m hids_agent.gen_synthetic --split dev --mixed --out runs/dev-input
python -m hids_agent.gen_synthetic --split holdout --mixed --out runs/holdout-input
python -m hids_agent.tune --events runs/dev-input/events-mixed.jsonl --labels runs/dev-input/labels.json --baseline runs/dev-input/baseline.json --allowlist runs/dev-input/allowlist.json --failures 5 6 --windows 30 300 --success-delays 60 600 --spray-users 5 6 --cooldowns 900 --min-severities medium high --config-out runs/frozen.json --report-out runs/sweep.json
python -m hids_agent.agent --input runs/holdout-input/events-mixed.jsonl --baseline runs/holdout-input/baseline.json --allowlist runs/holdout-input/allowlist.json --labels runs/holdout-input/labels.json --config runs/frozen.json --sweep runs/sweep.json --out runs/frozen-holdout
python -m hids_agent.evaluate --out runs/frozen-holdout --labels runs/holdout-input/labels.json
~~~

The generator writes a raw stream, labels, baseline and allow-list. Its optional mixed stream adds alternate field styles, a duplicate, a malformed line and alternate timestamps. The holdout also contains out-of-order records. Tune on development only. A raw tuning sweep keeps full-recall trials, ranks by fewer false alarms and breaks ties using lower count and severity thresholds, longer correlation windows and a shorter grouping cooldown. With no full-recall setting the tuner exits with status 1 and writes no selected config.

Labels include `attack_id`, `type`, `host`, `start`, `end` and optional `event_ids`. `--stream` evaluates a saved run against embedded sequence annotations read with the same framing as detection. The detector drops label fields before running any rule. A scoped shared reference takes precedence. Time-only labels require a host, recognized rule and interval. Independent observations within one alert may match different sequences. Ambiguous observations are flagged. Recall counts distinct matched sequences. Precision counts matched alerts. With an undefined denominator, the metric is unavailable.

The labeled target is PASS when all sequences are found, there are at most two false alarms, and at least one active simulated decision is linked to a matching observation. `hids_agent.evaluate` exits 0 on PASS, 1 on FAIL or INCOMPLETE, and 2 on an input or usage error. Runs without labels show UNSCORED.

The `run` subcommand can also import a candidate JSONL handoff. The files in `examples/` give a three-event Office case, its candidate example and an independent label. Both entry points use the same scoring and response engine.

## Detection options

Use `--learn-baseline --save-baseline PATH` on a trusted replay to export a reusable baseline. JSONL follow mode and the TCP and HTTP adapters are available through `hids_agent.agent --help`. HTTP requires a Content-Length header.

By default, authentication alerts require a successful logon after failures. `bruteforce.alert_without_success` also enables alerts for a source that reaches `bruteforce.failures_without_success`, and for one account failing from at least `dist_sources` addresses. A subsequent successful logon can update that alert.

A password spray is confirmed after `bruteforce.spray_grace_s` (120 s) and only when at most `spray_max_success_ratio` (half) of the failing users then log in from that address. Users behind a shared address (NAT or proxy) who mistype and then log in are recorded as a watch note, not an alert. The other brute-force variants alert immediately.

Stream approval events default to watch records. Use `approvals.from_stream` and an explicit `approvals.trusted_approvers` list only with a trusted event source. The approver name is a field in the replay. Confirm the dataset's approval-event schema before enabling it.

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

## Evidence collected so far

| Test | Result |
| --- | --- |
| **Core target on 30 hidden streams** (`build_dataset --split hidden`, seeds 101 to 130), config tuned on development seed 1 only; stream 101 replayed through `replay_stream` into the agent | **30/30 PASS: 690/690 attack sequences found (23 variants, 30 of each), 0 false alarms in every stream, a linked block in every stream.** Detection latency median 6 s, 95th percentile 248 s (slow brute force and the spray grace period), maximum 348 s |
| Same 30 streams with the tuner's earlier tie-break (most lenient tied setting: 4 failures, 600 s window) | 20/30 PASS: every miss was a false alarm on a user who mistyped 4 times. This is why the tuner now prefers settings closest to the defaults |
| `gen_synthetic` scripted fixture, 25 seeds each of dev and holdout | 50/50 PASS. Its seeds change background timing only; the attacks are the same script each time |
| 278 real attack recordings from the public [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) set (37,364 Windows events; 2 files unreadable on Windows because antivirus locked them) | All 1,834 relevant events (logons 4624/4625/4771, process 4688 and Sysmon 1, service 7045, Sysmon file events) read with every key field; 0 processing errors; one alert, a real malware sample where a fake `WINWORD.exe` in `AppData` started `cmd` |
| Throughput on one Windows laptop | About 26,000 to 33,000 raw events/s from 100,000 to 400,000 events, linear |

The real recordings carry no labels, so they measure format coverage and noise, not recall. They contain no Office macro or temp-folder service examples.

Limits of this evidence: we wrote the dataset builder knowing the rules, so passing it shows the rules handle the attack variants we designed, in real log layouts, among realistic noise. It cannot show how the agent does on attack variants nobody thought of. The real-recording test and the tuner over-fit finding above are the checks against that bias.

## Verify and present

~~~powershell
python -m unittest discover -s tests -t .
python -m hids_agent.benchmark --raw --events 1000000
python -m hids_agent demo --live --out runs/presentation
~~~

### Demo walkthrough

During the demo, show a live alert and its block line. Open the finished dashboard and expand the Office alert to show its grouped evidence and score. Show the approved file change in the audit trail, then the evaluation and linked simulated blocks. Repeat with detect mode if time permits.

The raw benchmark reports wall-clock throughput and peak process working set on Windows or peak resident set size on supported Unix hosts. It covers reading raw JSONL, detection, simulated response, evaluation and dashboard publication. Its background traffic is deliberately ordinary. This exercises throughput with sparse alerts and does not bound memory for candidate-heavy workloads.

In one Windows run, 1,000,000 raw events took 151.829 s (6,586 events/s) and peaked at 131.1 MiB of process working set. The run matched 4/4 labeled sequences with 0 false alarms and 0 detection processing errors.

Wazuh documents an agent, server, indexer and dashboard. OSSEC documents host log analysis, integrity checking and active response. This project focuses on a local replay and simulated decisions. [Wazuh components](https://documentation.wazuh.com/current/getting-started/components/index.html) · [OSSEC overview](https://www.ossec.net/docs/)
