# Mini SIEM interview notes

## Thirty-second pitch

“I extended a local SSH alerting demo into a small evidence-driven SIEM pipeline. It normalizes SSH and JSON events, deduplicates exact replays in SQLite, detects timed authentication patterns and selected web/network behavior, adds clearly simulated local IOC context, and links alerts to incident timelines. The score is an explainable triage heuristic. I can replay a fixed training dataset and show every raw event behind the alert.”

## Two-minute architecture explanation

`main.py` reads lines from a file or tails one. `parser.py` accepts a narrow SSH syslog subset or JSON-line events and normalizes timestamps to UTC. `storage.py` inserts each raw and normalized record into `events`, using a source-plus-raw fingerprint to avoid replay duplication. `detectors.py` maintains per-IP windows for authentication failures and distinct network ports, plus a decoded web-path pattern check. `intel.py` validates IPs and looks them up in a local, explicitly simulated indicator fixture. `main.py` links detection evidence IDs, while `storage.py` persists alerts and groups them by source IP and a 30-minute incident window. `api.py` serves read-only evidence endpoints and one status-update endpoint to the localhost dashboard. Every layer is small enough to inspect during an interview; stateful rule windows are in memory and therefore restart-bound.

## Five-minute demonstration

1. In terminal A, run `python src/main.py --once --log data/demo.jsonl --db data/alerts.db`. An empty database reports three alerts. Existing demo records are idempotent; use a fresh temporary `--db` plus matching `SIEM_DB` if repeating the first-run moment.
2. In terminal B, run `python src/api.py`. Open http://127.0.0.1:5001. Show nine events, three alerts, two incidents, and six matching event lookups. The IOC is simulated.
3. Open incident #1. Explain five failures from `192.0.2.23` in 17 seconds and a subsequent success. Point to the six linked raw events and AUTH-001/AUTH-002, not just a chart.
4. Show the heuristic: 55+15=70 for the burst; 80+15=95 for the success; incident maximum 95+5=100. Do not call 100 a certainty of compromise. Set status to Investigating.
5. Open incident #2 and distinguish suspicious web-path pattern from proven exploitation. Filter events by `198.51.100.30` to show the benign request too. Open `src/detectors.py`, `src/intel.py`, and `GET /api/incidents/1` for implementation evidence. Rerun ingestion to show zero additional alerts.

## Technical deep dive

- **Input and validation:** `parse_line` rejects unknown JSON event types, naive timestamps, invalid IPs and ports. `parse_syslog_line` accepts traditional `sshd` failed/accepted authentication lines. Unsupported records do not crash the batch.
- **Normalization:** Both sources become dicts with `timestamp`, `type`, `ip`, `source`, `raw_event`, user and host where available. UTC timestamps enable window comparison; the original line remains for auditability.
- **Detection and thresholds:** `BruteForceDetector.add_event` uses a `deque` keyed by IP, discards failures older than 60 seconds, and fires on the fifth. The active set prevents repeated alerts during a continuing burst. Success checks recent failures from that IP. Port detection counts distinct destination ports. A web pattern is only a suspicious request indicator.
- **Correlation:** `Storage.add_detection` links evidence in `alert_evidence`; it associates alerts from the same IP with the latest incident inside 30 minutes. An alert is a rule result; an incident is a related collection of alerts and evidence.
- **Intelligence:** `LocalIntel.lookup` validates IPs, returns `match`, `not_found`, `invalid`, or `unavailable`, and caches in memory. The fixture is simulated; no provider failures or live data occur because there is no external provider.
- **Risk:** The base rule score plus one local-match increment is capped at 100. The incident takes the maximum alert score, adding five for a success-after-failures signal. This avoids summing repeated failures into an unbounded score.
- **False positives:** An analyst can mark false positive, inspect raw evidence, and check account/session context. Rule thresholds are configurable in code. The current system does not learn baselines or enforce suppression per user.
- **Failure and production:** Malformed lines are skipped. If the local IOC file cannot load, startup fails; a future external provider should be optional and return explicit error/staleness states. Production needs auth, audit trails, durable detector state, rotation handling, queueing, schema migrations, rate limits, secure deployment and performance tests.

## Interview questions and grounded answers

1. **Why is this a SIEM rather than an SSH grep script?** It persists normalized events, evaluates multiple rules, enriches context and links evidence into incidents; it remains a small training SIEM.
2. **What is the ingest contract?** One SSH syslog line or one supported JSON object per line; malformed records are skipped by `parse_line`.
3. **How do you handle timezone?** JSON must contain an offset; syslog has none, so the demo assumes UTC and requires a supplied year for historical logs.
4. **Why keep raw events?** Analysts can verify the parser's interpretation and revisit false positives.
5. **What does the dedup hash cover?** Source plus exact raw line. It makes identical replays idempotent but may collapse genuinely repeated identical records.
6. **What happens at the fifth failure?** `BruteForceDetector` emits AUTH-001 once per continuous per-IP burst in a 60-second window.
7. **What if failures are one minute apart?** Old entries leave the deque; no threshold is met.
8. **Can a NAT cause a false alarm?** Yes. Several users behind one IP can share a window; investigate username and host evidence.
9. **Does AUTH-002 prove an account was compromised?** No. It correlates by source IP; the successful identity can differ from failed identities.
10. **Why is web SQL injection detection limited?** A path regex sees a payload-shaped string, not execution, response, or database impact.
11. **Does NET-001 confirm open ports?** No. It counts attempted destination ports; there is no connection outcome field.
12. **What is the IOC source?** `data/demo_iocs.json`, a fabricated training fixture with a reserved documentation IP.
13. **Can you claim the IP is malicious?** No. Only that it matches a simulated local indicator; it has no real-world reputation meaning.
14. **What does cache reduce?** Repeated local lookups within a processing batch; it does not persist or solve external API quotas.
15. **Why no VirusTotal integration?** A real integration needs credentials, rate and privacy controls, error handling and a robust demo fallback; reliability came first.
16. **What does a risk score of 100 mean?** Top triage priority under this heuristic, not a 100% compromise probability.
17. **How are alerts grouped?** Same source IP and at most 30 minutes from the latest incident alert; unrelated IPs remain separate.
18. **Can the rule recover after restart?** No. SQLite events persist but in-memory detection deques do not; durable offsets/state would be a next step.
19. **How does the API prevent SQL injection?** Values use bound SQLite parameters; the overview table names come from a fixed tuple in source.
20. **Is the dashboard safe on the internet?** No. It binds localhost and lacks authentication/CSRF protection for status updates.
21. **What tests show the pipeline is real?** `tests/test_pipeline.py` replays SSH; `tests/test_investigation.py` checks validation, positive/negative detections, dedup, linked evidence, scores and API status changes.
22. **Why T1110 for the success alert?** It describes the preceding failure pattern; the success increases investigative priority but does not establish T1078 abuse.
23. **Why T1190 for a path match?** It is a hypothesis for potential public-app exploitation, explicitly unconfirmed without outcome telemetry.
24. **How would you scale?** Durable log offsets, queue-based ingestion, indexed event storage, persistent window state, partitioning, replay safety, and measured load tests.

## Honest weak points

- **No live intelligence:** The fixture is excellent for deterministic explanation but cannot provide real reputation. Say exactly where a provider with timeout/cache/provenance would plug in.
- **Coarse identity correlation:** Per-IP grouping can mix users behind NAT. Show raw usernames and propose IP+account/host graph correlation after telemetry validation.
- **Restart and rotation:** State and offsets are not durable. Explain that a real pipeline would checkpoint offsets and reconstruct or persist windows.
- **Local-only access:** There is no auth or audit trail. Never present the dashboard as deployable to a SOC network.
- **Narrow telemetry:** No confirmed exploit or connection outcomes. Explain what extra response, endpoint, and network flow fields would be needed.

## Self-assessment based on tested behavior

| Dimension | Before | After | Evidence and constraint |
| --- | ---: | ---: | --- |
| Cybersecurity depth | 3 | 6 | SSH burst extended with correlation, web and port patterns; narrow telemetry |
| Detection engineering | 3 | 6 | Deterministic windows and tests; source-IP grouping |
| Threat intelligence | 1 | 4 | Simulated local IOC only, no live provider |
| Investigation | 1 | 6 | Persisted evidence timeline and status; no notes/audit |
| Backend | 4 | 6 | SQLite events/alerts/incidents and API; no migrations |
| Testing | 4 | 6 | Ten local tests; no load or browser automation |
| Dashboard/demo | 3 | 7 | Live-data console and repeatable fixture |
| Originality | 2 | 5 | Coherent compact SIEM; standard rules |
| Explainability | 4 | 8 | Evidence, explicit heuristic, limitations |
| Overall interview value | 3 | 7 | Defensible demo, provided limitations are stated |

A typical student mini SIEM often stops at alert counts; this one exposes the raw records and causal path. The memorable part is a repeatable failure-to-success incident with visible evidence and clearly labeled synthetic intelligence. Confidence would fall if one called the fixture a live feed, claimed the web request succeeded, or hid the restart limitation. For an internship, this is a useful practical discussion piece, not proof of production readiness. Potential after durable state, stronger correlation, and a real optional provider: **8/10**. Highest marginal next improvement: persistent processing offsets and window reconstruction so replay/restart behavior is reliable in live use.
