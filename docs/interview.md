# Mini SIEM interview notes

## Thirty-second pitch

“I extended a local SSH alerting demo into a small evidence-driven SIEM pipeline. It normalizes SSH and JSON events, deduplicates file replays with path/inode/offset/line identity, detects timed authentication patterns and selected web/network behavior, adds simulated local IOC context with an optional opt-in live provider, and links alerts to incident timelines. The score is an explainable triage heuristic. I can replay a fixed training dataset and show every raw event behind the alert.”

## Two-minute architecture explanation

`main.py` reads the file and checkpoints complete-line byte offsets in SQLite. On restart it replays stored normalized events through the rule state machine without writing old alerts. `parser.py` validates SSH or JSON lines and produces UTC events with source, IP, username, host, and supported web/network fields. `storage.py` persists raw and normalized data; file position plus line digest prevents replay duplicates while retaining identical lines at different offsets. `intel.py` checks a simulated local IOC fixture first, then optionally queries AbuseIPDB for public IPs only when explicitly configured. `detectors.py` evaluates authentication windows by IP and host, requires a matching account for success correlation when available, and checks web paths and distinct destination ports. Alerts link event IDs; incidents group alerts by IP and host within 30 minutes. `api.py` serves filters, timeline, status changes, and audit records on localhost, with an optional bearer token.

## Five-minute demonstration

1. On a fresh database, run `python src/main.py --once --log data/demo.jsonl --db data/alerts.db`. It produces four alerts. Run `python src/api.py` in another terminal and open http://127.0.0.1:5001. Show 14 events and three incidents.
2. Open incident #1. The five failures from `192.0.2.23` target `admin` on `demo-host`; the subsequent success matches both source and account. Show the six linked raw records and the simulated IOC label.
3. Explain heuristic priority: 55+15=70 for the burst, 80+15=95 for the success, incident maximum 95+5=100. This is **not** certainty of compromise. Set status to Investigating and show its audit record.
4. Open incident #2. Its web path resembles SQL injection and has HTTP 500, but neither proves database exploitation. Filter by `198.51.100.30` to compare the benign request. Open incident #3: five rejected connections to distinct ports on one destination indicate scanning behavior, not open ports.
5. Show `src/detectors.py`, `src/storage.py`, and `GET /api/incidents/1`. Replay the fixture; zero new alerts appear. Explain that a fresh live launch resumes its stored offset and rebuilds rule windows.

## Technical deep dive

- **Input and normalization:** `parse_line` rejects unknown types, naive JSON timestamps, invalid IPs, ports, HTTP statuses, and connection outcomes. SSH syslog has no timezone and is assumed UTC; JSON timestamps require an explicit offset. Raw lines remain stored.
- **Windows and identity:** `BruteForceDetector.add_event` uses deques keyed by IP and host. AUTH-002 requires the success username to match failed usernames if identities are present; if failure identities are absent, the alert explicitly says source-only correlation.
- **Evidence and incidents:** `alert_evidence` joins alerts to actual raw events. `incidents.entity_key` represents IP and host; 30-minute correlation uses ordered event time. Status changes are written to `incident_actions`.
- **Intelligence:** Local simulated data takes precedence. Optional AbuseIPDB queries only public addresses, with TTL cache, timeout, request budget, and explicit error status. No real provider response is part of the demonstration.
- **Recovery:** `ingest_offsets` stores file identity and position. On startup the detector rebuilds windows from `events`; an event-to-alert crash window remains because writes are not atomic.
- **Risk and false positives:** Rule base plus one IOC increment, capped at 100; incident max plus one success bonus. Analyst checks supporting evidence and can mark false positive. Neither web status nor rejected/accepted network traffic alone proves exploitation.
- **Security:** The development server binds localhost. Optional bearer authentication covers the API, rate limiting bounds writes, and status actions are audited. It is not a multi-user SOC deployment.

## Interview questions and grounded answers

1. **Why is this a SIEM rather than an SSH grep script?** It persists normalized events, evaluates multiple rules, enriches context and links evidence into incidents; it remains a small training SIEM.
2. **What is the ingest contract?** One SSH syslog line or one supported JSON object per line; malformed records are skipped by `parse_line`.
3. **How do you handle timezone?** JSON must contain an offset; syslog has none, so the demo assumes UTC and requires a supplied year for historical logs.
4. **Why keep raw events?** Analysts can verify the parser's interpretation and revisit false positives.
5. **What does the dedup hash cover?** For file ingestion, path, device/inode, offset and line digest. This preserves identical records at different positions and makes replays idempotent; stream ingestion falls back to source plus raw line.
6. **What happens at the fifth failure?** `BruteForceDetector` emits AUTH-001 once per continuous per-IP burst in a 60-second window.
7. **What if failures are one minute apart?** Old entries leave the deque; no threshold is met.
8. **Can a NAT cause a false alarm?** Yes. Several users behind one IP can share a window; investigate username and host evidence.
9. **Does AUTH-002 prove an account was compromised?** No. It correlates by IP and host, and requires the account to match when failure usernames are available. It still does not prove compromise.
10. **Why is web SQL injection detection limited?** A path regex sees a payload-shaped string, not execution, response, or database impact.
11. **Does NET-001 confirm open ports?** No. It counts attempted destination ports; the record may show attempted, accepted or rejected traffic, but does not establish an open service.
12. **What is the IOC source?** `data/demo_iocs.json`, a fabricated training fixture with a reserved documentation IP.
13. **Can you claim the IP is malicious?** No. Only that it matches a simulated local indicator; it has no real-world reputation meaning.
14. **What does cache reduce?** Repeated local lookups and optional public-IP AbuseIPDB requests within a process; the live cache has a 15-minute TTL and a 100-request process budget.
15. **Why no VirusTotal integration?** AbuseIPDB is optional and mocked in tests; a second provider would add quota, privacy and provenance complexity without strengthening the deterministic demo.
16. **What does a risk score of 100 mean?** Top triage priority under this heuristic, not a 100% compromise probability.
17. **How are alerts grouped?** Same IP and host and at most 30 minutes from the latest incident alert, assuming chronological input.
18. **Can the rule recover after restart?** Yes for the local model: file offsets persist, and stored events rebuild detector state on startup. Crash consistency is not fully atomic.
19. **How does the API prevent SQL injection?** Values use bound SQLite parameters; the overview table names come from a fixed tuple in source.
20. **Is the dashboard safe on the internet?** No. It binds localhost; an optional bearer token protects API calls, but there is no multi-user identity, TLS or production server.
21. **What tests show the pipeline is real?** `tests/test_pipeline.py`, `tests/test_investigation.py`, and `tests/test_extensions.py` cover parsing, rules, evidence, restart, rotation, mocked provider behavior, API token and audit.
22. **Why T1110 for the success alert?** It describes the preceding failure pattern; the success increases investigative priority but does not establish T1078 abuse.
23. **Why T1190 for a path match?** It is a hypothesis for potential public-app exploitation, explicitly unconfirmed without outcome telemetry.
24. **How would you scale?** Durable log offsets, queue-based ingestion, indexed event storage, persistent window state, partitioning, replay safety, and measured load tests.

## Honest weak points

- **Live provider unverified:** AbuseIPDB behavior is implemented from its documented API and mocked in tests. No real account or key was used; never claim a live lookup was demonstrated.
- **Crash consistency:** Offsets and detector windows recover, but event insertion and alert generation are separate commits. A crash between them can leave a missed alert.
- **Correlation scope:** Host and account checks reduce false matches; shared IPs, missing usernames, and ordered-input assumptions still matter.
- **Local safeguards only:** Optional shared bearer token, audit and rate limit do not constitute multi-user production access control.
- **Narrow telemetry:** HTTP 500 and rejected network connections add context but do not establish exploitation or endpoint outcome.

## Self-assessment

The earlier branch had 10 passing tests and a simulated-only provider. This extension has restart recovery, source/account/host boundaries, searchable network/web fields, optional mocked live lookups, audit, and local token protection. It is still an interview-scale system, around **7–8/10** for an entry-level demonstration, not a production SOC platform. The highest-value remaining change is transactional ingest so event, alert and offset updates cannot split across a crash.
