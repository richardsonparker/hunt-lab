Generates synthetic endpoint and firewall telemetry with a hidden ATT&CK attack chain, plus Splunk ingest configs and a full hunt walkthrough.

# Threat-Hunting Lab: Phishing

A reproducible threat-hunting lab. A MITRE ATT&CK-grounded attack chain is hidden
inside realistic benign telemetry for a fictional organization (Brightfield
Partners), spread across five Splunk sourcetypes. You hunt it from raw logs to a
defensible finding.

**Everything here is synthetic.** No real hosts, accounts, or organizations.
External IPs use IANA-reserved documentation ranges only (RFC 5737:
`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

## Quick start

Standard library only, no dependencies.

```bash
# Reproduce the exact incident described in the walkthrough
python generate.py --seed 93743820 --end-date 2026-08-19 --target-size 400MB

# Fast ~8MB sanity check
python generate.py --smoke-test
```

`--end-date` pins the 7-day window to 2026-08-13 → 2026-08-19, which puts the
attack on 2026-08-17 and matches every timestamp in the walkthrough. Omit it and
you get the same story on the 7 days ending yesterday.

- **Ingest into Splunk:** [docs/INGEST.md](docs/INGEST.md)
- **Start hunting, no spoilers:** [docs/BRIEF.md](docs/BRIEF.md)
- **Solution:** [solution/WALKTHROUGH.md](solution/WALKTHROUGH.md)

*You can Ingest the data to any siem, i chose splunk*

## The walkthrough

`solution/WALKTHROUGH.md` is the main deliverable: a hand-written, first-person
investigation with every SPL query in the order it was actually run by me. 
It documents the reasoning at each pivot, including corrections.

***Spoilers throughout — read `docs/BRIEF.md` and hunt first.***

## Data sources

| Sourcetype | Description |
|---|---|
| `fortigate` | Perimeter firewall traffic log (FortiOS-style key=value) |
| `sysmon:json` | Endpoint process, network, file, registry, and DNS telemetry |
| `wineventlog:security:json` | Windows authentication and process-creation audit events |
| `wineventlog:system:json` | Windows service and system events |
| `powershell:json` | PowerShell module and script-block logging |

*** All five are required. ***

## Repository structure

```
├── generate.py     # CLI: seeding, orchestration, streaming, validation
├── scenario/       # Org and environment generation, attack timeline, MITRE registry
├── generators/     # One module per telemetry source
├── validation/     # Process-tree integrity, auth correlation, leakage checks
├── splunk/         # props.conf / transforms.conf / inputs.conf / indexes.conf
├── docs/           # Learner brief and ingest instructions (regenerated every run)
└── solution/
    ├── WALKTHROUGH.md    # Hand-authored write-up, never touched by generate.py
    └── ground_truth.json # Machine-readable scenario facts (regenerated every run)
```

`dataset/` is gitignored — 300–500MB of generated telemetry, fully reproducible
from the seed above.

## Design notes

The attack is designed first, from documented ATT&CK behavior, before any log is
written. Identifiers (ProcessGuids, LogonIds, hashes, IPs) are generated once per
attack step and reused everywhere a real forensic relationship would appear, so
cross-source pivoting works the way it does in production instead of producing
anomalies with nothing behind them.

Four independent seeded RNG streams — environment, scenario, benign baseline,
false positives- keep the organization, attack chain, and noise separately
reproducible from a single `--seed`.

* There is one attack template, validated end to end. The seed determines the organization, hosts, accounts, timing, and infrastructure - but not the attack itself, so every run tells the same story. More attack chains are planned.
