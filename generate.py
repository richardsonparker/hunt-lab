#!/usr/bin/env python3
"""
CLI entry point: seeds the run, builds the scenario, streams the dataset,
validates it, and writes the Splunk config, docs, and solution files.

Usage:
    python generate.py
    python generate.py --target-size 900MB --seed 73918422
    python generate.py --target-size 10MB --smoke-test
"""

import argparse
import datetime
import json
import os
import random
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scenario import environment as env_mod
from scenario import templates as templates_mod
from scenario import timeline as timeline_mod
from scenario import false_positives as fp_mod
from scenario.identity import SeqCounters
from scenario.timeutil import get_tzinfo
from generators import sysmon, win_security, win_system, powershell, fortigate
from validation import validators

SOURCES = ["fortigate", "sysmon", "windows_security", "windows_system", "powershell"]
JSONL_SOURCES = {"sysmon", "windows_security", "windows_system", "powershell"}
FILE_NAMES = {
    "fortigate": "fortigate.log",
    "sysmon": "sysmon.jsonl",
    "windows_security": "windows_security.jsonl",
    "windows_system": "windows_system.jsonl",
    "powershell": "powershell.jsonl",
}
GENERATOR_MODULE = {
    "fortigate": fortigate,
    "sysmon": sysmon,
    "windows_security": win_security,
    "windows_system": win_system,
    "powershell": powershell,
}
# Rough realistic proportion of total dataset bytes per source.
SIZE_WEIGHTS = {"fortigate": 0.45, "sysmon": 0.30, "windows_security": 0.15, "powershell": 0.05, "windows_system": 0.05}
LICENSE_WARN_MB = 450
HARD_MAX_MB = 2048


def parse_size_mb(text):
    text = text.strip().upper()
    if text.endswith("GB"):
        return float(text[:-2]) * 1024
    if text.endswith("MB"):
        return float(text[:-2])
    return float(text)


def parse_args():
    p = argparse.ArgumentParser(description="Generate a synthetic Splunk threat-hunting lab dataset.")
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--target-size", type=str, default="400MB")
    p.add_argument("--smoke-test", action="store_true")
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--end-date", type=str, default=None, help="YYYY-MM-DD, defaults to the day before generation date")
    p.add_argument("--timezone", type=str, default="Asia/Jerusalem")
    p.add_argument("--workstations", type=int, default=6)
    p.add_argument("--out", type=str, default=os.path.dirname(os.path.abspath(__file__)))
    return p.parse_args()


def day_index_for(t, window_start, num_days):
    """Clamp to [0, num_days-1] so an attack chain that runs past midnight
    near the end of the window still lands in the dataset instead of being
    silently dropped by day-bucketed writing."""
    idx = int((t - window_start).total_seconds() // 86400)
    return max(0, min(num_days - 1, idx))


def day_weight(day_start):
    return 0.35 if day_start.weekday() >= 5 else 1.0


def measure_sample_bytes(source, seed, environment, sample_day, identity):
    """Bytes per *iteration* of generate_benign's `count` parameter -- not
    bytes per emitted line. Some sources emit more than one line per
    iteration (e.g. a 4624 logon paired with its 4634 logoff), so sizing the
    real run's iteration count on a per-line average would overshoot the
    target by that multiplier."""
    rng_sample = random.Random(seed + 999)
    mod = GENERATOR_MODULE[source]
    sample_iterations = 25
    total = 0
    for src, t, rec in mod.generate_benign(seed, environment, rng_sample, sample_day, sample_iterations, identity):
        if src != source:
            continue
        line = rec if isinstance(rec, str) else json.dumps(rec, ensure_ascii=False)
        total += len(line.encode("utf-8")) + 1
    return max(1, total // sample_iterations)


def write_record(f, source, rec):
    if source in JSONL_SOURCES:
        f.write(json.dumps(rec, ensure_ascii=False))
        f.write("\n")
    else:
        f.write(rec)
        f.write("\n")


def main():
    args = parse_args()
    generation_dt = datetime.datetime.now()

    seed = args.seed
    if seed is None:
        seed = secrets.randbelow(99_999_999) + 1
        print("Selected seed: {}".format(seed))

    target_mb = 8.0 if args.smoke_test else parse_size_mb(args.target_size)
    if target_mb > HARD_MAX_MB:
        print("ERROR: --target-size exceeds the {} MB hard maximum.".format(HARD_MAX_MB))
        sys.exit(1)
    split_output = target_mb > LICENSE_WARN_MB
    if split_output:
        print("WARNING: target size {:.0f} MB exceeds the {} MB/day Splunk Free/Enterprise license cap.".format(target_mb, LICENSE_WARN_MB))
        print("         Output will be split into per-day files for multi-day ingestion.")

    tz = get_tzinfo(args.timezone)

    if args.end_date:
        end_date = datetime.datetime.strptime(args.end_date, "%Y-%m-%d").replace(tzinfo=tz)
    else:
        end_date = datetime.datetime.now(tz).replace(hour=0, minute=0, second=0, microsecond=0) - datetime.timedelta(days=1)
    num_days = args.days
    window_start = (end_date - datetime.timedelta(days=num_days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    window_end = end_date.replace(hour=23, minute=59, second=59, microsecond=999000)

    rng_env = random.Random(seed)
    rng_scenario = random.Random(seed + 1)
    rng_benign = random.Random(seed + 2)
    rng_fp = random.Random(seed + 3)

    environment = env_mod.build_environment(rng_env, num_workstations=args.workstations)
    template = templates_mod.select_template(seed)
    identity_seq = SeqCounters()

    attack_day_index = rng_scenario.choice([min(3, num_days - 1), min(4, num_days - 1)])
    scenario, attack_events = timeline_mod.build_scenario(
        template, environment, rng_scenario, seed, window_start, window_end, args.timezone, attack_day_index,
        identity_seq,
    )
    fp_events, fp_descriptions = fp_mod.build_false_positives(
        seed, environment, rng_fp, window_start, num_days, attack_day_index, identity_seq,
    )

    out_root = args.out
    dataset_dir = os.path.join(out_root, "dataset")
    solution_dir = os.path.join(out_root, "solution")
    splunk_dir = os.path.join(out_root, "splunk")
    docs_dir = os.path.join(out_root, "docs")
    for d in (dataset_dir, solution_dir, splunk_dir, docs_dir):
        os.makedirs(d, exist_ok=True)

    # Clear stale output from a previous run (e.g. switching target sizes
    # across the license-split threshold would otherwise leave orphaned
    # files that neither this run nor the validators know about).
    for fname in os.listdir(dataset_dir):
        os.remove(os.path.join(dataset_dir, fname))

    sample_day = window_start
    target_bytes_total = target_mb * 1024 * 1024
    per_source_target_bytes = {s: target_bytes_total * SIZE_WEIGHTS[s] for s in SOURCES}
    per_source_avg_bytes = {s: measure_sample_bytes(s, seed, environment, sample_day, identity_seq) for s in SOURCES}
    per_source_total_count = {
        s: max(num_days, int(per_source_target_bytes[s] / per_source_avg_bytes[s])) for s in SOURCES
    }

    weights = [day_weight(window_start + datetime.timedelta(days=d)) for d in range(num_days)]
    weight_sum = sum(weights)

    event_counts = {s: 0 for s in SOURCES}
    file_handles = {}

    def open_files_for_day(day_index):
        handles = {}
        for s in SOURCES:
            fname = FILE_NAMES[s]
            if split_output:
                base, ext = os.path.splitext(fname)
                fname = "{}_day{}{}".format(base, day_index + 1, ext)
            handles[s] = open(os.path.join(dataset_dir, fname), "w", encoding="utf-8", newline="\n")
        return handles

    if not split_output:
        file_handles = {s: open(os.path.join(dataset_dir, FILE_NAMES[s]), "w", encoding="utf-8", newline="\n") for s in SOURCES}

    for day_index in range(num_days):
        day_start = window_start + datetime.timedelta(days=day_index)
        day_end = day_start + datetime.timedelta(days=1)
        scale = weights[day_index] / weight_sum

        if split_output:
            file_handles = open_files_for_day(day_index)

        day_buckets = {s: [] for s in SOURCES}

        for s in SOURCES:
            count = max(1, round(per_source_total_count[s] * scale))
            mod = GENERATOR_MODULE[s]
            for src, t, rec in mod.generate_benign(seed, environment, rng_benign, day_start, count, identity_seq):
                day_buckets[src].append((t, rec))

        for src, t, rec in attack_events:
            if day_index_for(t, window_start, num_days) == day_index:
                day_buckets[src].append((t, rec))
        for src, t, rec in fp_events:
            if day_index_for(t, window_start, num_days) == day_index:
                day_buckets[src].append((t, rec))

        for s in SOURCES:
            day_buckets[s].sort(key=lambda x: x[0])
            for t, rec in day_buckets[s]:
                write_record(file_handles[s], s, rec)
                event_counts[s] += 1

        if split_output:
            for f in file_handles.values():
                f.close()

    if not split_output:
        for f in file_handles.values():
            f.close()

    # -- Splunk configs --
    write_splunk_configs(splunk_dir, split_output, num_days)

    # -- docs --
    write_brief(docs_dir, environment, scenario)
    write_ingest(docs_dir, split_output, num_days)

    # -- solution --
    # solution/WALKTHROUGH.md is a hand-authored investigation write-up and
    # is never touched by generation. Only the machine-readable ground truth
    # is (re)written here.
    generation_ts = generation_dt.strftime("%Y-%m-%d %H:%M:%S")
    ground_truth = dict(scenario)
    ground_truth["false_positives"] = fp_descriptions
    ground_truth["generation_timestamp"] = generation_ts
    ground_truth["event_counts"] = event_counts
    with open(os.path.join(solution_dir, "ground_truth.json"), "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2, ensure_ascii=False)

    # -- validation --
    results = validators.run_all(scenario, environment, dataset_dir, window_start, window_end, seed)
    failed = [r for r in results if not r[1]]

    total_bytes = sum(
        os.path.getsize(os.path.join(dataset_dir, f)) for f in os.listdir(dataset_dir)
    )

    print("")
    if failed:
        print("Generation FAILED validation:")
        for name, ok, detail in results:
            status = "PASS" if ok else "FAIL"
            print("  {:<28} {:<4} {}".format(name, status, detail))
        sys.exit(1)

    print_summary(seed, window_start, window_end, args.timezone, dataset_dir, event_counts, results, split_output)


def write_splunk_configs(splunk_dir, split_output, num_days):
    props = """[fortigate]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\\r\\n]+)
# date= and time= are adjacent literal key=value pairs on every line; anchor
# on date= and consume the literal "time=" between the two values.
TIME_PREFIX = date=
TIME_FORMAT = %Y-%m-%d time=%H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD = 30
TRUNCATE = 0
KV_MODE = auto
TRANSFORMS-host_fortigate = set_host_fortigate

[sysmon:json]
KV_MODE = json
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\\r\\n]+)
TIME_PREFIX = "time":\\s*"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%z
MAX_TIMESTAMP_LOOKAHEAD = 40
TRUNCATE = 0
TRANSFORMS-host = set_host_json

[wineventlog:security:json]
KV_MODE = json
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\\r\\n]+)
TIME_PREFIX = "time":\\s*"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%z
MAX_TIMESTAMP_LOOKAHEAD = 40
TRUNCATE = 0
TRANSFORMS-host = set_host_json

[wineventlog:system:json]
KV_MODE = json
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\\r\\n]+)
TIME_PREFIX = "time":\\s*"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%z
MAX_TIMESTAMP_LOOKAHEAD = 40
TRUNCATE = 0
TRANSFORMS-host = set_host_json

[powershell:json]
KV_MODE = json
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\\r\\n]+)
TIME_PREFIX = "time":\\s*"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%z
MAX_TIMESTAMP_LOOKAHEAD = 40
TRUNCATE = 0
TRANSFORMS-host = set_host_json
"""
    transforms = """# Sets Splunk's metadata host field from the per-record "host" JSON key.
# Necessary because each JSONL file interleaves events from every host in
# the environment -- a single inputs.conf host= stanza cannot distinguish
# them, so host is derived from event content instead at index time.
[set_host_json]
REGEX = "host":\\s*"([^"]+)"
FORMAT = host::$1
DEST_KEY = MetaData:Host

# FortiGate host is the sending appliance itself (devname), not the
# src/dst IPs inside the traffic record -- consistent with real syslog.
[set_host_fortigate]
REGEX = devname=(\\S+)
FORMAT = host::$1
DEST_KEY = MetaData:Host
"""
    if split_output:
        inputs_stanzas = []
        for base, sourcetype in (
            ("fortigate", "fortigate"), ("sysmon", "sysmon:json"), ("windows_security", "wineventlog:security:json"),
            ("windows_system", "wineventlog:system:json"), ("powershell", "powershell:json"),
        ):
            ext = "log" if base == "fortigate" else "jsonl"
            for d in range(1, num_days + 1):
                inputs_stanzas.append(
                    "[monitor://$SPLUNK_HOME/etc/apps/hunt_lab/dataset/{0}_day{1}.{2}]\nsourcetype = {3}\nindex = hunt_lab\ndisabled = false\n".format(
                        base, d, ext, sourcetype))
        inputs = "\n".join(inputs_stanzas)
    else:
        inputs = """[monitor://$SPLUNK_HOME/etc/apps/hunt_lab/dataset/fortigate.log]
sourcetype = fortigate
index = hunt_lab
disabled = false

[monitor://$SPLUNK_HOME/etc/apps/hunt_lab/dataset/sysmon.jsonl]
sourcetype = sysmon:json
index = hunt_lab
disabled = false

[monitor://$SPLUNK_HOME/etc/apps/hunt_lab/dataset/windows_security.jsonl]
sourcetype = wineventlog:security:json
index = hunt_lab
disabled = false

[monitor://$SPLUNK_HOME/etc/apps/hunt_lab/dataset/windows_system.jsonl]
sourcetype = wineventlog:system:json
index = hunt_lab
disabled = false

[monitor://$SPLUNK_HOME/etc/apps/hunt_lab/dataset/powershell.jsonl]
sourcetype = powershell:json
index = hunt_lab
disabled = false
"""
    indexes = """[hunt_lab]
homePath = $SPLUNK_DB/hunt_lab/db
coldPath = $SPLUNK_DB/hunt_lab/colddb
thawedPath = $SPLUNK_DB/hunt_lab/thaweddb
maxTotalDataSizeMB = 5000
"""
    with open(os.path.join(splunk_dir, "props.conf"), "w", encoding="utf-8") as f:
        f.write(props)
    with open(os.path.join(splunk_dir, "transforms.conf"), "w", encoding="utf-8") as f:
        f.write(transforms)
    with open(os.path.join(splunk_dir, "inputs.conf"), "w", encoding="utf-8") as f:
        f.write(inputs)
    with open(os.path.join(splunk_dir, "indexes.conf"), "w", encoding="utf-8") as f:
        f.write(indexes)


def write_brief(docs_dir, environment, scenario):
    lines = []
    lines.append("# Threat Hunt Brief")
    lines.append("")
    lines.append(
        "Suspicious activity may have occurred in this environment. Investigate the available telemetry, "
        "determine what happened, identify affected systems and accounts, reconstruct the timeline, and "
        "map confirmed behaviors to MITRE ATT&CK."
    )
    lines.append("")
    lines.append("## Organization: {}".format(scenario["organization"]))
    lines.append("")
    lines.append("Domain: `{}`".format(scenario["domain"]))
    lines.append("")
    lines.append("| Hostname | IP | Role | OS |")
    lines.append("|---|---|---|---|")
    for h in environment["hosts"]:
        lines.append("| {} | {} | {} | {} |".format(h["hostname"], h["ip"], h["role"].replace("_", " "), h["os"]))
    lines.append("")
    lines.append("## Data sources")
    lines.append("")
    lines.append("| Sourcetype | Index | Description |")
    lines.append("|---|---|---|")
    lines.append("| `fortigate` | hunt_lab | FortiGate perimeter firewall traffic log |")
    lines.append("| `sysmon:json` | hunt_lab | Endpoint process, network, file, registry, DNS telemetry |")
    lines.append("| `wineventlog:security:json` | hunt_lab | Windows authentication and process-creation audit events |")
    lines.append("| `wineventlog:system:json` | hunt_lab | Windows service and system events |")
    lines.append("| `powershell:json` | hunt_lab | PowerShell module and script block logging |")
    lines.append("")
    lines.append("See [INGEST.md](INGEST.md) for setup instructions.")
    lines.append("")
    lines.append("## Verification searches")
    lines.append("")
    lines.append("```spl")
    lines.append("index=hunt_lab | stats count by sourcetype")
    lines.append("```")
    lines.append("```spl")
    lines.append("index=hunt_lab | timechart span=1h count by sourcetype")
    lines.append("```")
    lines.append("")
    lines.append("If you get stuck, `solution/WALKTHROUGH.md` is available as a reference -- try the hunt first.")
    lines.append("")
    with open(os.path.join(docs_dir, "BRIEF.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def write_ingest(docs_dir, split_output, num_days):
    lines = []
    lines.append("# INGEST.md -- Splunk Setup")
    lines.append("")
    lines.append("## 0. Generate the dataset")
    lines.append("")
    lines.append(
        "If `dataset/` doesn't exist yet (it isn't committed to source control -- "
        "see `.gitignore`), generate it first. There is currently **one** validated "
        "attack template, so every seed produces the same story shape (phishing -> "
        "C2 -> SMB lateral movement) -- what changes per seed is the specific "
        "organization, hosts, accounts, and exact evidence, not the attack pattern."
    )
    lines.append("")
    lines.append(
        "**Use this exact command** to reproduce the incident documented in "
        "`solution/WALKTHROUGH.md`, with matching hostnames, timestamps, and event details:"
    )
    lines.append("")
    lines.append("```bash")
    lines.append("python generate.py --seed 93743820 --end-date 2026-08-19 --target-size 400MB")
    lines.append("```")
    lines.append("")
    lines.append(
        "`--end-date` pins the 7-day window to 2026-08-13 -> 2026-08-19 so the attack "
        "lands on 2026-08-17 -- omit it and the same seed still produces the same "
        "organization and attack chain, just on a different (also valid) calendar window "
        "that won't line up with the specific dates in the walkthrough."
    )
    lines.append("")
    lines.append(
        "A **different seed** (e.g. `--seed 4`) generates a fresh instance of this same "
        "template -- a different fictional company, different hostnames and accounts, "
        "different exact timestamps and file sizes -- but `solution/WALKTHROUGH.md` won't "
        "match it line-for-line anymore, since that document was written against seed "
        "`93743820` specifically. Use a different seed to practice the hunt cold, without "
        "the answer key lining up; use `93743820` to follow along with the walkthrough."
    )
    lines.append("")
    lines.append("```bash")
    lines.append("python generate.py --smoke-test   # fast ~8MB run to sanity-check the pipeline (any seed)")
    lines.append("```")
    lines.append("")
    lines.append("## 1. Create the index")
    lines.append("")
    lines.append("Copy `splunk/indexes.conf`, `splunk/props.conf`, and `splunk/transforms.conf` into an app directory, e.g.:")
    lines.append("")
    lines.append("```bash")
    lines.append("mkdir -p $SPLUNK_HOME/etc/apps/hunt_lab/{default,dataset}")
    lines.append("cp splunk/*.conf $SPLUNK_HOME/etc/apps/hunt_lab/default/")
    lines.append("cp dataset/* $SPLUNK_HOME/etc/apps/hunt_lab/dataset/")
    lines.append("$SPLUNK_HOME/bin/splunk restart")
    lines.append("```")
    lines.append("")
    lines.append("## 2. Load the data")
    lines.append("")
    lines.append("Restarting Splunk with `inputs.conf` in place monitors the files automatically. For a one-time")
    lines.append("load instead of continuous monitoring, use `splunk add oneshot` per file:")
    lines.append("")
    lines.append("```bash")
    lines.append("$SPLUNK_HOME/bin/splunk add oneshot dataset/fortigate.log -index hunt_lab -sourcetype fortigate")
    lines.append("$SPLUNK_HOME/bin/splunk add oneshot dataset/sysmon.jsonl -index hunt_lab -sourcetype sysmon:json")
    lines.append("$SPLUNK_HOME/bin/splunk add oneshot dataset/windows_security.jsonl -index hunt_lab -sourcetype wineventlog:security:json")
    lines.append("$SPLUNK_HOME/bin/splunk add oneshot dataset/windows_system.jsonl -index hunt_lab -sourcetype wineventlog:system:json")
    lines.append("$SPLUNK_HOME/bin/splunk add oneshot dataset/powershell.jsonl -index hunt_lab -sourcetype powershell:json")
    lines.append("```")
    if split_output:
        lines.append("")
        lines.append(
            "The dataset exceeds the 450 MB/day guidance and was split into per-day files "
            "(`*_day1` .. `*_day{}`). Ingest one day at a time across multiple calendar days if you are on".format(num_days)
        )
        lines.append("Splunk Free or a post-trial Enterprise license (500 MB/day cap).")
    lines.append("")
    lines.append("## 3. Verify")
    lines.append("")
    lines.append("```spl")
    lines.append("index=hunt_lab | stats count by sourcetype")
    lines.append("```")
    lines.append("```spl")
    lines.append("index=hunt_lab | timechart span=1h count by sourcetype")
    lines.append("```")
    lines.append("```spl")
    lines.append("index=hunt_lab sourcetype=sysmon:json | stats count by EventCode")
    lines.append("```")
    lines.append("")
    lines.append("## 4. Cleaning up / switching to a different seed")
    lines.append("")
    lines.append(
        "Every run of `generate.py` deletes and rewrites everything under `dataset/` for you "
        "automatically -- you never need to clean that folder by hand before regenerating."
    )
    lines.append("")
    lines.append(
        "There are two separate things people mean by \"delete the dataset,\" and they need "
        "different commands:"
    )
    lines.append("")
    lines.append("**A. Delete the local `dataset/` folder on disk** -- e.g. to tidy up before")
    lines.append("committing this project to git (`dataset/` is already covered by `.gitignore`,")
    lines.append("so this is just housekeeping, not required for git safety):")
    lines.append("")
    lines.append("```powershell")
    lines.append("cd path\\to\\this\\project      # make sure you are NOT already inside dataset\\")
    lines.append("Remove-Item -Recurse -Force .\\dataset")
    lines.append("```")
    lines.append("")
    lines.append(
        "If that fails with an error, you are almost certainly still `cd`'d inside `dataset\\` "
        "itself -- Windows refuses to delete a folder that is your shell's current location. "
        "Run `cd ..` first, then retry."
    )
    lines.append("")
    lines.append("**B. Delete the data already loaded INTO Splunk's `hunt_lab` index** -- needed")
    lines.append("when you regenerate (same seed with a new date, or a genuinely different seed)")
    lines.append("and don't want the new incident mixed together with the old one inside Splunk.")
    lines.append("This is separate from (A) and is **irreversible**. Splunk must be stopped first:")
    lines.append("")
    lines.append("```powershell")
    lines.append('& "$SPLUNK_HOME\\bin\\splunk.exe" stop')
    lines.append('& "$SPLUNK_HOME\\bin\\splunk.exe" clean eventdata -index hunt_lab')
    lines.append('& "$SPLUNK_HOME\\bin\\splunk.exe" start')
    lines.append("```")
    lines.append("")
    lines.append(
        "Example end-to-end workflow for regenerating the documented incident from scratch "
        "(e.g. after the calendar window drifted, or you just want a clean reload):"
    )
    lines.append("")
    lines.append("```powershell")
    lines.append("python generate.py --seed 93743820 --end-date 2026-08-19 --target-size 400MB")
    lines.append('& "$SPLUNK_HOME\\bin\\splunk.exe" stop')
    lines.append('& "$SPLUNK_HOME\\bin\\splunk.exe" clean eventdata -index hunt_lab')
    lines.append('& "$SPLUNK_HOME\\bin\\splunk.exe" start')
    lines.append("cd dataset")
    lines.append('& "$SPLUNK_HOME\\bin\\splunk.exe" add oneshot .\\fortigate.log -index hunt_lab -sourcetype fortigate')
    lines.append("# ...repeat the oneshot command for the other four dataset files (see Section 2)")
    lines.append("```")
    lines.append("")
    lines.append(
        "To instead try a **different** incident (same attack template, different specific "
        "details, no matching walkthrough), swap `--seed 93743820 --end-date 2026-08-19` for "
        "any other seed, e.g. `--seed 4`, and drop `--end-date` -- everything else in the "
        "workflow above is identical."
    )
    lines.append("")
    lines.append(
        "If you'd rather keep multiple incidents queryable side by side instead of replacing "
        "one with another, skip the `clean eventdata` step and instead add a second index "
        "stanza to `splunk/indexes.conf` (e.g. `[hunt_lab_2]`), redeploy it alongside the "
        "existing config, restart Splunk, and point your `oneshot` commands at `-index hunt_lab_2`."
    )
    lines.append("")
    lines.append("## 5. Porting to a different SIEM")
    lines.append("")
    lines.append(
        "The dataset itself (`dataset/*`) is SIEM-agnostic -- plain `key=value` syslog for "
        "FortiGate and newline-delimited JSON with native Sysmon/Windows Event Log field names "
        "for everything else -- so only the ingest-time parsing config needs to be rewritten "
        "(e.g. an Elastic ingest pipeline or Sentinel DCR) in place of "
        "`splunk/props.conf`/`transforms.conf`."
    )
    lines.append("")
    lines.append(
        "The one behavior to reproduce: each JSONL file interleaves events from every host in "
        "the environment, so the source host must be extracted per-record from the JSON `host` "
        "field (or `devname=` for FortiGate) rather than assumed from the file or input itself."
    )
    lines.append("")
    with open(os.path.join(docs_dir, "INGEST.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def print_summary(seed, window_start, window_end, tz_name, dataset_dir, event_counts, results, split_output):
    sizes = {}
    for fname in os.listdir(dataset_dir):
        path = os.path.join(dataset_dir, fname)
        base = fname.split("_day")[0].split(".")[0]
        sizes[base] = sizes.get(base, 0) + os.path.getsize(path)
    total_size = sum(sizes.values())

    print("Generation successful")
    print("")
    print("Seed: {}".format(seed))
    print("Time window: {} -> {} ({})".format(window_start.date(), window_end.date(), tz_name))
    print("")
    print("Dataset size:")
    for base in ("fortigate", "sysmon", "windows_security", "windows_system", "powershell"):
        mb = sizes.get(base, 0) / (1024 * 1024)
        print("  {:<26} {:.1f} MB".format(base, mb))
    print("  " + "-" * 33)
    print("  {:<26} {:.1f} MB".format("Total", total_size / (1024 * 1024)))
    print("")
    print("Events:")
    for s in SOURCES:
        print("  {:<26} {}".format(s, event_counts[s]))
    print("")
    print("Validation:")
    for name, ok, detail in results:
        print("  {:<28} {}".format(name, "PASS" if ok else "FAIL"))
    print("")
    print("Generated:")
    print("  docs/BRIEF.md")
    print("  docs/INGEST.md")
    print("  splunk/props.conf, inputs.conf, indexes.conf, transforms.conf")
    print("  solution/ground_truth.json")
    print("")
    print("Next: see docs/INGEST.md")


if __name__ == "__main__":
    main()
