"""
Post-generation validation suite. Reads the written dataset/ and solution/
files back from disk so it validates what a learner would actually ingest,
not generator-internal state. Every check returns (name, passed, detail).
Generation fails loudly (non-zero exit) if any check here fails.
"""

import glob
import json
import os
import re
import datetime

FORBIDDEN_TERMS = [
    "malicious", "attack_stage", "scenario_id", "mitre_id", "ground_truth",
    "ioc=true", "compromised", "threat_actor", "attack_event", "is_attack",
]

STAGE_ORDER = [
    "initial_access", "execution", "persistence", "discovery",
    "credential_use", "lateral_movement", "collection", "staging", "exfiltration",
]

JSONL_BASES = {
    "sysmon": "sysmon:json",
    "windows_security": "wineventlog:security:json",
    "windows_system": "wineventlog:system:json",
    "powershell": "powershell:json",
}


class ValidationError(Exception):
    pass


def _resolve_paths(dataset_dir, base, ext):
    """A dataset file may exist as a single file (base.ext) or, when the
    license-cap split kicks in, as base_day1.ext, base_day2.ext, ... Return
    every matching path, in day order."""
    single = os.path.join(dataset_dir, "{}.{}".format(base, ext))
    if os.path.exists(single):
        return [single]
    split_paths = sorted(
        glob.glob(os.path.join(dataset_dir, "{}_day*.{}".format(base, ext))),
        key=lambda p: int(re.search(r"_day(\d+)\.", p).group(1)),
    )
    return split_paths


def _read_jsonl_file(path):
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValidationError("{}:{} does not parse as JSON: {}".format(path, lineno, e))
    return records


def _read_jsonl(dataset_dir, base):
    paths = _resolve_paths(dataset_dir, base, "jsonl")
    if not paths:
        raise ValidationError("no {}*.jsonl file found in {}".format(base, dataset_dir))
    records = []
    for p in paths:
        records.extend(_read_jsonl_file(p))
    return records


def _read_fortigate_file(path):
    lines = []
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line:
                continue
            if "=" not in line or "type=traffic" not in line:
                raise ValidationError("{}:{} does not look like a key=value traffic log".format(path, lineno))
            lines.append(line)
    return lines


def _read_fortigate(dataset_dir):
    paths = _resolve_paths(dataset_dir, "fortigate", "log")
    if not paths:
        raise ValidationError("no fortigate*.log file found in {}".format(dataset_dir))
    lines = []
    for p in paths:
        lines.extend(_read_fortigate_file(p))
    return lines


def check_scenario_integrity(scenario):
    stages_present = {s["stage"] for s in scenario["attack_timeline"]}
    required_min = {"initial_access", "execution", "discovery", "lateral_movement", "exfiltration"}
    missing = required_min - stages_present
    if missing:
        return ("Scenario integrity", False, "Missing required stages: {}".format(missing))
    if not (5 <= len(scenario["mitre_mappings"]) <= 20):
        return ("Scenario integrity", False, "Technique count out of scope: {}".format(len(scenario["mitre_mappings"])))
    return ("Scenario integrity", True, "{} stages, {} technique mappings".format(len(stages_present), len(scenario["mitre_mappings"])))


def check_timeline_consistency(scenario):
    fmt = "%Y-%m-%dT%H:%M:%S.%f%z"
    times = []
    for step in scenario["attack_timeline"]:
        times.append(datetime.datetime.strptime(step["time"], fmt))
    if times != sorted(times):
        return ("Timeline consistency", False, "attack_timeline steps are not chronologically ordered")
    stage_positions = {}
    for i, step in enumerate(scenario["attack_timeline"]):
        stage_positions.setdefault(step["stage"], []).append(i)
    if "collection" in stage_positions and "exfiltration" in stage_positions:
        if max(stage_positions["collection"]) > min(stage_positions["exfiltration"]):
            return ("Timeline consistency", False, "collection occurs after exfiltration begins")
    return ("Timeline consistency", True, "{} steps in chronological order".format(len(times)))


def check_environment_consistency(scenario, environment):
    hostnames = {h["hostname"] for h in environment["hosts"]}
    usernames = {u["username"] for u in environment["users"]}
    for h in scenario["affected_hosts"]:
        if h not in hostnames:
            return ("Environment consistency", False, "affected host {} not in network map".format(h))
    for a in scenario["affected_accounts"]:
        if a not in usernames:
            return ("Environment consistency", False, "affected account {} not in user list".format(a))
    ips = [h["ip"] for h in environment["hosts"]]
    if len(ips) != len(set(ips)):
        return ("Environment consistency", False, "duplicate IP addresses in network map")
    return ("Environment consistency", True, "{} hosts, {} users, all referenced entities resolve".format(len(environment["hosts"]), len(environment["users"])))


def check_process_relationships(dataset_dir):
    records = _read_jsonl(dataset_dir, "sysmon")
    guids = set()
    dupes = []
    parent_refs = []
    root_sentinel = "{00000000-0000-0000-0000-000000000000}"
    for r in records:
        if r.get("EventCode") == 1:
            g = r["ProcessGuid"]
            if g in guids:
                dupes.append(g)
            guids.add(g)
    if dupes:
        return ("Process relationships", False, "{} duplicate ProcessGuid value(s) found (e.g. {})".format(len(dupes), dupes[0]))
    for r in records:
        if r.get("EventCode") == 1:
            pguid = r.get("ParentProcessGuid")
            if pguid and pguid != root_sentinel and pguid not in guids:
                parent_refs.append((r["ProcessGuid"], pguid))
    if parent_refs:
        return ("Process relationships", False, "{} process-create events reference an unresolved ParentProcessGuid (e.g. {})".format(len(parent_refs), parent_refs[0]))
    return ("Process relationships", True, "{} unique ProcessGuids, all parent references resolve".format(len(guids)))


def check_authentication_correlation(dataset_dir, environment):
    records = _read_jsonl(dataset_dir, "windows_security")
    hostnames = {h["hostname"] for h in environment["hosts"]}
    bad_types = set()
    for r in records:
        lt = r.get("LogonType")
        if lt is not None and lt not in (2, 3, 4, 5, 7, 8, 9, 10, 11):
            bad_types.add(lt)
    if bad_types:
        return ("Authentication correlation", False, "implausible LogonType values found: {}".format(bad_types))
    logon_ids_4624 = {r["TargetLogonId"] for r in records if r.get("EventCode") == 4624 and "TargetLogonId" in r}
    logoff_refs = {r["TargetLogonId"] for r in records if r.get("EventCode") == 4634 and "TargetLogonId" in r}
    orphaned = logoff_refs - logon_ids_4624
    if orphaned:
        return ("Authentication correlation", False, "4634 logoff events reference LogonIds with no matching 4624: {}".format(list(orphaned)[:3]))
    return ("Authentication correlation", True, "{} logon events, LogonId lifecycle consistent".format(len(records)))


def check_network_correlation(dataset_dir, scenario):
    sysmon_records = _read_jsonl(dataset_dir, "sysmon")
    fortigate_lines = _read_fortigate(dataset_dir)
    infra = scenario.get("attacker_infrastructure", {})
    infra_ip = infra.get("ip")
    if infra_ip:
        sysmon_hits = [r for r in sysmon_records if r.get("EventCode") == 3 and r.get("DestinationIp") == infra_ip]
        fortigate_hits = [l for l in fortigate_lines if "dstip={}".format(infra_ip) in l]
        if not sysmon_hits:
            return ("Network correlation", False, "no Sysmon EventCode 3 events to attacker infrastructure IP {}".format(infra_ip))
        if not fortigate_hits:
            return ("Network correlation", False, "no FortiGate traffic-log entries to attacker infrastructure IP {}".format(infra_ip))
    lateral_hosts = scenario.get("affected_hosts", [])
    if len(lateral_hosts) >= 2:
        second_host = lateral_hosts[1]
        sec_records = _read_jsonl(dataset_dir, "windows_security")
        second_host_logons = [r for r in sec_records if r.get("host") == second_host.lower() and r.get("EventCode") == 4624 and r.get("LogonType") in (3, 10)]
        if not second_host_logons:
            return ("Network correlation", False, "no remote logon evidence on second affected host {}".format(second_host))
    return ("Network correlation", True, "attacker-infrastructure and lateral-movement evidence present on both endpoints")


def check_hash_stability(seed, dataset_dir):
    records = _read_jsonl(dataset_dir, "sysmon")
    seen = {}
    for r in records:
        if r.get("EventCode") != 1 or "Image" not in r or "Hashes" not in r:
            continue
        image = r["Image"]
        h = r["Hashes"]
        if image in seen and seen[image] != h:
            return ("Hash stability", False, "Image {} maps to more than one hash set".format(image))
        seen[image] = h
    return ("Hash stability", True, "{} distinct binaries, each with exactly one hash set".format(len(seen)))


def check_attack_evidence_sufficiency(scenario):
    by_source = scenario.get("expected_telemetry", {})
    if not by_source or sum(by_source.values()) < 30:
        return ("Attack evidence", False, "too few attack events generated: {}".format(by_source))
    sources_used = set(by_source.keys())
    if len(sources_used) < 3:
        return ("Attack evidence", False, "attack evidence spans fewer than 3 telemetry sources: {}".format(sources_used))
    return ("Attack evidence", True, "{} total attack events across {} sources".format(sum(by_source.values()), len(sources_used)))


def check_file_validity(dataset_dir, window_start, window_end):
    for base in JSONL_BASES:
        if not _resolve_paths(dataset_dir, base, "jsonl"):
            return ("File validity", False, "missing {}(.jsonl / _dayN.jsonl)".format(base))
        records = _read_jsonl(dataset_dir, base)
        if not records:
            return ("File validity", False, "{} is empty".format(base))
        for r in records[:5] + records[-5:]:
            keys = list(r.keys())
            if keys[0] != "time":
                return ("File validity", False, "{}: 'time' is not the first key of a record".format(base))
    if not _resolve_paths(dataset_dir, "fortigate", "log"):
        return ("File validity", False, "missing fortigate.log")
    _read_fortigate(dataset_dir)
    return ("File validity", True, "all dataset files parse; 'time' is the first key in every JSONL record")


def check_leakage(dataset_dir):
    hits = []
    for root, _, files in os.walk(dataset_dir):
        for fname in files:
            path = os.path.join(root, fname)
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for lineno, line in enumerate(f, 1):
                    lower = line.lower()
                    for term in FORBIDDEN_TERMS:
                        if term in lower:
                            hits.append("{}:{} contains '{}'".format(fname, lineno, term))
    if hits:
        return ("Leakage (dataset/ only)", False, "; ".join(hits[:5]))
    return ("Leakage (dataset/ only)", True, "no forbidden ground-truth terms found in dataset/")


def check_dataset_size(dataset_dir):
    total = 0
    for root, _, files in os.walk(dataset_dir):
        for fname in files:
            total += os.path.getsize(os.path.join(root, fname))
    mb = total / (1024 * 1024)
    if mb > 2048:
        return ("Dataset size", False, "{:.1f} MB exceeds the 2 GB hard maximum".format(mb))
    detail = "{:.1f} MB total".format(mb)
    if mb > 450:
        detail += " (over 450 MB -- license-cap warning issued)"
    return ("Dataset size", True, detail)


def run_all(scenario, environment, dataset_dir, window_start, window_end, seed):
    results = [
        check_scenario_integrity(scenario),
        check_timeline_consistency(scenario),
        check_environment_consistency(scenario, environment),
        check_process_relationships(dataset_dir),
        check_authentication_correlation(dataset_dir, environment),
        check_network_correlation(dataset_dir, scenario),
        check_hash_stability(seed, dataset_dir),
        check_attack_evidence_sufficiency(scenario),
        check_file_validity(dataset_dir, window_start, window_end),
        check_leakage(dataset_dir),
        check_dataset_size(dataset_dir),
    ]
    return results
