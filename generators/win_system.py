"""
Windows System (wineventlog:system:json) event builders + benign baseline.
"""

import datetime
from scenario.identity import format_time


def _base(time_dt, host, computer_name, event_code):
    return {
        "time": format_time(time_dt),
        "host": host.lower(),
        "ComputerName": computer_name,
        "EventCode": event_code,
        "EventID": event_code,
    }


def service_installed_7045(time_dt, host, computer_name, service_name, service_file_name,
                            service_type, service_start_type, account_name):
    rec = _base(time_dt, host, computer_name, 7045)
    rec.update({
        "ServiceName": service_name,
        "ImagePath": service_file_name,
        "ServiceType": service_type,
        "StartType": service_start_type,
        "AccountName": account_name,
    })
    return rec


def service_state_7036(time_dt, host, computer_name, service_name, state):
    rec = _base(time_dt, host, computer_name, 7036)
    rec.update({
        "ServiceName": service_name,
        "State": state,
    })
    return rec


def service_crashed_7034(time_dt, host, computer_name, service_name):
    rec = _base(time_dt, host, computer_name, 7034)
    rec.update({
        "ServiceName": service_name,
    })
    return rec


def eventlog_started_6005(time_dt, host, computer_name):
    return _base(time_dt, host, computer_name, 6005)


def eventlog_stopped_6006(time_dt, host, computer_name):
    return _base(time_dt, host, computer_name, 6006)


def system_shutdown_1074(time_dt, host, computer_name, user, reason):
    rec = _base(time_dt, host, computer_name, 1074)
    rec.update({
        "User": user,
        "ProcessName": "C:\\Windows\\System32\\winlogon.exe",
        "Reason": reason,
    })
    return rec


ROUTINE_SERVICES = ["WSearch", "BITS", "wuauserv", "Spooler", "EdrSvcAgent"]


def generate_benign(seed, environment, rng, day_start, count, identity):
    from scenario.identity import biased_business_hour_offset
    hosts = [h for h in environment["hosts"] if h["role"] in ("workstation", "file_server", "domain_controller")]
    for _ in range(count):
        host = rng.choice(hosts)
        svc = rng.choice(ROUTINE_SERVICES)
        t = day_start + datetime.timedelta(seconds=biased_business_hour_offset(rng))
        state = rng.choice(["running", "stopped"])
        rec = service_state_7036(t, host["hostname"], host["fqdn"], svc, state)
        yield "windows_system", t, rec

    if rng.random() < 0.15:
        host = rng.choice(hosts)
        t = day_start + datetime.timedelta(seconds=biased_business_hour_offset(rng))
        rec = system_shutdown_1074(t, host["hostname"], host["fqdn"], "SYSTEM", "Operating System: Reconfiguration (Planned)")
        yield "windows_system", t, rec
