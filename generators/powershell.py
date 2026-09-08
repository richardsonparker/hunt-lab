"""
PowerShell Operational (powershell:json) event builders + benign baseline.
"""

import datetime
from scenario.identity import format_time

BENIGN_SCRIPTS = [
    "Get-ChildItem C:\\Shares\\Finance | Sort-Object LastWriteTime -Descending | Select-Object -First 20",
    "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,Status",
    "Get-ADUser -Filter * -Properties Department | Export-Csv C:\\Reports\\adusers.csv",
    "Restart-Service -Name Spooler -Force",
    "Get-EventLog -LogName System -Newest 50",
    "Copy-Item C:\\Users\\Public\\template.xlsx -Destination C:\\Shares\\Sales\\",
]


def _base(time_dt, host, computer_name, event_code):
    return {
        "time": format_time(time_dt),
        "host": host.lower(),
        "ComputerName": computer_name,
        "EventCode": event_code,
        "EventID": event_code,
    }


def script_block_4104(time_dt, host, computer_name, script_block_text, script_block_id,
                       path, user, message_number=1, message_total=1):
    rec = _base(time_dt, host, computer_name, 4104)
    rec.update({
        "ScriptBlockText": script_block_text,
        "ScriptBlockId": script_block_id,
        "Path": path,
        "User": user,
        "MessageNumber": message_number,
        "MessageTotal": message_total,
    })
    return rec


def module_log_4103(time_dt, host, computer_name, command_line, user, host_name="ConsoleHost", host_version="5.1"):
    rec = _base(time_dt, host, computer_name, 4103)
    rec.update({
        "CommandLine": command_line,
        "User": user,
        "HostName": host_name,
        "HostVersion": host_version,
    })
    return rec


def generate_benign(seed, environment, rng, day_start, count, identity):
    import uuid
    from scenario.identity import biased_business_hour_offset
    workstations = [h for h in environment["hosts"] if h["role"] in ("workstation", "file_server")]
    for _ in range(count):
        host = rng.choice(workstations)
        user = host.get("primary_user") or "adm-jsmith"
        script = rng.choice(BENIGN_SCRIPTS)
        t = day_start + datetime.timedelta(seconds=biased_business_hour_offset(rng))
        sbid = str(uuid.UUID(int=rng.getrandbits(128)))
        rec = script_block_4104(t, host["hostname"], host["fqdn"], script, sbid, "-", user)
        yield "powershell", t, rec
