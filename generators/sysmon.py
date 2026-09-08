"""
Sysmon (sysmon:json) event builders + benign baseline generator.
"""

from scenario.identity import format_time, format_utc_time, hashes_field

LEGIT_BINARIES = [
    ("C:\\Windows\\explorer.exe", "Windows Explorer", "Microsoft Corporation"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "Microsoft Outlook", "Microsoft Corporation"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "Microsoft Word", "Microsoft Corporation"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "Microsoft Excel", "Microsoft Corporation"),
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "Google Chrome", "Google LLC"),
    ("C:\\Windows\\System32\\svchost.exe", "Host Process for Windows Services", "Microsoft Corporation"),
    ("C:\\Windows\\System32\\cmd.exe", "Windows Command Processor", "Microsoft Corporation"),
    ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "Windows PowerShell", "Microsoft Corporation"),
    ("C:\\Windows\\System32\\notepad.exe", "Notepad", "Microsoft Corporation"),
    ("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "Microsoft Edge", "Microsoft Corporation"),
    ("C:\\Windows\\System32\\dllhost.exe", "COM Surrogate", "Microsoft Corporation"),
    ("C:\\Windows\\System32\\taskhostw.exe", "Host Process for Windows Tasks", "Microsoft Corporation"),
    ("C:\\ProgramData\\EDRAgent\\edrsvc.exe", "Endpoint Agent Service", "Sentinel Defense Co"),
]


def _base(time_dt, host, computer_name, event_code, seed_ext=""):
    rec = {
        "time": format_time(time_dt),
        "host": host.lower(),
        "ComputerName": computer_name,
        "EventCode": event_code,
        "EventID": event_code,
        "UtcTime": format_utc_time(time_dt),
    }
    return rec


def process_create(seed, time_dt, host, computer_name, process_guid, pid, image,
                    description, product, company, original_filename, command_line,
                    current_directory, user, logon_guid, logon_id, integrity_level,
                    parent_process_guid, parent_pid, parent_image, parent_command_line,
                    file_version="1.0.0.0"):
    rec = _base(time_dt, host, computer_name, 1)
    rec.update({
        "ProcessGuid": process_guid,
        "ProcessId": pid,
        "Image": image,
        "FileVersion": file_version,
        "Description": description,
        "Product": product,
        "Company": company,
        "OriginalFileName": original_filename,
        "CommandLine": command_line,
        "CurrentDirectory": current_directory,
        "User": user,
        "LogonGuid": logon_guid,
        "LogonId": logon_id,
        "IntegrityLevel": integrity_level,
        "Hashes": hashes_field(seed, image),
        "ParentProcessGuid": parent_process_guid,
        "ParentProcessId": parent_pid,
        "ParentImage": parent_image,
        "ParentCommandLine": parent_command_line,
    })
    return rec


def network_connect(time_dt, host, computer_name, process_guid, pid, image, user,
                     protocol, src_ip, src_port, dst_ip, dst_port, dst_hostname, initiated=True):
    rec = _base(time_dt, host, computer_name, 3)
    rec.update({
        "ProcessGuid": process_guid,
        "ProcessId": pid,
        "Image": image,
        "User": user,
        "Protocol": protocol,
        "SourceIp": src_ip,
        "SourcePort": src_port,
        "DestinationIp": dst_ip,
        "DestinationPort": dst_port,
        "DestinationHostname": dst_hostname or "",
        "Initiated": "true" if initiated else "false",
    })
    return rec


def file_create(time_dt, host, computer_name, process_guid, pid, image, target_filename, user):
    rec = _base(time_dt, host, computer_name, 11)
    rec.update({
        "ProcessGuid": process_guid,
        "ProcessId": pid,
        "Image": image,
        "TargetFilename": target_filename,
        "CreationUtcTime": format_utc_time(time_dt),
        "User": user,
    })
    return rec


def registry_set(time_dt, host, computer_name, process_guid, pid, image, target_object, details, user):
    rec = _base(time_dt, host, computer_name, 13)
    rec.update({
        "EventType": "SetValue",
        "ProcessGuid": process_guid,
        "ProcessId": pid,
        "Image": image,
        "TargetObject": target_object,
        "Details": details,
        "User": user,
    })
    return rec


def dns_query(time_dt, host, computer_name, process_guid, pid, image, query_name, query_results, user):
    rec = _base(time_dt, host, computer_name, 22)
    rec.update({
        "ProcessGuid": process_guid,
        "ProcessId": pid,
        "Image": image,
        "QueryName": query_name,
        "QueryStatus": "0",
        "QueryResults": query_results,
        "User": user,
    })
    return rec


def generate_benign(seed, environment, rng, day_start, count, identity):
    """Yield ordinary process-create / network / dns noise across workstations for one day."""
    import datetime
    from scenario.identity import make_process_guid, make_logon_id, biased_business_hour_offset
    from generators.fortigate import benign_external_ip

    hosts = [h for h in environment["hosts"] if h["role"] in ("workstation", "file_server", "domain_controller")]
    domain = environment["domain"]

    for _ in range(count):
        host = rng.choice(hosts)
        user = host["primary_user"] if host["role"] == "workstation" else "SYSTEM"
        image, desc, company = rng.choice(LEGIT_BINARIES)
        t = day_start + datetime.timedelta(seconds=biased_business_hour_offset(rng))
        machine_guid = environment["machine_guids"][host["hostname"]]
        seq = identity.next(host["hostname"])
        pguid = make_process_guid(machine_guid, t, seq)
        pid = rng.randint(1000, 32000)
        lguid = make_process_guid(machine_guid, t, seq + 50000)
        lid = make_logon_id(rng)
        rec = process_create(
            seed, t, host["hostname"], host["fqdn"] or host["hostname"], pguid, pid, image,
            desc, desc, company, image.split("\\")[-1],
            '"{}"'.format(image), "C:\\Users\\{}\\".format(user), "{}\\{}".format(domain.split(".")[0].upper(), user),
            lguid, lid, "Medium",
            "{00000000-0000-0000-0000-000000000000}", 4, "C:\\Windows\\explorer.exe", "explorer.exe",
        )
        yield "sysmon", t, rec

        if rng.random() < 0.3:
            dst_ip = benign_external_ip(rng)
            netrec = network_connect(
                t, host["hostname"], host["fqdn"] or host["hostname"], pguid, pid, image, user,
                "tcp", host["ip"], rng.randint(49152, 65000), dst_ip, rng.choice([443, 443, 443, 80]),
                rng.choice(["www.microsoft.com", "outlook.office365.com", "update.googleapis.com", "www.google.com"]),
            )
            yield "sysmon", t, netrec
