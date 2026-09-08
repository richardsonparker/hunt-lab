"""
Deliberate, coherent false positives. Each has its own internally consistent
benign story and is planted independently of the attack chain, using
rng_fp so it never perturbs attack or benign-baseline determinism.
"""

import datetime
import uuid

from scenario.identity import make_process_guid, make_logon_id, format_time
from scenario.environment import host_by_name, workstation_hosts
from generators import sysmon, win_security, win_system, powershell, fortigate


def _pick_day(rng_fp, window_start, exclude_day_index, num_days):
    idx = rng_fp.choice([d for d in range(num_days) if d != exclude_day_index])
    return window_start + datetime.timedelta(days=idx)


def build_false_positives(seed, environment, rng_fp, window_start, num_days, attack_day_index, seq_counters):
    events = []
    descriptions = []
    domain_short = environment["domain"].split(".")[0].upper()
    ws_hosts = workstation_hosts(environment)
    admins = [u["username"] for u in environment["users"] if u["is_admin"]]
    fs = host_by_name(environment, "FS01")
    dc = host_by_name(environment, environment["dc_hostname"])

    def guid(host, t):
        return make_process_guid(environment["machine_guids"][host], t, seq_counters.next(host))

    def day_time(base_day, hour, minute):
        return base_day.replace(hour=hour, minute=minute, second=rng_fp.randint(0, 59), microsecond=0)

    # FP 1: admin running unusual-but-legitimate PowerShell (bulk AD export) after hours
    day = _pick_day(rng_fp, window_start, attack_day_index, num_days)
    t = day_time(day, rng_fp.randint(19, 22), rng_fp.randint(0, 59))
    admin = rng_fp.choice(admins)
    host = dc["hostname"]
    sbid = str(uuid.UUID(int=rng_fp.getrandbits(128)))
    rec = powershell.script_block_4104(
        t, host, dc["fqdn"],
        "Get-ADUser -Filter * -Properties * | Export-Csv \\\\FS01\\IT$\\quarterly_ad_export.csv -NoTypeInformation",
        sbid, "C:\\Scripts\\quarterly_export.ps1", "{}\\{}".format(domain_short, admin),
    )
    events.append(("powershell", t, rec))
    descriptions.append({
        "name": "After-hours bulk AD export by IT admin",
        "spl": 'index=hunt_lab sourcetype=powershell:json EventCode=4104 ScriptBlockText="*Export-Csv*" host={}'.format(host.lower()),
        "why_benign": "Matches the documented quarterly AD-export script path ({}) and runs from {}'s account on the domain controller itself -- expected admin workflow, not attacker discovery.".format("C:\\Scripts\\quarterly_export.ps1", admin),
    })

    # FP 2: legitimate remote administration session (RDP from IT workstation to FS01)
    day = _pick_day(rng_fp, window_start, attack_day_index, num_days)
    t = day_time(day, rng_fp.randint(9, 17), rng_fp.randint(0, 59))
    admin = rng_fp.choice(admins)
    it_ws = rng_fp.choice(ws_hosts)
    lid = make_logon_id(rng_fp)
    rec = win_security.logon_success(
        t, "FS01", fs["fqdn"], admin, domain_short, lid, win_security.LOGON_TYPE_RDP,
        "User32", "Negotiate", it_ws["hostname"], it_ws["ip"], rng_fp.randint(49152, 65000),
    )
    events.append(("windows_security", t, rec))
    t2 = t + datetime.timedelta(minutes=rng_fp.randint(10, 40))
    events.append(("windows_security", t2, win_security.logoff(t2, "FS01", fs["fqdn"], admin, domain_short, lid)))
    descriptions.append({
        "name": "Legitimate RDP admin session to FS01",
        "spl": 'index=hunt_lab sourcetype=wineventlog:security:json EventCode=4624 LogonType=10 dest=FS01',
        "why_benign": "Source is an internal workstation IP ({}) -- not the reserved 203.0.113.0/24 attacker-infra block -- with a short, single session and a matching 4634/4647 logoff shortly after.".format(it_ws["ip"]),
    })

    # FP 3: burst of failed logons from expired cached credential
    day = _pick_day(rng_fp, window_start, attack_day_index, num_days)
    t = day_time(day, rng_fp.randint(8, 10), rng_fp.randint(0, 59))
    ws = rng_fp.choice(ws_hosts)
    user = ws["primary_user"]
    n_fail = rng_fp.randint(5, 8)
    for i in range(n_fail):
        events.append(("windows_security", t, win_security.logon_failed(
            t, ws["hostname"], ws["fqdn"], user, domain_short, win_security.LOGON_TYPE_INTERACTIVE,
            ws["hostname"], "-", "-", failure_status="0xC000006A", failure_sub_status="0xC000006A",
        )))
        t = t + datetime.timedelta(seconds=rng_fp.randint(20, 90))
    lid = make_logon_id(rng_fp)
    events.append(("windows_security", t, win_security.logon_success(
        t, ws["hostname"], ws["fqdn"], user, domain_short, lid, win_security.LOGON_TYPE_INTERACTIVE,
        "User32", "Negotiate", ws["hostname"], "-", "-",
    )))
    descriptions.append({
        "name": "Expired cached credential lockout ({})".format(user),
        "spl": 'index=hunt_lab sourcetype=wineventlog:security:json EventCode=4625 host={} | stats count by TargetUserName'.format(ws["hostname"].lower()),
        "why_benign": "All {} failures and the eventual success come from the user's own registered workstation ({}) with no external or lateral IP involved -- a stale cached password, not a brute force.".format(n_fail, ws["hostname"]),
    })

    # FP 4: software installation creating a service
    day = _pick_day(rng_fp, window_start, attack_day_index, num_days)
    t = day_time(day, rng_fp.randint(10, 16), rng_fp.randint(0, 59))
    ws = rng_fp.choice(ws_hosts)
    user = ws["primary_user"]
    installer_guid = guid(ws["hostname"], t)
    installer_pid = rng_fp.randint(2000, 9000)
    rec = sysmon.process_create(
        seed, t, ws["hostname"], ws["fqdn"], installer_guid, installer_pid,
        "C:\\Users\\{}\\Downloads\\AcroRdrDCUpd2400.exe".format(user), "Adobe Acrobat Reader DC Update",
        "Adobe Acrobat Reader DC", "Adobe Inc.", "AcroRdrDCUpd2400.exe",
        '"AcroRdrDCUpd2400.exe" /sAll', "C:\\Users\\{}\\Downloads\\".format(user),
        "{}\\{}".format(domain_short, user), installer_guid, make_logon_id(rng_fp), "High",
        "{00000000-0000-0000-0000-000000000000}", 4, "C:\\Windows\\explorer.exe", "explorer.exe",
    )
    events.append(("sysmon", t, rec))
    t2 = t + datetime.timedelta(seconds=rng_fp.randint(30, 90))
    svc_rec = win_system.service_installed_7045(
        t2, ws["hostname"], ws["fqdn"], "AdobeARMservice", "C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\armsvc.exe",
        "user mode service", "auto start", "LocalSystem",
    )
    events.append(("windows_system", t2, svc_rec))
    descriptions.append({
        "name": "Adobe Acrobat updater installs a service",
        "spl": 'index=hunt_lab sourcetype=wineventlog:system:json EventCode=7045 | search ServiceName="AdobeARMservice"',
        "why_benign": "ImagePath points at Adobe's own signed update-service binary under Program Files, installed immediately after a user-initiated download in the same session -- routine patching, not attacker persistence.",
    })

    # FP 5: odd-looking child process from a legitimate application (Excel macro reporting tool)
    day = _pick_day(rng_fp, window_start, attack_day_index, num_days)
    t = day_time(day, rng_fp.randint(9, 17), rng_fp.randint(0, 59))
    ws = rng_fp.choice(ws_hosts)
    user = ws["primary_user"]
    excel_guid = guid(ws["hostname"], t)
    excel_pid = rng_fp.randint(2000, 9000)
    events.append(("sysmon", t, sysmon.process_create(
        seed, t, ws["hostname"], ws["fqdn"], excel_guid, excel_pid,
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "Microsoft Excel", "Microsoft Office",
        "Microsoft Corporation", "EXCEL.EXE", '"EXCEL.EXE" "C:\\Shares\\Finance\\Monthly_Report_Macro.xlsm"',
        "C:\\Shares\\Finance\\", "{}\\{}".format(domain_short, user), excel_guid, make_logon_id(rng_fp), "Medium",
        "{00000000-0000-0000-0000-000000000000}", 4, "C:\\Windows\\explorer.exe", "explorer.exe",
    )))
    t2 = t + datetime.timedelta(seconds=rng_fp.randint(5, 30))
    cmd_guid = guid(ws["hostname"], t2)
    cmd_pid = rng_fp.randint(2000, 9000)
    events.append(("sysmon", t2, sysmon.process_create(
        seed, t2, ws["hostname"], ws["fqdn"], cmd_guid, cmd_pid,
        "C:\\Windows\\System32\\cmd.exe", "Windows Command Processor", "Microsoft(R) Windows(R) Operating System",
        "Microsoft Corporation", "CMD.EXE", 'cmd.exe /c copy "Monthly_Report.pdf" "C:\\Shares\\Finance\\Archive\\"',
        "C:\\Shares\\Finance\\", "{}\\{}".format(domain_short, user), cmd_guid, make_logon_id(rng_fp), "Medium",
        excel_guid, excel_pid, "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
        '"EXCEL.EXE" "C:\\Shares\\Finance\\Monthly_Report_Macro.xlsm"',
    )))
    descriptions.append({
        "name": "Excel macro workbook spawns cmd.exe to archive a report",
        "spl": 'index=hunt_lab sourcetype=sysmon:json EventCode=1 ParentImage="*EXCEL.EXE" Image="*cmd.exe"',
        "why_benign": "The known internal 'Monthly_Report_Macro.xlsm' workbook always spawns a single short-lived cmd.exe to copy its own output into an Archive folder -- consistent filename, consistent parent, no network activity, no persistence.",
    })

    # FP 6: uncommon but benign external connection (contracted backup vendor)
    day = _pick_day(rng_fp, window_start, attack_day_index, num_days)
    t = day_time(day, rng_fp.randint(1, 4), rng_fp.randint(0, 59))
    vendor_ip = "198.51.100.{}".format(rng_fp.randint(2, 254))
    line = fortigate.traffic_log(
        t, fs["ip"], rng_fp.randint(49152, 65000), "internal", vendor_ip, 443, "wan1",
        rng_fp.randint(20_000_000, 29_000_000), "tcp", "accept", 2, "backup-sync", "HTTPS",
        "cloud.backup", "United States", "Israel", rng_fp.randint(600, 1800),
        rng_fp.randint(8_000_000, 20_000_000), rng_fp.randint(400_000, 900_000), 4000, 3000,
    )
    events.append(("fortigate", t, line))
    descriptions.append({
        "name": "Off-hours outbound sync to contracted backup vendor",
        "spl": 'index=hunt_lab sourcetype=fortigate dstip="198.51.100.0/24" app="backup-sync" | stats sum(sentbyte) by dstip',
        "why_benign": "Large, sustained overnight upload from FS01 to a single stable vendor IP with app='backup-sync' -- matches the nightly offsite backup window, not the short bursty pattern seen from the attacker-infra block (203.0.113.0/24).",
    })

    return events, descriptions
