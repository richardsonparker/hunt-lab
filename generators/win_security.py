"""
Windows Security (wineventlog:security:json) event builders + benign baseline.
"""

import datetime
from scenario.identity import format_time, make_logon_id

LOGON_TYPE_INTERACTIVE = 2
LOGON_TYPE_NETWORK = 3
LOGON_TYPE_BATCH = 4
LOGON_TYPE_SERVICE = 5
LOGON_TYPE_UNLOCK = 7
LOGON_TYPE_RDP = 10


def _base(time_dt, host, computer_name, event_code):
    return {
        "time": format_time(time_dt),
        "host": host.lower(),
        "ComputerName": computer_name,
        "EventCode": event_code,
        "EventID": event_code,
    }


def logon_success(time_dt, host, computer_name, target_user, target_domain, target_logon_id,
                   logon_type, logon_process, auth_package, workstation_name, ip_address, ip_port,
                   subject_user="-", subject_logon_id="0x0"):
    rec = _base(time_dt, host, computer_name, 4624)
    rec.update({
        "SubjectUserName": subject_user,
        "SubjectLogonId": subject_logon_id,
        "TargetUserName": target_user,
        "TargetDomainName": target_domain,
        "TargetLogonId": target_logon_id,
        "LogonType": logon_type,
        "LogonProcessName": logon_process,
        "AuthenticationPackageName": auth_package,
        "WorkstationName": workstation_name,
        "IpAddress": ip_address,
        "IpPort": ip_port,
    })
    return rec


def logon_failed(time_dt, host, computer_name, target_user, target_domain, logon_type,
                  workstation_name, ip_address, ip_port, failure_status="0xC000006D",
                  failure_sub_status="0xC000006A"):
    rec = _base(time_dt, host, computer_name, 4625)
    rec.update({
        "SubjectUserName": "-",
        "SubjectLogonId": "0x0",
        "TargetUserName": target_user,
        "TargetDomainName": target_domain,
        "LogonType": logon_type,
        "WorkstationName": workstation_name,
        "IpAddress": ip_address,
        "IpPort": ip_port,
        "Status": failure_status,
        "SubStatus": failure_sub_status,
    })
    return rec


def logoff(time_dt, host, computer_name, target_user, target_domain, target_logon_id):
    rec = _base(time_dt, host, computer_name, 4634)
    rec.update({
        "TargetUserName": target_user,
        "TargetDomainName": target_domain,
        "TargetLogonId": target_logon_id,
        "LogonType": LOGON_TYPE_INTERACTIVE,
    })
    return rec


def token_logoff(time_dt, host, computer_name, subject_user, subject_domain, subject_logon_id):
    rec = _base(time_dt, host, computer_name, 4647)
    rec.update({
        "SubjectUserName": subject_user,
        "SubjectDomainName": subject_domain,
        "SubjectLogonId": subject_logon_id,
    })
    return rec


def explicit_creds(time_dt, host, computer_name, subject_user, target_user, target_domain,
                    target_server, process_name):
    rec = _base(time_dt, host, computer_name, 4648)
    rec.update({
        "SubjectUserName": subject_user,
        "TargetUserName": target_user,
        "TargetDomainName": target_domain,
        "TargetServerName": target_server,
        "ProcessName": process_name,
    })
    return rec


def special_privileges(time_dt, host, computer_name, subject_user, subject_domain, subject_logon_id):
    rec = _base(time_dt, host, computer_name, 4672)
    rec.update({
        "SubjectUserName": subject_user,
        "SubjectDomainName": subject_domain,
        "SubjectLogonId": subject_logon_id,
        "PrivilegeList": "SeDebugPrivilege",
    })
    return rec


def process_creation_4688(time_dt, host, computer_name, subject_user, subject_logon_id,
                           process_name, process_id, command_line, parent_process_name):
    rec = _base(time_dt, host, computer_name, 4688)
    rec.update({
        "SubjectUserName": subject_user,
        "SubjectLogonId": subject_logon_id,
        "ProcessName": process_name,
        "ProcessId": process_id,
        "CommandLine": command_line,
        "ParentProcessName": parent_process_name,
    })
    return rec


def share_access_5140(time_dt, host, computer_name, subject_user, subject_domain, subject_logon_id,
                       ip_address, ip_port, share_name, share_local_path):
    rec = _base(time_dt, host, computer_name, 5140)
    rec.update({
        "SubjectUserName": subject_user,
        "SubjectDomainName": subject_domain,
        "SubjectLogonId": subject_logon_id,
        "ObjectType": "File",
        "IpAddress": ip_address,
        "IpPort": ip_port,
        "ShareName": share_name,
        "ShareLocalPath": share_local_path,
        "AccessMask": "0x1",
    })
    return rec


def kerberos_tgs(time_dt, host, computer_name, target_user, target_domain, service_name, ip_address):
    rec = _base(time_dt, host, computer_name, 4769)
    rec.update({
        "TargetUserName": target_user,
        "TargetDomainName": target_domain,
        "ServiceName": service_name,
        "IpAddress": ip_address,
    })
    return rec


WORK_HOUR_LOGON_PROCS = ["User32", "NtLmSsp", "Kerberos"]


def generate_benign(seed, environment, rng, day_start, count, identity):
    from scenario.identity import make_logon_id, biased_business_hour_offset
    domain_short = environment["domain"].split(".")[0].upper()
    workstations = [h for h in environment["hosts"] if h["role"] == "workstation"]
    day_end = day_start + datetime.timedelta(days=1)

    for _ in range(count):
        host = rng.choice(workstations)
        user = host["primary_user"]
        t = day_start + datetime.timedelta(seconds=biased_business_hour_offset(rng))
        lid = make_logon_id(rng)
        rec = logon_success(
            t, host["hostname"], host["fqdn"], user, domain_short, lid,
            LOGON_TYPE_INTERACTIVE, "User32", "Negotiate", host["hostname"], "-", "-",
        )
        yield "windows_security", t, rec
        logoff_t = t + datetime.timedelta(hours=rng.randint(4, 9))
        if logoff_t < day_end:
            rec2 = logoff(logoff_t, host["hostname"], host["fqdn"], user, domain_short, lid)
            yield "windows_security", logoff_t, rec2

        if rng.random() < 0.12:
            t2 = day_start + datetime.timedelta(seconds=biased_business_hour_offset(rng))
            rec3 = logon_failed(
                t2, host["hostname"], host["fqdn"], user, domain_short, LOGON_TYPE_INTERACTIVE,
                host["hostname"], "-", "-",
            )
            yield "windows_security", t2, rec3
