"""
Canonical MITRE ATT&CK technique registry used by scenario templates.

Every ID/name/URL below is a verified, long-standing ATT&CK entry (Enterprise
matrix). Templates reference techniques by key; nothing here is invented.
"""

TECHNIQUES = {
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
    },
    "T1204.002": {
        "name": "User Execution: Malicious File",
        "url": "https://attack.mitre.org/techniques/T1204/002/",
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1059.005": {
        "name": "Command and Scripting Interpreter: Visual Basic",
        "url": "https://attack.mitre.org/techniques/T1059/005/",
    },
    "T1059.003": {
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "url": "https://attack.mitre.org/techniques/T1059/003/",
    },
    "T1547.001": {
        "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "url": "https://attack.mitre.org/techniques/T1547/001/",
    },
    "T1053.005": {
        "name": "Scheduled Task/Job: Scheduled Task",
        "url": "https://attack.mitre.org/techniques/T1053/005/",
    },
    "T1082": {
        "name": "System Information Discovery",
        "url": "https://attack.mitre.org/techniques/T1082/",
    },
    "T1087.001": {
        "name": "Account Discovery: Local Account",
        "url": "https://attack.mitre.org/techniques/T1087/001/",
    },
    "T1087.002": {
        "name": "Account Discovery: Domain Account",
        "url": "https://attack.mitre.org/techniques/T1087/002/",
    },
    "T1018": {
        "name": "Remote System Discovery",
        "url": "https://attack.mitre.org/techniques/T1018/",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "T1078": {
        "name": "Valid Accounts",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1078.002": {
        "name": "Valid Accounts: Domain Accounts",
        "url": "https://attack.mitre.org/techniques/T1078/002/",
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "T1021.001": {
        "name": "Remote Services: Remote Desktop Protocol",
        "url": "https://attack.mitre.org/techniques/T1021/001/",
    },
    "T1021.002": {
        "name": "Remote Services: SMB/Windows Admin Shares",
        "url": "https://attack.mitre.org/techniques/T1021/002/",
    },
    "T1005": {
        "name": "Data from Local System",
        "url": "https://attack.mitre.org/techniques/T1005/",
    },
    "T1074.001": {
        "name": "Data Staged: Local Data Staging",
        "url": "https://attack.mitre.org/techniques/T1074/001/",
    },
    "T1560.001": {
        "name": "Archive Collected Data: Archive via Utility",
        "url": "https://attack.mitre.org/techniques/T1560/001/",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "url": "https://attack.mitre.org/techniques/T1041/",
    },
    "T1048.003": {
        "name": "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol",
        "url": "https://attack.mitre.org/techniques/T1048/003/",
    },
    "T1567.002": {
        "name": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
        "url": "https://attack.mitre.org/techniques/T1567/002/",
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "url": "https://attack.mitre.org/techniques/T1105/",
    },
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "T1505.003": {
        "name": "Server Software Component: Web Shell",
        "url": "https://attack.mitre.org/techniques/T1505/003/",
    },
    "T1543.003": {
        "name": "Create or Modify System Process: Windows Service",
        "url": "https://attack.mitre.org/techniques/T1543/003/",
    },
    "T1219": {
        "name": "Remote Access Software",
        "url": "https://attack.mitre.org/techniques/T1219/",
    },
    "T1569.002": {
        "name": "System Services: Service Execution",
        "url": "https://attack.mitre.org/techniques/T1569/002/",
    },
}


def lookup(technique_id):
    entry = TECHNIQUES[technique_id]
    return {"id": technique_id, "name": entry["name"], "url": entry["url"]}
