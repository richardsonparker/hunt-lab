# Threat Hunt Brief

Suspicious activity may have occurred in this environment. Investigate the available telemetry, determine what happened, identify affected systems and accounts, reconstruct the timeline, and map confirmed behaviors to MITRE ATT&CK.

## Organization: Brightfield Partners

Domain: `brightfield.local`

| Hostname | IP | Role | OS |
|---|---|---|---|
| FGT-EDGE01 | 10.42.1.176 | firewall | FortiOS 7.4 |
| DC01 | 10.42.5.200 | domain controller | Windows Server 2022 |
| FS01 | 10.42.5.132 | file server | Windows Server 2022 |
| WKS01 | 10.42.20.85 | workstation | Windows 10 22H2 |
| WKS02 | 10.42.20.225 | workstation | Windows 11 23H2 |
| WKS03 | 10.42.20.33 | workstation | Windows 11 23H2 |
| WKS04 | 10.42.20.170 | workstation | Windows 11 23H2 |
| WKS05 | 10.42.20.117 | workstation | Windows 10 22H2 |
| WKS06 | 10.42.20.176 | workstation | Windows 11 23H2 |

## Data sources

| Sourcetype | Index | Description |
|---|---|---|
| `fortigate` | hunt_lab | FortiGate perimeter firewall traffic log |
| `sysmon:json` | hunt_lab | Endpoint process, network, file, registry, DNS telemetry |
| `wineventlog:security:json` | hunt_lab | Windows authentication and process-creation audit events |
| `wineventlog:system:json` | hunt_lab | Windows service and system events |
| `powershell:json` | hunt_lab | PowerShell module and script block logging |

See [INGEST.md](INGEST.md) for setup instructions.

## Verification searches

```spl
index=hunt_lab | stats count by sourcetype
```
```spl
index=hunt_lab | timechart span=1h count by sourcetype
```

If you get stuck, `solution/WALKTHROUGH.md` is available as a reference -- try the hunt first.
