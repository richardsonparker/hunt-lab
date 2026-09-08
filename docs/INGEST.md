# INGEST.md -- Splunk Setup

## 0. Generate the dataset

If `dataset/` doesn't exist yet (it isn't committed to source control -- see `.gitignore`), generate it first:

```bash
python generate.py --seed <n> --target-size 400MB
python generate.py --smoke-test   # fast ~8MB run to sanity-check the pipeline
```

## 1. Create the index

Copy `splunk/indexes.conf`, `splunk/props.conf`, and `splunk/transforms.conf` into an app directory, e.g.:

```bash
mkdir -p $SPLUNK_HOME/etc/apps/hunt_lab/{default,dataset}
cp splunk/*.conf $SPLUNK_HOME/etc/apps/hunt_lab/default/
cp dataset/* $SPLUNK_HOME/etc/apps/hunt_lab/dataset/
$SPLUNK_HOME/bin/splunk restart
```

## 2. Load the data

Restarting Splunk with `inputs.conf` in place monitors the files automatically. For a one-time
load instead of continuous monitoring, use `splunk add oneshot` per file:

```bash
$SPLUNK_HOME/bin/splunk add oneshot dataset/fortigate.log -index hunt_lab -sourcetype fortigate
$SPLUNK_HOME/bin/splunk add oneshot dataset/sysmon.jsonl -index hunt_lab -sourcetype sysmon:json
$SPLUNK_HOME/bin/splunk add oneshot dataset/windows_security.jsonl -index hunt_lab -sourcetype wineventlog:security:json
$SPLUNK_HOME/bin/splunk add oneshot dataset/windows_system.jsonl -index hunt_lab -sourcetype wineventlog:system:json
$SPLUNK_HOME/bin/splunk add oneshot dataset/powershell.jsonl -index hunt_lab -sourcetype powershell:json
```

## 3. Verify

```spl
index=hunt_lab | stats count by sourcetype
```
```spl
index=hunt_lab | timechart span=1h count by sourcetype
```
```spl
index=hunt_lab sourcetype=sysmon:json | stats count by EventCode
```

## 4. Cleaning up / switching to a different seed

Every run of `generate.py` deletes and rewrites everything under `dataset/` for you automatically -- you never need to clean that folder by hand before regenerating.

There are two separate things people mean by "delete the dataset," and they need different commands:

**A. Delete the local `dataset/` folder on disk** -- e.g. to tidy up before
committing this project to git (`dataset/` is already covered by `.gitignore`,
so this is just housekeeping, not required for git safety):

```powershell
cd path\to\this\project      # make sure you are NOT already inside dataset\
Remove-Item -Recurse -Force .\dataset
```

If that fails with an error, you are almost certainly still `cd`'d inside `dataset\` itself -- Windows refuses to delete a folder that is your shell's current location. Run `cd ..` first, then retry.

## 5. Porting to a different SIEM

The dataset itself (`dataset/*`) is SIEM-agnostic -- plain `key=value` syslog for FortiGate and newline-delimited JSON with native Sysmon/Windows Event Log field names for everything else -- so only the ingest-time parsing config needs to be rewritten (e.g. an Elastic ingest pipeline or Sentinel DCR) in place of `splunk/props.conf`/`transforms.conf`.

The one behavior to reproduce: each JSONL file interleaves events from every host in the environment, so the source host must be extracted per-record from the JSON `host` field (or `devname=` for FortiGate) rather than assumed from the file or input itself.

**B. Delete the data already loaded INTO Splunk's `hunt_lab` index** -- needed
when you regenerate with a *different* seed and don't want the new incident
mixed together with the old one inside Splunk. This is separate from (A) and
is **irreversible**:

```powershell
& "$SPLUNK_HOME\bin\splunk.exe" clean eventdata -index hunt_lab
```

Example end-to-end workflow for switching to a new seed cleanly:

```powershell
python generate.py --seed 4 --target-size 400MB   # overwrites dataset/ with the new incident
& "$SPLUNK_HOME\bin\splunk.exe" clean eventdata -index hunt_lab   # wipe the old incident out of Splunk
& "$SPLUNK_HOME\bin\splunk.exe" add oneshot .\dataset\fortigate.log -index hunt_lab -sourcetype fortigate
# ...repeat the oneshot command for the other four dataset files (see Section 2)
```

