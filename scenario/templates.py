"""
Validated attack templates.

Each template is a documented, non-zero-day attacker behavior chain grounded
in MITRE ATT&CK / CISA / Microsoft / Mandiant reporting patterns. The seed
selects one template; templates.py never assembles a chain from randomly
sampled techniques. Concrete event construction for each template lives in
scenario/timeline.py (one builder function per template id) so the metadata
here stays purely descriptive.
"""

TEMPLATES = [
    {
        "id": "phishing_macro_lateral_smb",
        "name": "Phishing Attachment to SMB Lateral Movement",
        "summary": (
            "A user opens a malicious Office attachment delivered by email. "
            "A macro launches PowerShell, which establishes registry run-key "
            "persistence, performs local/domain discovery, and reuses a "
            "captured account to move laterally to the file server over SMB, "
            "where data is staged and archived before a small exfiltration "
            "burst to an external host."
        ),
        "techniques": [
            {"stage": "initial_access", "id": "T1566.001"},
            {"stage": "execution", "id": "T1204.002"},
            {"stage": "execution", "id": "T1059.005"},
            {"stage": "execution", "id": "T1059.001"},
            {"stage": "persistence", "id": "T1547.001"},
            {"stage": "discovery", "id": "T1082"},
            {"stage": "discovery", "id": "T1087.002"},
            {"stage": "discovery", "id": "T1018"},
            {"stage": "lateral_movement", "id": "T1021.002"},
            {"stage": "collection", "id": "T1005"},
            {"stage": "staging", "id": "T1074.001"},
            {"stage": "staging", "id": "T1560.001"},
            {"stage": "exfiltration", "id": "T1041"},
        ],
    },
]


def select_template(seed):
    return TEMPLATES[0]
