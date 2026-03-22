import re
from datetime import datetime

LATERAL_INDICATORS = [
    "psexec",
    "wmiexec",
    "winrm",
    "invoke-command",
    "enter-pssession",
    "net use",
    "at \\\\",
    "schtasks /s",
    "mimikatz",
    "pass the hash",
    "overpass the hash",
    "dcom",
    "rdp",
    "xfreerdp",
    "rdesktop",
]

def analyze(log):
    findings = []
    log_lower = log.lower()

    matched = [i for i in LATERAL_INDICATORS if i in log_lower]

    if not matched:
        return []

    severity = "Critical" if len(matched) >= 2 else "High"

    ips = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", log)
    domains = re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b", log)

    findings.append({
        "timestamp": datetime.utcnow().isoformat(),
        "severity": severity,
        "technique": "T1021",
        "description": f"Lateral movement detected: {', '.join(matched)}",
        "mitre_phase": "Lateral Movement",
        "iocs": {"ips": ips, "domains": domains, "indicators": matched}
    })

    return findings
