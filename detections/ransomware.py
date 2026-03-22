import re
from datetime import datetime

RANSOMWARE_INDICATORS = [
    "vssadmin delete shadows",
    "bcdedit /set recoveryenabled no",
    "wbadmin delete catalog",
    "cipher /w",
    ".locked", ".encrypted", ".crypto", ".crypt",
    "readme_to_decrypt",
    "your_files_are_encrypted",
    "wmic shadowcopy delete",
    "taskkill /f /im",
    "net stop",
]

def analyze(log):
    findings = []
    log_lower = log.lower()

    matched = [i for i in RANSOMWARE_INDICATORS if i in log_lower]

    if len(matched) >= 2:
        severity = "Critical"
    elif len(matched) == 1:
        severity = "High"
    else:
        return []

    ips = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", log)
    domains = re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b", log)

    findings.append({
        "timestamp": datetime.utcnow().isoformat(),
        "severity": severity,
        "technique": "T1486",
        "description": f"Ransomware behavior detected: {', '.join(matched)}",
        "mitre_phase": "Impact",
        "iocs": {"ips": ips, "domains": domains, "indicators": matched}
    })

    return findings
