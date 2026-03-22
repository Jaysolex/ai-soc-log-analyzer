import re
from datetime import datetime

EXFIL_INDICATORS = [
    "curl -d",
    "wget --post",
    "invoke-webrequest",
    "certutil -encode",
    "base64",
    "ftp ",
    "scp ",
    "rclone",
    "mega.nz",
    "pastebin.com",
    "transfer.sh",
    "ngrok",
    "dnscat",
    "data exfil",
]

def analyze(log):
    findings = []
    log_lower = log.lower()

    matched = [i for i in EXFIL_INDICATORS if i in log_lower]

    if not matched:
        return []

    severity = "Critical" if len(matched) >= 2 else "High"

    ips = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", log)
    domains = re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b", log)

    findings.append({
        "timestamp": datetime.utcnow().isoformat(),
        "severity": severity,
        "technique": "T1041",
        "description": f"Data exfiltration attempt detected: {', '.join(matched)}",
        "mitre_phase": "Exfiltration",
        "iocs": {"ips": ips, "domains": domains, "indicators": matched}
    })

    return findings
