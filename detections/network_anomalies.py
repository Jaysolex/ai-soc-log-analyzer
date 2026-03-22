import re, json
from datetime import datetime

def analyze(log: str):
    findings = []
    log_lower = log.lower()

    ips = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", log)
    domains = re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b", log)

    # Port scan
    if "nmap" in log_lower or "masscan" in log_lower:
        findings.append({
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "Medium",
            "technique": "T1046",
            "description": "Possible port scanning activity detected.",
            "iocs": {"ips": ips, "domains": domains}
        })

    # Beacon behavior (periodic HTTP)
    if "GET /status" in log and "repeat" in log_lower:
        findings.append({
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "High",
            "technique": "T1071",
            "description": "Command-and-control beaconing pattern.",
            "iocs": {"ips": ips, "domains": domains}
        })

    if not findings:
        findings.append({
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "Informational",
            "description": "No network anomalies detected.",
            "iocs": {"ips": ips, "domains": domains}
        })
    return findings
