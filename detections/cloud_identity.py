from datetime import datetime

def analyze(log: str):
    findings = []
    lower = log.lower()

    if "assumerole" in lower and "admin" in lower:
        findings.append({
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "High",
            "technique": "T1098",
            "description": "Privileged role assumption – possible credential abuse."
        })

    if "deactivatemfadevice" in lower:
        findings.append({
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "Critical",
            "technique": "T1110",
            "description": "MFA disabled on account."
        })

    if not findings:
        findings.append({
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "Informational",
            "description": "No identity anomalies detected."
        })
    return findings
