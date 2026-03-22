import re
import json
from datetime import datetime

# PowerShell process-behavior detection
# Maps suspicious command-line usage to MITRE ATT&CK technique T1059.001

def analyze(log: str) -> dict:
    """
    Detects PowerShell misuse patterns, extracts IOCs, and returns a structured finding
    that the main Lambda function can aggregate or send to Bedrock for summarization.
    """

    findings = []
    log_lower = log.lower()

    # IOC extraction (simple regex pass)
    ips = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", log)
    domains = re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b", log)
    hashes = re.findall(r"\b[a-fA-F0-9]{32,64}\b", log)

    indicators = {
        "ips": ips,
        "domains": domains,
        "hashes": hashes
    }

    # Detection logic
    suspicious_flags = ["-nop", "-w hidden", "-enc", "invoke-expression", "iex"]
    if any(flag in log_lower for flag in suspicious_flags):
        finding = {
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "High",
            "technique": "T1059.001",
            "description": "Suspicious PowerShell execution with obfuscation or encoded command.",
            "iocs": indicators,
            "mitre_phase": "Execution"
        }
        findings.append(finding)

    # If no detection, return informational result
    if not findings:
        findings.append({
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "Informational",
            "technique": "None",
            "description": "No suspicious PowerShell activity detected.",
            "iocs": indicators
        })

    return findings


if __name__ == "__main__":
    sample_log = "powershell -nop -w hidden -enc SQBmACgA connecting 185.22.45.90 example.com"
    output = analyze(sample_log)
    print(json.dumps(output, indent=2))
