import re
from datetime import datetime

EXFIL_INDICATORS = [
    "curl -d", "wget --post", "invoke-webrequest",
    "certutil -encode", "base64", "ftp ", "scp ",
    "rclone", "mega.nz", "pastebin.com",
    "transfer.sh", "ngrok", "dnscat", "data exfil",
]

WHITELIST_IPS = [
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168."
]

WHITELIST_DOMAINS = [
    "amazonaws.com", "amazon.com", "aws.amazon.com",
    "cloudtrail.amazonaws.com", "lambda.amazonaws.com",
    "sts.amazonaws.com", "kms.amazonaws.com",
    "logs.amazonaws.com", "s3.amazonaws.com",
    "resource-explorer-2.amazonaws.com",
    "guardduty.amazonaws.com"
]

WHITELIST_LOG_SOURCES = [
    "cloudtrail.amazonaws.com",
    "resource-explorer-2.amazonaws.com",
    "\"eventsource\": \"lambda.amazonaws.com\"",
    "AWSServiceRoleFor",
    "CLOUDWATCH_LOGS_DELIVERY"
]

def is_aws_internal(log):
    return any(source in log for source in WHITELIST_LOG_SOURCES)

def analyze(log):
    if is_aws_internal(log):
        return []

    findings = []
    log_lower = log.lower()
    matched = [i for i in EXFIL_INDICATORS if i in log_lower]

    if not matched:
        return []

    severity = "Critical" if len(matched) >= 2 else "High"

    ips = [ip for ip in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", log)
           if not any(ip.startswith(w) for w in WHITELIST_IPS)]

    domains = [d for d in re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b", log)
               if not any(w in d for w in WHITELIST_DOMAINS)]

    findings.append({
        "timestamp": datetime.utcnow().isoformat(),
        "severity": severity,
        "technique": "T1041",
        "description": f"Data exfiltration attempt detected: {', '.join(matched)}",
        "mitre_phase": "Exfiltration",
        "iocs": {"ips": ips, "domains": domains, "indicators": matched}
    })

    return findings
