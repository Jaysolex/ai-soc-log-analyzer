import json
import re
import os
import urllib.request
from datetime import datetime

# 🔐 Secure API key from environment
VT_API_KEY = os.getenv("VT_API_KEY", "")


# ---------------------------
# IOC EXTRACTION
# ---------------------------
def extract_iocs(text):
    return {
        "ips": re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", text),
        "domains": re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}\b", text),
        "hashes": re.findall(r"\b[a-fA-F0-9]{32,64}\b", text)
    }


# ---------------------------
# MITRE MAPPING
# ---------------------------
def map_mitre(log_text):
    techniques = {
        "powershell -nop": "T1059.001",
        "rundll32": "T1085",
        "nmap": "T1046"
    }

    for key, tech in techniques.items():
        if key in log_text.lower():
            return tech

    return "Unknown"


# ---------------------------
# VIRUSTOTAL LOOKUP
# ---------------------------
def vt_lookup(ioc_type, value):
    if not VT_API_KEY:
        return {"error": "No VT_API_KEY configured"}

    try:
        url_map = {
            "ips": f"https://www.virustotal.com/api/v3/ip_addresses/{value}",
            "domains": f"https://www.virustotal.com/api/v3/domains/{value}",
            "hashes": f"https://www.virustotal.com/api/v3/files/{value}"
        }

        url = url_map[ioc_type]

        req = urllib.request.Request(
            url,
            headers={"x-apikey": VT_API_KEY}
        )

        with urllib.request.urlopen(req, timeout=6) as response:
            data = json.loads(response.read().decode())

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        # 🔥 SOC intelligence logic
        if malicious > 3:
            reputation = "malicious"
        elif malicious > 0 or suspicious > 0:
            reputation = "suspicious"
        else:
            reputation = "clean"

        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "reputation": reputation
        }

    except Exception as e:
        return {"error": str(e)}


# ---------------------------
# MAIN HANDLER
# ---------------------------
def lambda_handler(event, context):
    log_text = event.get("log", "")

    iocs = extract_iocs(log_text)
    mitre_code = map_mitre(log_text)

    # 🔥 Threat intel enrichment
    threat_intel = {}

    for ioc_type, values in iocs.items():
        for v in values:
            threat_intel[v] = vt_lookup(ioc_type, v)

    # 🔥 ADVANCED SEVERITY LOGIC (NEW)
    severity = "Informational"

    if mitre_code != "Unknown":
        severity = "High"

    for intel in threat_intel.values():
        if intel.get("reputation") == "malicious":
            severity = "Critical"
            break
        elif intel.get("reputation") == "suspicious" and severity != "Critical":
            severity = "Medium"

    response = {
        "severity": severity,
        "technique": mitre_code,
        "summary": "SOC analysis with threat intel enrichment",
        "iocs": iocs,
        "threat_intel": threat_intel,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    print("Analysis complete:", json.dumps(response, indent=2))

    return {
        "statusCode": 200,
        "body": json.dumps(response)
    }