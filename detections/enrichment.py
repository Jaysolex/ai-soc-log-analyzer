import json
import urllib.request
import urllib.parse
import os
from datetime import datetime

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")
VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_KEY", "")
SHODAN_KEY = os.environ.get("SHODAN_KEY", "")

def check_abuseipdb(ip):
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={
            "Key": ABUSEIPDB_KEY,
            "Accept": "application/json"
        })
        with urllib.request.urlopen(req, timeout=5) as res:
            data = json.loads(res.read())["data"]
            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", "unknown"),
                "total_reports": data.get("totalReports", 0),
                "is_tor": data.get("isTor", False)
            }
    except Exception as e:
        return {"error": str(e)}

def check_virustotal(ioc):
    try:
        encoded = urllib.parse.quote(ioc, safe="")
        url = f"https://www.virustotal.com/api/v3/search?query={encoded}"
        req = urllib.request.Request(url, headers={
            "x-apikey": VIRUSTOTAL_KEY
        })
        with urllib.request.urlopen(req, timeout=5) as res:
            data = json.loads(res.read())
            stats = data.get("data", [{}])[0].get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)
            }
    except Exception as e:
        return {"error": str(e)}

def check_shodan(ip):
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as res:
            data = json.loads(res.read())
            return {
                "open_ports": data.get("ports", []),
                "org": data.get("org", "unknown"),
                "country": data.get("country_name", "unknown"),
                "vulns": list(data.get("vulns", {}).keys())
            }
    except Exception as e:
        return {"error": str(e)}

def enrich(findings):
    enriched = []
    for finding in findings:
        iocs = finding.get("iocs", {})
        ips = iocs.get("ips", [])
        domains = iocs.get("domains", [])

        intel = {}

        for ip in ips:
            intel[ip] = {
                "abuseipdb": check_abuseipdb(ip) if ABUSEIPDB_KEY else "no key",
                "shodan": check_shodan(ip) if SHODAN_KEY else "no key",
                "virustotal": check_virustotal(ip) if VIRUSTOTAL_KEY else "no key"
            }

        for domain in domains:
            intel[domain] = {
                "virustotal": check_virustotal(domain) if VIRUSTOTAL_KEY else "no key"
            }

        finding["threat_intel"] = intel
        finding["enriched_timestamp"] = datetime.utcnow().isoformat()
        enriched.append(finding)

    return enriched
