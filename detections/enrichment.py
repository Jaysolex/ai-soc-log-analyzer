from datetime import datetime

def enrich(findings):
    """
    Mock enrichment step: adds fake threat reputation fields
    so Lambda output shows integrated threat intel even offline.
    """
    for f in findings:
        f["threat_intel"] = {
            "malicious": 0,
            "suspicious": 0,
            "reputation": "unknown"
        }
        f["enriched_timestamp"] = datetime.utcnow().isoformat()
    return findings
