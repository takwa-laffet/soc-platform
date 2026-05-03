import re
from urllib.parse import urlparse

import requests

from config import (
    VT_API_KEY,
    ABUSEIPDB_API_KEY,
    OTX_API_KEY,
    THREAT_INTEL_TIMEOUT,
    THREAT_INTEL_MAX_INDICATORS,
)

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
DOMAIN_RE = re.compile(
    r"\b(?=.{1,253}\b)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\b"
)

PRIVATE_IP_PREFIXES = (
    "10.",
    "127.",
    "169.254.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.2",
    "172.30.",
    "172.31.",
    "192.168.",
)


def _safe_get_json(url, headers=None, params=None):
    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=THREAT_INTEL_TIMEOUT,
        )
        if response.status_code >= 400:
            return {
                "ok": False,
                "status": response.status_code,
                "error": response.text[:300],
            }
        return {
            "ok": True,
            "status": response.status_code,
            "data": response.json(),
        }
    except Exception as exc:
        return {"ok": False, "status": 0, "error": str(exc)}


def _normalize_domain(value):
    if not value:
        return ""
    value = value.strip().lower()
    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        return parsed.netloc.lower()
    return value


def _is_public_ipv4(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if any(o < 0 or o > 255 for o in octets):
        return False
    return not ip.startswith(PRIVATE_IP_PREFIXES)


def extract_indicators(log_text):
    ips = []
    domains = []
    hashes = []

    for ip in IPV4_RE.findall(log_text or ""):
        if _is_public_ipv4(ip):
            ips.append(ip)

    for d in DOMAIN_RE.findall(log_text or ""):
        nd = _normalize_domain(d)
        if nd and nd != "localhost":
            domains.append(nd)

    for h in HASH_RE.findall(log_text or ""):
        hashes.append(h.lower())

    # Keep deterministic order while removing duplicates.
    ips = list(dict.fromkeys(ips))[:THREAT_INTEL_MAX_INDICATORS]
    domains = list(dict.fromkeys(domains))[:THREAT_INTEL_MAX_INDICATORS]
    hashes = list(dict.fromkeys(hashes))[:THREAT_INTEL_MAX_INDICATORS]

    return {"ips": ips, "domains": domains, "hashes": hashes}


def vt_lookup(indicator_type, value):
    if not VT_API_KEY:
        return {"enabled": False, "error": "VT_API_KEY not configured"}

    endpoint_map = {
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{value}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{value}",
        "hash": f"https://www.virustotal.com/api/v3/files/{value}",
    }
    url = endpoint_map.get(indicator_type)
    if not url:
        return {"enabled": True, "error": "Unsupported indicator type"}

    result = _safe_get_json(url, headers={"x-apikey": VT_API_KEY})
    if not result.get("ok"):
        return {"enabled": True, "error": result.get("error"), "status": result.get("status")}

    attrs = (result.get("data") or {}).get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)

    return {
        "enabled": True,
        "source": "virustotal",
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "reputation": attrs.get("reputation"),
        "last_analysis_date": attrs.get("last_analysis_date"),
    }


def abuseipdb_lookup(ip):
    if not ABUSEIPDB_API_KEY:
        return {"enabled": False, "error": "ABUSEIPDB_API_KEY not configured"}

    result = _safe_get_json(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
    )
    if not result.get("ok"):
        return {"enabled": True, "error": result.get("error"), "status": result.get("status")}

    data = (result.get("data") or {}).get("data", {})
    return {
        "enabled": True,
        "source": "abuseipdb",
        "abuse_confidence_score": int(data.get("abuseConfidenceScore", 0) or 0),
        "usage_type": data.get("usageType"),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "total_reports": int(data.get("totalReports", 0) or 0),
    }


def otx_lookup(indicator_type, value):
    if not OTX_API_KEY:
        return {"enabled": False, "error": "OTX_API_KEY not configured"}

    endpoint_map = {
        "ip": f"https://otx.alienvault.com/api/v1/indicators/IPv4/{value}/general",
        "domain": f"https://otx.alienvault.com/api/v1/indicators/domain/{value}/general",
        "hash": f"https://otx.alienvault.com/api/v1/indicators/file/{value}/general",
    }
    url = endpoint_map.get(indicator_type)
    if not url:
        return {"enabled": True, "error": "Unsupported indicator type"}

    result = _safe_get_json(url, headers={"X-OTX-API-KEY": OTX_API_KEY})
    if not result.get("ok"):
        return {"enabled": True, "error": result.get("error"), "status": result.get("status")}

    data = result.get("data") or {}
    pulse_info = data.get("pulse_info") or {}
    pulse_count = int(pulse_info.get("count", 0) or 0)

    return {
        "enabled": True,
        "source": "alienvault_otx",
        "pulse_count": pulse_count,
        "country_code": data.get("country_code"),
        "asn": data.get("asn"),
        "reputation": data.get("reputation"),
    }


def _score_indicator(enrichment):
    score = 0
    reasons = []

    vt = enrichment.get("virustotal") or {}
    if vt.get("enabled"):
        malicious = int(vt.get("malicious", 0) or 0)
        suspicious = int(vt.get("suspicious", 0) or 0)
        if malicious > 0:
            score += min(70, malicious * 10)
            reasons.append(f"VirusTotal malicious detections: {malicious}")
        if suspicious > 0:
            score += min(25, suspicious * 5)
            reasons.append(f"VirusTotal suspicious detections: {suspicious}")

    abuse = enrichment.get("abuseipdb") or {}
    if abuse.get("enabled"):
        abuse_score = int(abuse.get("abuse_confidence_score", 0) or 0)
        if abuse_score >= 80:
            score += 60
            reasons.append(f"AbuseIPDB confidence score is very high ({abuse_score})")
        elif abuse_score >= 40:
            score += 35
            reasons.append(f"AbuseIPDB confidence score is elevated ({abuse_score})")
        elif abuse_score > 0:
            score += 10

    otx = enrichment.get("alienvault_otx") or {}
    if otx.get("enabled"):
        pulse_count = int(otx.get("pulse_count", 0) or 0)
        if pulse_count > 0:
            score += min(40, pulse_count * 4)
            reasons.append(f"AlienVault OTX pulse hits: {pulse_count}")

    if score >= 90:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"

    return score, level, reasons


def enrich_indicator(indicator_type, value):
    enrichment = {
        "indicator_type": indicator_type,
        "value": value,
        "virustotal": vt_lookup(indicator_type, value),
        "alienvault_otx": otx_lookup(indicator_type, value),
    }

    if indicator_type == "ip":
        enrichment["abuseipdb"] = abuseipdb_lookup(value)

    score, level, reasons = _score_indicator(enrichment)
    enrichment["context"] = {
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons,
        "recommendation": (
            "Escalate and isolate immediately" if level in {"critical", "high"}
            else "Monitor and correlate with additional telemetry"
        ),
    }
    return enrichment


def enrich_log(log_text, manual_indicators=None):
    extracted = extract_indicators(log_text)
    manual_indicators = manual_indicators or {}

    all_indicators = {
        "ips": list(dict.fromkeys(extracted["ips"] + (manual_indicators.get("ips") or [])))[:THREAT_INTEL_MAX_INDICATORS],
        "domains": list(dict.fromkeys(extracted["domains"] + [_normalize_domain(d) for d in (manual_indicators.get("domains") or []) if d]))[:THREAT_INTEL_MAX_INDICATORS],
        "hashes": list(dict.fromkeys(extracted["hashes"] + [h.lower() for h in (manual_indicators.get("hashes") or []) if h]))[:THREAT_INTEL_MAX_INDICATORS],
    }

    enriched = []
    for ip in all_indicators["ips"]:
        enriched.append(enrich_indicator("ip", ip))
    for domain in all_indicators["domains"]:
        enriched.append(enrich_indicator("domain", domain))
    for file_hash in all_indicators["hashes"]:
        enriched.append(enrich_indicator("hash", file_hash))

    high_risk = [i for i in enriched if i.get("context", {}).get("risk_level") in {"critical", "high"}]
    medium_risk = [i for i in enriched if i.get("context", {}).get("risk_level") == "medium"]

    return {
        "indicators": all_indicators,
        "results": enriched,
        "summary": {
            "total": len(enriched),
            "critical_or_high": len(high_risk),
            "medium": len(medium_risk),
            "low": len(enriched) - len(high_risk) - len(medium_risk),
        },
    }
