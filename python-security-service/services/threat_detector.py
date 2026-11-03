import re


ATTACK_SIGNATURES = [
    (
        "SQL_INJECTION_ATTEMPT",
        "CRITICAL",
        0.96,
        r"(\bUNION\b\s+\bSELECT\b|'?\s*OR\s+['\"]?1['\"]?\s*=\s*['\"]?1|--\s*$|;\s*DROP\s+TABLE|SLEEP\(\d+\))",
        "SQL Injection payload signature detected in request parameters or body."
    ),
    (
        "XSS_ATTACK_ATTEMPT",
        "HIGH",
        0.93,
        r"(<script[\s>]|javascript:|onerror\s*=|onload\s*=|document\.cookie|alert\()",
        "Cross-Site Scripting (XSS) script injection payload detected."
    ),
    (
        "PATH_TRAVERSAL_OR_LFI",
        "HIGH",
        0.91,
        r"(\.\./|\.\.\\|/etc/passwd|/proc/self/environ|win\.ini)",
        "Directory Traversal / Local File Inclusion (LFI) probe detected."
    ),
    (
        "COMMAND_INJECTION_ATTEMPT",
        "CRITICAL",
        0.94,
        r"(;\s*(?:cat|ls|whoami|curl|wget|bash|sh|nc)\b|\|\|\s*(?:id|uname)|\$\((?:whoami|id)\))",
        "OS Command Injection metacharacter sequence detected."
    ),
]


def analyze_threat_telemetry(payload: dict) -> dict:
    """
    Module 4: Python Threat Detection & Anomaly Scoring Engine.
    Evaluates log telemetry using:
    1) Deterministic Signature Matching (SQLi, XSS, LFI, Command Injection)
    2) Rule-Based Threshold Evaluation (Failed Login Bursts)
    3) Statistical Z-Score / Anomaly Detection (Abnormal Request Rate Spikes)
    """
    source_ip = payload.get("sourceIp", "203.0.113.55")
    endpoint = payload.get("endpoint", "/api/v1/auth/login")
    http_method = payload.get("httpMethod", "POST")
    status_code = int(payload.get("statusCode", 200))
    raw_body = str(payload.get("payload", ""))
    user_agent = str(payload.get("userAgent", "Mozilla/5.0"))
    event_count = max(1, int(payload.get("eventCount", 1)))
    baseline_rpm = float(payload.get("baselineRpm", 15.0))
    baseline_std = float(payload.get("baselineStd", 5.0))

    combined_text = f"{endpoint} {raw_body} {user_agent}"
    detections = []

    # 1. Signature Evaluation
    for threat_type, severity, confidence, pattern, desc in ATTACK_SIGNATURES:
        if re.search(pattern, combined_text, re.IGNORECASE):
            detections.append({
                "threatType": threat_type,
                "detectionMethod": "SIGNATURE",
                "severity": severity,
                "confidenceScore": confidence,
                "description": f"{desc} Source IP: {source_ip} targeting {http_method} {endpoint}."
            })

    # 2. Rule-Based Failed Authentication Threshold
    if status_code in (401, 403) and event_count >= 8:
        detections.append({
            "threatType": "BRUTE_FORCE_CREDENTIAL_ATTACK",
            "detectionMethod": "RULE_THRESHOLD",
            "severity": "CRITICAL" if event_count >= 15 else "HIGH",
            "confidenceScore": 0.95,
            "description": f"Threshold rule triggered: {event_count} failed authentication attempts from {source_ip} targeting {endpoint}."
        })

    # 3. Statistical Z-Score Anomaly Detection
    z_score = (event_count - baseline_rpm) / max(1.0, baseline_std)
    if z_score >= 4.0 or event_count >= 100:
        detections.append({
            "threatType": "ABNORMAL_TRAFFIC_DDOS_ANOMALY",
            "detectionMethod": "ML_ANOMALY",
            "severity": "CRITICAL",
            "confidenceScore": round(min(0.99, 0.75 + (z_score / 40.0)), 2),
            "zScore": round(z_score, 2),
            "description": f"Statistical anomaly detected (Z-score={round(z_score, 2)}): {event_count} events from {source_ip} targeting {endpoint}."
        })

    return {
        "sourceIp": source_ip,
        "endpoint": endpoint,
        "eventCount": event_count,
        "anomalyZScore": round(z_score, 2),
        "detections": detections
    }
