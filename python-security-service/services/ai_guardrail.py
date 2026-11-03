import re
import time


def inspect_ai_payload(payload: dict) -> dict:
    """
    Module 7: OWASP Top 10 for LLM Applications Guardrail Inspector.
    Detects Prompt Injection (LLM01), Secret/API Key Leakage (LLM02),
    PII Exposure (LLM02), and Unsafe Executable Output / XSS (LLM05).
    """
    start = time.time()
    prompt = str(payload.get("prompt") or "")
    response = payload.get("response")
    sanitized_prompt = prompt
    sanitized_response = str(response) if response is not None else None
    stage = payload.get("stage", "FULL_INTERACTION")

    violations = []
    owasp_categories = set()
    risk_score = 0.05

    # 1. OWASP LLM01: Prompt Injection & Jailbreak Detection
    injection_rules = [
        (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)", "Direct Instruction Override Attempt"),
        (r"(system\s*prompt|reveal\s+your\s+instructions|developer\s+mode|DAN\s+mode)", "System Prompt Extraction / Jailbreak Attempt"),
        (r"(bypass\s+security|act\s+as\s+an?\s+unrestricted|disregard\s+safety)", "Safety Policy Bypass Attempt"),
    ]
    for pattern, detail in injection_rules:
        if re.search(pattern, sanitized_prompt, re.IGNORECASE):
            violations.append({
                "type": "PROMPT_INJECTION",
                "owasp": "LLM01:2025 Prompt Injection",
                "severity": "CRITICAL",
                "detail": detail
            })
            owasp_categories.add("LLM01: Prompt Injection")
            risk_score = max(risk_score, 0.95)

    # 2. OWASP LLM02: API Key & Cloud Secret Leakage Detection + Redaction
    secret_rules = [
        (r"\b(AKIA[0-9A-Z]{16})\b", "AWS IAM Access Key ID", "AKIA****************[REDACTED]"),
        (r"\b(sk-[a-zA-Z0-9_-]{20,})\b", "OpenAI / LLM Secret API Key", "sk-********************[REDACTED]"),
        (r"\b(ghp_[a-zA-Z0-9]{30,})\b", "GitHub Personal Access Token", "ghp_********************[REDACTED]"),
        (r"\b(AIza[0-9A-Za-z-_]{35})\b", "Google Cloud / Gemini API Key", "AIza********************[REDACTED]"),
    ]
    for pattern, name, repl in secret_rules:
        if re.search(pattern, sanitized_prompt):
            violations.append({
                "type": "API_KEY_LEAKAGE",
                "owasp": "LLM02:2025 Sensitive Information Disclosure",
                "severity": "CRITICAL",
                "detail": f"{name} detected in prompt"
            })
            owasp_categories.add("LLM02: Sensitive Information Disclosure")
            sanitized_prompt = re.sub(pattern, repl, sanitized_prompt)
            risk_score = max(risk_score, 0.96)

        if sanitized_response and re.search(pattern, sanitized_response):
            violations.append({
                "type": "API_KEY_LEAKAGE_IN_OUTPUT",
                "owasp": "LLM02:2025 Sensitive Information Disclosure",
                "severity": "CRITICAL",
                "detail": f"{name} leaked in LLM output"
            })
            owasp_categories.add("LLM02: Sensitive Information Disclosure")
            sanitized_response = re.sub(pattern, repl, sanitized_response)
            risk_score = max(risk_score, 0.96)

    # 3. OWASP LLM02: PII Redaction (SSN & Email)
    pii_rules = [
        (r"\b\d{3}-\d{2}-\d{4}\b", "US Social Security Number (SSN)", "[REDACTED_SSN]"),
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "Email Address PII", "[REDACTED_EMAIL]"),
    ]
    for pattern, name, repl in pii_rules:
        if re.search(pattern, sanitized_prompt):
            violations.append({
                "type": "PII_EXPOSURE",
                "owasp": "LLM02:2025 Sensitive Information Disclosure",
                "severity": "HIGH",
                "detail": f"{name} detected and redacted"
            })
            owasp_categories.add("LLM02: Sensitive Information Disclosure")
            sanitized_prompt = re.sub(pattern, repl, sanitized_prompt)
            risk_score = max(risk_score, 0.78)

    # 4. OWASP LLM05: Improper Output Handling (XSS)
    combined = f"{sanitized_prompt} {sanitized_response or ''}"
    if re.search(r"<script[\s>]|javascript:|onerror\s*=", combined, re.IGNORECASE):
        violations.append({
            "type": "UNSAFE_EXECUTABLE_OUTPUT_XSS",
            "owasp": "LLM05:2025 Improper Output Handling",
            "severity": "HIGH",
            "detail": "Executable XSS script tag detected"
        })
        owasp_categories.add("LLM05: Improper Output Handling")
        risk_score = max(risk_score, 0.88)
        if sanitized_response:
            sanitized_response = re.sub(
                r"<script[\s\S]*?>[\s\S]*?</script>",
                "[REMOVED_UNSAFE_SCRIPT]",
                sanitized_response,
                flags=re.IGNORECASE
            )

    verdict = "ALLOWED"
    if any(v["type"] in ("PROMPT_INJECTION", "UNSAFE_EXECUTABLE_OUTPUT_XSS") for v in violations):
        verdict = "BLOCKED"
    elif any("API_KEY" in v["type"] or "PII" in v["type"] for v in violations):
        verdict = "REDACTED"
    elif violations:
        verdict = "FLAGGED"

    latency_ms = max(1, int((time.time() - start) * 1000))
    return {
        "verdict": verdict,
        "allowed": verdict != "BLOCKED",
        "risk_score": round(risk_score, 2),
        "stage": stage,
        "owasp_llm_categories": list(owasp_categories),
        "detected_violations": violations,
        "sanitized_prompt": sanitized_prompt,
        "sanitized_response": sanitized_response,
        "latency_ms": latency_ms
    }
