import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from services.scanner_engine import run_vulnerability_scan
from services.cloud_inspector import run_cloud_posture_scan
from services.ai_guardrail import inspect_ai_payload
from services.ai_advisor import analyze_security_finding
from services.threat_detector import analyze_threat_telemetry

PORT = int(os.environ.get("PYTHON_SERVICE_PORT", "8000"))
INTERNAL_SECRET = os.environ.get(
    "INTERNAL_SERVICE_SECRET",
    "secplatform_internal_hmac_secret_change_in_prod_9f8a7b6c5d4e3f2a"
)


def dispatch_internal_request(method: str, path: str, headers: dict, payload: dict) -> tuple[int, dict]:
    """
    Core request router for the Python Security & AI Microservice.
    Enforces internal service authentication and dispatches to the specialized security engines.
    """
    if method == "GET":
        if path == "/health":
            return 200, {
                "status": "UP",
                "service": "aegis-python-security-ai-microservice",
                "capabilities": [
                    "SSL_TLS_SCANNER",
                    "HTTP_HEADER_SCANNER",
                    "TCP_PORT_SCANNER",
                    "OSV_DEPENDENCY_SCANNER",
                    "MULTI_CLOUD_CSPM_INSPECTOR",
                    "THREAT_SIGNATURE_AND_ANOMALY_ENGINE",
                    "AI_REMEDIATION_ADVISOR",
                    "OWASP_LLM_GUARDRAIL"
                ]
            }
        return 404, {"error": "NOT_FOUND"}

    if method == "POST":
        header_secret = headers.get("X-Internal-Service-Secret") or headers.get("x-internal-service-secret") or ""
        if header_secret != INTERNAL_SECRET:
            return 403, {"error": "FORBIDDEN_INTERNAL_SECRET"}

        try:
            if path == "/internal/scan/vulnerability":
                return 200, run_vulnerability_scan(payload)
            elif path == "/internal/scan/cloud":
                return 200, run_cloud_posture_scan(payload)
            elif path == "/internal/ai/analyze-finding":
                return 200, analyze_security_finding(payload)
            elif path == "/internal/ai-security/inspect":
                return 200, inspect_ai_payload(payload)
            elif path == "/internal/threat/analyze":
                return 200, analyze_threat_telemetry(payload)
            else:
                return 404, {"error": "ENDPOINT_NOT_FOUND"}
        except Exception as exc:
            return 400, {"error": "EXECUTION_ERROR", "message": str(exc)}

    return 405, {"error": "METHOD_NOT_ALLOWED"}


class SecurityServiceHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        if os.environ.get("QUIET_LOGS") == "1":
            return
        super().log_message(format, *args)

    def _send_json(self, status_code: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        status, data = dispatch_internal_request("GET", self.path, dict(self.headers), {})
        return self._send_json(status, data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            payload = json.loads(raw_body)
        except Exception:
            return self._send_json(400, {"error": "INVALID_JSON"})

        status, data = dispatch_internal_request("POST", self.path, dict(self.headers), payload)
        return self._send_json(status, data)


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 4 and sys.argv[1] == "--cli-dispatch":
        endpoint_path = sys.argv[2]
        raw_payload = sys.argv[3]
        try:
            payload_obj = json.loads(raw_payload)
        except Exception:
            payload_obj = {}
        status_code, response_data = dispatch_internal_request(
            "POST",
            endpoint_path,
            {"X-Internal-Service-Secret": INTERNAL_SECRET},
            payload_obj
        )
        print(json.dumps({"status": status_code, "data": response_data}))
        sys.exit(0 if status_code < 400 else 1)

    server = ThreadingHTTPServer(("0.0.0.0", PORT), SecurityServiceHandler)
    print(f"[AegisCloud Python Security & AI Service] Listening on http://0.0.0.0:{PORT}")
    server.serve_forever()

