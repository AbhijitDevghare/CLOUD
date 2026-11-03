import ipaddress
import json
import socket
import ssl
import urllib.request
import urllib.error
from urllib.parse import urlparse


def is_private_or_ssrf_ip(ip_str: str) -> bool:
    """Blocks loopback, RFC1918 private networks, link-local, and cloud metadata IPs (169.254.169.254)."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
            or str(addr) == "169.254.169.254"
        )
    except ValueError:
        return True


def validate_target_ssrf(target_url: str) -> dict:
    """Validates target URL and resolves hostname to block SSRF attacks."""
    try:
        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            return {"valid": False, "reason": "Only http:// and https:// schemes are allowed."}

        hostname = (parsed.hostname or "").lower()
        if not hostname or hostname in ("localhost", "127.0.0.1", "::1") or hostname.endswith(".local"):
            return {"valid": False, "reason": f"Restricted local hostname: {hostname}"}

        # Check if hostname is directly an IP
        try:
            ipaddress.ip_address(hostname)
            if is_private_or_ssrf_ip(hostname):
                return {"valid": False, "reason": f"IP {hostname} is restricted by SSRF Guard."}
            return {"valid": True, "hostname": hostname, "port": parsed.port or (443 if parsed.scheme == "https" else 80)}
        except ValueError:
            pass

        # Resolve DNS
        try:
            infos = socket.getaddrinfo(hostname, None)
            for info in infos:
                resolved_ip = info[4][0]
                if is_private_or_ssrf_ip(resolved_ip):
                    return {"valid": False, "reason": f"Host {hostname} resolves to private/SSRF IP {resolved_ip}"}
        except socket.gaierror:
            pass

        return {"valid": True, "hostname": hostname, "port": parsed.port or (443 if parsed.scheme == "https" else 80)}
    except Exception as exc:
        return {"valid": False, "reason": str(exc)}


def run_vulnerability_scan(payload: dict) -> dict:
    """Executes real SSL/TLS, HTTP Security Header, TCP Port, or OSV Dependency CVE scan."""
    scan_category = payload.get("scanCategory", "WEB_PASSIVE")
    target_url = payload.get("targetUrl", "")
    manifest_packages = payload.get("manifestPackages", [])
    findings = []

    if scan_category == "DEPENDENCY_CVE":
        for pkg in manifest_packages:
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            ecosystem = pkg.get("ecosystem", "npm")
            try:
                req_data = json.dumps({
                    "version": version,
                    "package": {"name": name, "ecosystem": ecosystem}
                }).encode("utf-8")
                req = urllib.request.Request(
                    "https://api.osv.dev/v1/query",
                    data=req_data,
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    osv_data = json.loads(resp.read().decode("utf-8"))
                    for vuln in osv_data.get("vulns", [])[:3]:
                        vuln_id = vuln.get("id", "OSV-VULN")
                        aliases = vuln.get("aliases", [])
                        cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
                        findings.append({
                            "source_type": "DEPENDENCY_CVE",
                            "rule_id": vuln_id,
                            "title": f"Vulnerable Dependency: {name}@{version} ({cve_id})",
                            "description": (vuln.get("summary") or vuln.get("details") or f"Vulnerability in {name}")[:400],
                            "category": "DEPENDENCY_CVE",
                            "severity": "HIGH",
                            "cvss_score": 7.8,
                            "cve_id": cve_id,
                            "cwe_id": "CWE-1395",
                            "affected_asset": f"{name}@{version}",
                            "remediation_summary": f"Upgrade {name} to the latest patched version.",
                            "compliance_controls": ["A.8.8", "CC7.1"],
                            "evidence": {"package": name, "version": version, "osvId": vuln_id}
                        })
            except Exception:
                pass
        return {"findings": findings, "scannerEngine": "PYTHON_OSV_DEPENDENCY_SCANNER"}

    ssrf = validate_target_ssrf(target_url)
    if not ssrf.get("valid"):
        raise ValueError(ssrf.get("reason", "Blocked by SSRF Guard"))

    parsed = urlparse(target_url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # 1. SSL/TLS Verification
    if parsed.scheme != "https":
        findings.append({
            "source_type": "SSL_TLS",
            "rule_id": "PY-TLS-001",
            "title": "Plaintext HTTP Transport (Missing SSL/TLS Encryption)",
            "description": f"Target {target_url} uses unencrypted HTTP instead of HTTPS.",
            "category": "SSL_TLS",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "cwe_id": "CWE-319",
            "affected_asset": target_url,
            "remediation_summary": "Configure TLS 1.2/1.3 certificates and redirect HTTP to HTTPS.",
            "compliance_controls": ["A.8.24", "CC6.7"],
            "evidence": {"scheme": parsed.scheme}
        })
    else:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    tls_ver = ssock.version()
                    if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3"):
                        findings.append({
                            "source_type": "SSL_TLS",
                            "rule_id": "PY-TLS-002",
                            "title": f"Weak TLS Protocol Negotiated ({tls_ver})",
                            "description": f"Endpoint negotiated legacy protocol {tls_ver}.",
                            "category": "SSL_TLS",
                            "severity": "HIGH",
                            "cvss_score": 7.4,
                            "cwe_id": "CWE-326",
                            "affected_asset": target_url,
                            "remediation_summary": "Disable TLS 1.0/1.1 and enforce TLS 1.2+.",
                            "compliance_controls": ["A.8.24", "CC6.7"],
                            "evidence": {"tlsVersion": tls_ver}
                        })
        except Exception:
            pass

    # 2. HTTP Security Header Analysis
    try:
        req = urllib.request.Request(target_url, headers={"User-Agent": "AegisCloud-SecurityScanner/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            required_headers = [
                ("strict-transport-security", "PY-HDR-HSTS", "Missing Strict-Transport-Security (HSTS) Header", "MEDIUM", 5.8),
                ("content-security-policy", "PY-HDR-CSP", "Missing Content-Security-Policy (CSP) Header", "MEDIUM", 6.1),
                ("x-frame-options", "PY-HDR-XFO", "Missing X-Frame-Options Header", "LOW", 4.3),
                ("x-content-type-options", "PY-HDR-XCTO", "Missing X-Content-Type-Options Header", "LOW", 3.7),
            ]
            for h_key, r_id, title, sev, cvss in required_headers:
                if h_key not in headers:
                    findings.append({
                        "source_type": "HTTP_HEADERS",
                        "rule_id": r_id,
                        "title": title,
                        "description": f"HTTP response from {target_url} lacks the '{h_key}' security header.",
                        "category": "HTTP_HEADERS",
                        "severity": sev,
                        "cvss_score": cvss,
                        "cwe_id": "CWE-693",
                        "affected_asset": target_url,
                        "remediation_summary": f"Configure web server or reverse proxy to emit the {h_key} header.",
                        "compliance_controls": ["A.8.8", "CC6.6"],
                        "evidence": {"missingHeader": h_key, "statusCode": resp.status}
                    })
    except Exception:
        pass

    # 3. Active Port Scan if requested
    if scan_category in ("PORT_SCAN", "WEB_ACTIVE"):
        for probe_port, svc_name, sev, cvss in [
            (22, "SSH", "MEDIUM", 5.3),
            (3306, "MySQL", "CRITICAL", 9.1),
            (5432, "PostgreSQL", "CRITICAL", 9.1),
            (6379, "Redis", "CRITICAL", 9.8),
        ]:
            try:
                with socket.create_connection((hostname, probe_port), timeout=0.7):
                    findings.append({
                        "source_type": "PORT_SCAN",
                        "rule_id": f"PY-PORT-{probe_port}",
                        "title": f"Exposed Network Service Port: TCP/{probe_port} ({svc_name})",
                        "description": f"TCP port {probe_port} ({svc_name}) is open and reachable on {hostname}.",
                        "category": "PORT_SCAN",
                        "severity": sev,
                        "cvss_score": cvss,
                        "cwe_id": "CWE-284",
                        "affected_asset": f"{hostname}:{probe_port}",
                        "remediation_summary": f"Restrict inbound access to port {probe_port} using firewall rules.",
                        "compliance_controls": ["A.8.20", "CC6.6"],
                        "evidence": {"port": probe_port, "service": svc_name, "state": "OPEN"}
                    })
            except Exception:
                pass

    return {"findings": findings, "scannerEngine": "PYTHON_SECURITY_SCANNER_V1"}
