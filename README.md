# AegisCloud — AI-Powered Unified Cloud and Application Security Platform

An enterprise-grade, unified cybersecurity posture management (CSPM), vulnerability assessment (DAST/SCA), real-time threat detection (SIEM), human-approved active response (SOAR), OWASP LLM Top 10 application guardrail, and continuous compliance tracking (ISO/IEC 27001 & SOC 2) platform.

---

## 1. Architecture & Technology Stack

- **Frontend (`frontend/`)**: React.js 18, JavaScript (ES6+ only — zero TypeScript), Vite, Tailwind CSS, React Router v6, Axios, Socket.IO Client, Lucide Icons.
- **Primary Backend (`backend/`)**: Node.js, Express.js (JavaScript only — zero TypeScript), Socket.IO Server, JWT + RBAC Middleware, AES-256-GCM Credential Envelope Encryption, SSRF Guard, Joi Validation.
- **Security & AI Microservice (`python-security-service/`)**: Python 3.11+ HTTP/FastAPI Worker service providing SSL/TLS socket inspection, HTTP Security Header grading, TCP Port scanning, Google OSV.dev dependency CVE lookups, AWS `boto3` Cloud Posture evaluation, and OWASP Top 10 for LLM Applications runtime guardrails.
- **Database & Real-Time Layer (`database/`)**:
  - **PostgreSQL 16** (Relational + `JSONB` for multi-cloud configurations, vulnerabilities, audit logs, and compliance control mappings). Includes an automatic `pg-mem` embedded PostgreSQL fallback for instant zero-daemon local execution and testing.
  - **Redis 7** (Sliding-window brute-force/DDoS counters, JWT revocation blocklists, active WAF IP blocklist cache, and pub/sub). Includes an automatic in-memory Redis fallback when a local Redis server is not running.
- **Infrastructure (`infra/`, `docker-compose.yml`)**: Docker, Docker Compose, Nginx Reverse Proxy with rate limiting and security headers.

---

## 2. Project Directory Structure

```text
├── .env.example
├── .gitignore
├── docker-compose.yml
├── README.md
├── infra/
│   └── nginx/
│       └── nginx.conf
├── database/
│   ├── migrations/
│   │   └── 001_initial_schema.sql
│   └── seeds/
│       └── 001_compliance_controls.sql
├── backend/
│   ├── Dockerfile
│   ├── package.json
│   ├── src/
│   │   ├── server.js
│   │   ├── config/
│   │   │   ├── db.js
│   │   │   ├── redis.js
│   │   │   └── migrate.js
│   │   ├── middleware/
│   │   │   └── auth.js
│   │   ├── services/
│   │   │   ├── auditService.js
│   │   │   ├── complianceEngine.js
│   │   │   └── pythonBridge.js
│   │   ├── utils/
│   │   │   ├── encryption.js
│   │   │   └── ssrfGuard.js
│   │   └── routes/
│   │       ├── authRoutes.js
│   │       ├── cloudRoutes.js
│   │       ├── vulnerabilityRoutes.js
│   │       ├── threatRoutes.js
│   │       ├── aiSecurityRoutes.js
│   │       ├── complianceRoutes.js
│   │       └── dashboardRoutes.js
│   └── tests/
│       └── platform.test.js
├── python-security-service/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── scanner_engine.py
│   │   ├── cloud_inspector.py
│   │   └── ai_guardrail.py
│   └── tests/
│       ├── __init__.py
│       └── test_security_engines.py
└── frontend/
    ├── Dockerfile
    ├── package.json
    ├── vite.config.js
    ├── tailwind.config.js
    ├── postcss.config.js
    ├── index.html
    └── src/
        ├── main.jsx
        ├── App.jsx
        ├── index.css
        ├── api/
        │   └── client.js
        ├── context/
        │   └── AuthContext.jsx
        ├── components/
        │   └── Layout.jsx
        └── pages/
            ├── LoginPage.jsx
            ├── DashboardPage.jsx
            ├── CloudSecurityPage.jsx
            ├── VulnerabilityPage.jsx
            ├── ThreatPreventionPage.jsx
            ├── AiSecurityPage.jsx
            ├── CompliancePage.jsx
            └── AdminAuditPage.jsx
```

---

## 3. Implemented Functional Modules (Modules 1–8)

1. **Module 1 — Authentication, RBAC & Audit Trail (`/api/v1/auth`)**:
   - Bcrypt password hashing, 5-attempt brute-force account lockout, JWT Access + Refresh tokens, Redis session token revocation on logout, RBAC (`ADMIN`, `ANALYST`, `AUDITOR`), and immutable PostgreSQL `audit_logs`.
2. **Module 2 — Multi-Cloud Integration (`/api/v1/cloud`)**:
   - AWS, Microsoft Azure, and Google Cloud Platform onboarding with **AES-256-GCM credential envelope encryption**.
   - Clear separation between `LIVE` Cloud SDK inspection (`boto3`) and `DEMO_SIMULATION` sandbox evaluation.
3. **Module 3 — Vulnerability Assessment (`/api/v1/vulnerabilities`)**:
   - **SSRF Guard** blocking private RFC 1918, loopback (`127.0.0.1`), and cloud metadata (`169.254.169.254`) targets.
   - Mandatory **Domain Ownership Verification** gate before unlocking active/port scans.
   - Real SSL/TLS handshake & protocol inspection, HTTP Security Header grading (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`), TCP Port scanning, and **Google OSV.dev** dependency CVE detection.
4. **Module 4 — Threat Detection & Monitoring (`/api/v1/threats`)**:
   - Signature detection (SQL Injection, XSS, Path Traversal, Command Injection), Redis sliding-window brute-force login correlation, and statistical traffic spike anomaly detection with live **Socket.IO** alerts.
5. **Module 5 — Attack Prevention & Automated Response (`/api/v1/threats/prevention`)**:
   - **Protected IP Safelist** preventing self-inflicted DoS on corporate/loopback networks.
   - **Administrator Approval Workflow** for high-impact WAF/Firewall IP blocks and IAM key containment, plus **1-Click Rollback**.
6. **Module 6 — AI-Powered Security Analysis (`/api/v1/ai-security`)**:
   - Generates structured executive summaries, attack vector analyses, priority scores, and copy-pasteable CLI/configuration remediation steps with database caching.
7. **Module 7 — AI Application Security Guardrails (`/api/v1/ai-security/inspect`)**:
   - Runtime inspection aligned with **OWASP Top 10 for LLM Applications**: detects Prompt Injection (`LLM01`), automatically redacts leaked AWS/OpenAI/GitHub/GCP API keys and SSN/Email PII (`LLM02`), and sanitizes executable XSS in LLM outputs (`LLM05`).
8. **Module 8 — Compliance Management (`/api/v1/compliance`)**:
   - Pre-seeded **ISO/IEC 27001:2022** and **SOC 2** controls dynamically linked to open technical findings, with auditor evidence attachment and JSON audit report export.

---

## 4. Installation & Execution Instructions

### Option A: Docker Compose (Full Stack with PostgreSQL 16, Redis 7 & Nginx)

```bash
cp .env.example .env
docker compose up --build
```
- **Frontend UI (via Nginx Gateway)**: `http://localhost` (or `http://localhost:5173`)
- **Backend REST API & Socket.IO**: `http://localhost:5000`
- **Python Security & AI Service**: `http://localhost:8000`

### Option B: Local Development (Node.js + Python)

1. **Start the Python Security & AI Service**:
   ```bash
   cd python-security-service
   python app.py
   ```
2. **Install & Start the Express.js Backend**:
   ```bash
   cd backend
   npm install
   npm start
   ```
   *(Note: If PostgreSQL or Redis are not running locally, the backend automatically initializes an embedded PostgreSQL engine with all migrations/seeds and an in-memory Redis store).*
3. **Install & Start the React.js Frontend**:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
   Open `http://localhost:5173` in your browser.

---

## 5. Seeded RBAC Demo Credentials

| Role | Email | Password | Permissions |
| :--- | :--- | :--- | :--- |
| **Platform Admin** | `admin@aegiscloud.io` | `Admin@12345!` | Full access: Connect clouds, approve WAF blocks, rollback actions, manage users & RBAC. |
| **Security Analyst** | `analyst@aegiscloud.io` | `Analyst@12345!` | Run cloud & vulnerability scans, ingest telemetry, request containment, run AI guardrails. |
| **Compliance Auditor** | `auditor@aegiscloud.io` | `Auditor@12345!` | Read-only posture visibility, manage ISO 27001 / SOC 2 evidence, export compliance reports, view full audit logs. |

---

## 6. Running Automated Tests

- **Backend Integration & Security Test Suite**:
  ```bash
  cd backend
  npm test
  ```
- **Python Security & AI Guardrail Unit Tests**:
  ```bash
  python -m unittest discover -s python-security-service/tests -t python-security-service -v
  ```
