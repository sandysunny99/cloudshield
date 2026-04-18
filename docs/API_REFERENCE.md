# CloudShield API Reference 🔌

The CloudShield API provides a unified interface for container scanning, cloud configuration assessment, and EDR telemetry management.

## Base URL
- **Local**: `http://localhost:5000`
- **Render**: `https://cloudshield-tya3.onrender.com`

---

## Security Scanning

### 1. Container Image Scan
Triggers a Trivy-powered vulnerability scan of a container image.

- **Endpoint**: `/api/scan/container`
- **Method**: `POST`
- **Payload**:
  ```json
  { "image": "nginx:latest" }
  ```
- **Response**:
  ```json
  {
    "status": "completed",
    "image": "nginx:latest",
    "vulnerabilities": [...],
    "summary": { "critical": 2, "high": 5, ... }
  }
  ```

### 2. Cloud Configuration Scan
Evaluates cloud configurations (JSON/YAML) against security policies.

- **Endpoint**: `/api/scan/cloud`
- **Method**: `POST`
- **Payload**: Raw JSON or YAML representation of your cloud resources.
- **Response**:
  ```json
  {
    "status": "completed",
    "engine": "opa|builtin",
    "violations": [...]
  }
  ```

---

## EDR & Fleet Status

### 3. Agent Telemetry Receiver
Endpoint for CloudShield agents to ship host telemetry.

- **Endpoint**: `/api/agent-scan`
- **Method**: `POST`
- **Headers**:
  - `x-agent-signature`: HMAC-SHA256 signature
  - `x-agent-timestamp`: UTC timestamp
- **Payload**: Signed telemetry JSON (CPU, RAM, Processes).

### 4. Fleet Dashboard Status
Returns a list of all connected agents and their current health.

- **Endpoint**: `/api/agent-status`
- **Method**: `GET`
- **Response**:
  ```json
  {
    "agents": [
      {
        "agentId": "uuid",
        "connection_status": "online",
        "cpu_percent": 15.2,
        ...
      }
    ]
  }
  ```

---

## Aggregated Analytics

### 5. Unified Risk Score
Calculates an aggregate risk score (0-100) across all findings.

- **Endpoint**: `/api/risk/score`
- **Method**: `GET`
- **Response**:
  ```json
  {
    "status": "success",
    "data": {
      "final_score": 75,
      "category": "HIGH",
      "finding_count": 12
    }
  }
  ```

### 6. Security Metrics
Returns real-time attack metrics (blocked IPs, request rates).

- **Endpoint**: `/api/security-metrics`
- **Method**: `GET`
