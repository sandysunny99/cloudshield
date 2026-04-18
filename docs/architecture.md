# CloudShield Architecture

CloudShield leverages a distributed Edge-to-Cloud architecture mapping remote system states into an aggregated global risk platform.

## Architecture Diagram

```mermaid
graph TD
    %% Define Edge Devices
    subgraph Edge Layer [1. Edge Layer]
        A1[Agent 1: Windows Client]
        A2[Agent 2: Linux Server]
        A3[Agent 3: Storage Node]
    end

    %% Define Network Edge
    subgraph Network Security
        WAF[Cloudflare WAF Edge]
    end

    %% Define Cloud SaaS Backend
    subgraph Backend Services [2. Render Backend Environment]
        API[Flask Gateway API]
        Auth[HMAC Validator]
        Risk[Risk & Telemetry Engine]
        DB[(PostgreSQL Database)]
    end

    %% Define Web Dashboard
    subgraph Presentation [3. Vercel Frontend]
        Vite[Vite Dashboard UI]
        Metrics[Metrics Polling Hub]
    end

    %% Routing Flow
    A1 -- "Encrypted Telemetry JSON\n(x-agent-signature)" --> WAF
    A2 -- "Encrypted Telemetry JSON\n(x-agent-signature)" --> WAF
    A3 -- "Encrypted Telemetry JSON\n(x-agent-signature)" --> WAF

    %% WAF Pass-through
    WAF -- "Valid IP & Requests" --> API

    %% Inner Backend Logic
    API --> Auth
    Auth -- "Pass" --> Risk
    Auth -- "Fail (5 Attempts)" --> WAF_BAN[WAF Ban Instruction]
    WAF_BAN -. "API Update" .-> WAF
    
    Risk --> DB
    
    %% Dashboard Flow
    Metrics -- "/api/dashboard-summary\n(Every 30s)" --> API
    Vite <--> Metrics
    API <--> DB

    classDef default fill:#1e1e2e,stroke:#313244,stroke-width:2px,color:#cdd6f4;
    classDef edgeObject fill:#11111b,stroke:#89b4fa,stroke-width:2px,color:#89b4fa;
    classDef databaseNode fill:#11111b,stroke:#a6e3a1,stroke-width:2px,color:#a6e3a1;
    classDef ui fill:#11111b,stroke:#f9e2af,stroke-width:2px,color:#f9e2af;
    
    class A1,A2,A3 edgeObject;
    class DB databaseNode;
    class Vite,Metrics ui;
```

## System Flow

### Remote Endpoint Execution
1. **Agent Execution**: The user launches the standalone `.exe` or `python agent.py` loop. It begins harvesting Trivy CVEs, CPU metrics, and open ports.
2. **Cryptographic Sealing**: The agent uses physical API keys to hash the payload signature. 
3. **Transmission**: The payload transits to `/api/agent-scan` externally over standard HTTPS REST.

### Cloud Receiving & Security Routing
1. **Cloudflare**: Incoming traffic checks WAF policies and stops DoS routing.
2. **Backend Interception**: Flask captures the packet. `handle_failed_auth()` executes via HMAC. Invalid keys > 5 trigger a massive fallback ban via Edge networking API.
3. **Database Sink**: Valid data uses `SQLAlchemy` mapping. `Agent` tables are safely `UPSERT`-ed, capturing immediate state and resetting the `last_seen` timestamp. 

### Web Aggregation
1. **Frontend Hub**: `dashboard.js` loops an infinite poll grabbing `/api/dashboard-summary` safely capturing total global state locally at an interval rate logic handling 429 back-offs manually.
2. **Agent Pruning**: Background Flask threads ensure any Agent breaching more than a 60 second lag falls to "offline". Any dead agent lagging more than 300 seconds is strictly removed out of the system state (`SQLAlchemy Delete`).
