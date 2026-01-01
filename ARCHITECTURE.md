# Architecture: CyberAgent - AI Security Operations Center

A comprehensive technical overview of the Nexus CyberAgent plugin architecture, including system components, data flows, security model, and integration patterns.

---

## System Overview

Nexus CyberAgent is a hardened, multi-tier security analysis platform that provides AI-powered threat detection, vulnerability assessment, penetration testing, and incident response capabilities. The architecture employs defense-in-depth principles with isolated sandbox tiers, multi-agent AI orchestration, and comprehensive audit logging.

```mermaid
graph TB
    subgraph Cloud["Nexus Cloud Platform"]
        API[API Gateway]
        Auth[Auth Service]

        subgraph Plugin["CyberAgent Plugin - Hardened Docker"]
            Routes[API Routes]
            JobSvc[Job Service]
            WorkflowSvc[Workflow Service]
            Queue[Job Queue]
            WS[WebSocket Server]
        end

        subgraph Nexus["Nexus Core Services"]
            MA[MageAgent AI]
            OA[Orchestration Agent]
            LA[Learning Agent]
            GR[GraphRAG]
        end

        DB[(PostgreSQL)]
        RD[(Redis)]
        MQ[BullMQ]
    end

    subgraph Sandbox["Isolated Sandbox Tiers"]
        T1[Tier 1 - Basic Analysis]
        T2[Tier 2 - Behavioral Analysis]
        T3[Tier 3 - Full Detonation]
    end

    subgraph External["External Integrations"]
        SIEM[SIEM Platforms]
        TI[Threat Intel Feeds]
        EDR[EDR Solutions]
    end

    API --> Auth
    API --> Routes
    Routes --> JobSvc
    Routes --> WorkflowSvc
    JobSvc --> Queue
    Queue --> MQ
    MQ --> T1 & T2 & T3

    JobSvc --> MA
    JobSvc --> OA
    WorkflowSvc --> LA
    JobSvc --> GR

    JobSvc --> DB
    Queue --> RD
    WS --> RD

    Routes --> SIEM
    Routes --> TI
    Routes --> EDR
```

---

## Core Components

### API Gateway and Routing

The CyberAgent API provides RESTful endpoints for all security operations with comprehensive middleware for authentication, rate limiting, and usage tracking.

| Component | Responsibility | Technology |
|-----------|----------------|------------|
| **Routes** | HTTP request handling and validation | Express.js |
| **Authentication** | JWT validation and RBAC | Custom middleware |
| **Rate Limiter** | DoS protection and quota enforcement | Redis + Token bucket |
| **Usage Tracking** | Billing metering and analytics | Custom middleware |
| **Error Handler** | Standardized error responses | Express middleware |

**API Architecture:**

```typescript
interface APIConfig {
  version: 'v1';
  basePath: '/api/v1/cyberagent';
  endpoints: {
    scan: '/scan';
    threats: '/threats';
    incidents: '/incidents';
    compliance: '/compliance/:framework';
    jobs: '/jobs';
    workflows: '/workflows';
    malware: '/malware';
    exploits: '/exploits';
    iocs: '/iocs';
    yara: '/yara';
  };
}
```

### Job Service and Queue System

The job service manages the complete lifecycle of security operations from creation through completion.

```mermaid
stateDiagram-v2
    [*] --> Queued: Job submitted
    Queued --> Running: Worker available
    Running --> Completed: Success
    Running --> Failed: Error
    Running --> Cancelled: User cancelled
    Failed --> Queued: Retry enabled
    Completed --> [*]
    Cancelled --> [*]
```

**Queue Architecture:**

```mermaid
flowchart TB
    subgraph Producers["Job Producers"]
        API[API Requests]
        Workflow[Workflow Engine]
        Schedule[Scheduled Scans]
    end

    subgraph Queue["BullMQ Queue System"]
        PQ[(Pentest Queue)]
        MQ[(Malware Queue)]
        EQ[(Exploit Queue)]
        CQ[(C2 Queue)]
        AQ[(APT Queue)]
    end

    subgraph Workers["Queue Processors"]
        PW[Pentest Processor]
        MW[Malware Processor]
        EW[Exploit Processor]
        CW[C2 Processor]
        AW[APT Processor]
    end

    subgraph Sandboxes["Execution Sandboxes"]
        T1[Tier 1]
        T2[Tier 2]
        T3[Tier 3]
    end

    API & Workflow & Schedule --> PQ & MQ & EQ & CQ & AQ
    PQ --> PW
    MQ --> MW
    EQ --> EW
    CQ --> CW
    AQ --> AW
    PW & MW & EW & CW & AW --> T1 & T2 & T3
```

### Workflow Engine

The workflow engine executes complex multi-step security operations with dependency management, conditions, and approvals.

```mermaid
flowchart LR
    subgraph Input["Workflow Definition"]
        Def[YAML/JSON Definition]
        Vars[Variables]
        Conds[Conditions]
    end

    subgraph Engine["Workflow Engine"]
        Parse[Parser]
        Deps[Dependency Graph]
        Exec[Step Executor]
        State[State Manager]
    end

    subgraph Steps["Step Types"]
        Scan[Scan Steps]
        Analysis[Analysis Steps]
        Notify[Notification Steps]
        Approval[Approval Steps]
        Export[Export Steps]
    end

    subgraph Output["Execution Output"]
        Results[Step Results]
        Report[Reports]
        Events[Events]
    end

    Def & Vars & Conds --> Parse
    Parse --> Deps
    Deps --> Exec
    Exec --> State
    State --> Scan & Analysis & Notify & Approval & Export
    Scan & Analysis & Notify & Approval & Export --> Results & Report & Events
```

**Supported Workflow Step Types:**

| Step Type | Description | Configuration |
|-----------|-------------|---------------|
| `scan` | Execute security scan | scan_type, target, tools, config |
| `condition` | Conditional branching | conditions, on_true, on_false |
| `parallel` | Parallel step execution | steps[] |
| `loop` | Iterate over collection | items, step, max_iterations |
| `approval` | Manual approval gate | approvers, timeout, message |
| `notification` | Send alerts | channels, recipients, message |
| `nexus_analysis` | AI-powered analysis | analysis_type, input_step |
| `report` | Generate reports | report_type, format, include_steps |
| `export` | Export data | format, destination |

### Nexus Integration Framework

The Nexus Integration orchestrates comprehensive security analysis by integrating multiple AI services.

```mermaid
sequenceDiagram
    participant Job as Scan Job
    participant NI as Nexus Integration
    participant GR as GraphRAG
    participant MA as MageAgent
    participant OA as Orchestration Agent
    participant LA as Learning Agent

    Job->>NI: Analyze malware results
    NI->>GR: Store malware analysis
    GR-->>NI: Entity ID
    NI->>GR: Store IOCs
    GR-->>NI: IOC correlation results
    NI->>MA: Multi-agent analysis
    MA-->>NI: Analysis synthesis
    NI->>LA: Trigger learning
    LA-->>NI: Learning ID
    alt High/Critical Threat
        NI->>OA: Autonomous threat hunting
        OA-->>NI: Attribution results
    end
    NI-->>Job: Comprehensive analysis
```

**Integration Services:**

| Service | Purpose | Capabilities |
|---------|---------|--------------|
| **GraphRAG** | Persistent knowledge graph | Threat intel storage, IOC correlation, pattern matching |
| **MageAgent** | Multi-agent AI analysis | Deep analysis, pattern recognition, synthesis |
| **Orchestration Agent** | Autonomous operations | Threat hunting, incident response, attribution |
| **Learning Agent** | Continuous improvement | Detection tuning, rule generation, model updates |

---

## Sandbox Architecture

CyberAgent employs a three-tier sandbox architecture for safe execution of security tools and malware analysis.

```mermaid
graph TB
    subgraph Tier1["Tier 1 - Basic Analysis"]
        T1Net[Network Isolated]
        T1Static[Static Analysis]
        T1Hash[Hash Lookups]
        T1Yara[YARA Scanning]
    end

    subgraph Tier2["Tier 2 - Behavioral Analysis"]
        T2Net[Controlled Network]
        T2Dynamic[Dynamic Analysis]
        T2Monitor[Process Monitoring]
        T2API[API Hooking]
    end

    subgraph Tier3["Tier 3 - Full Detonation"]
        T3Net[Simulated Internet]
        T3Full[Full Execution]
        T3C2[C2 Simulation]
        T3Lateral[Lateral Movement]
    end

    subgraph Control["Sandbox Controller"]
        Select[Tier Selection]
        Provision[VM Provisioning]
        Monitor[Execution Monitor]
        Cleanup[Secure Cleanup]
    end

    Select --> T1Net & T2Net & T3Net
    Provision --> T1Static & T2Dynamic & T3Full
    Monitor --> T1Yara & T2Monitor & T3C2
    Cleanup --> T1Hash & T2API & T3Lateral
```

**Tier Characteristics:**

| Tier | Isolation Level | Network Access | Execution Mode | Use Cases |
|------|----------------|----------------|----------------|-----------|
| **Tier 1** | High | None | Static only | File hashing, YARA, basic analysis |
| **Tier 2** | Very High | Controlled | Monitored execution | Behavioral analysis, API monitoring |
| **Tier 3** | Maximum | Simulated | Full detonation | Advanced malware, C2 analysis |

---

## Data Flow

### Security Scan Pipeline

```mermaid
sequenceDiagram
    participant Client
    participant API as API Gateway
    participant Auth as Auth Service
    participant Job as Job Service
    participant Queue as Job Queue
    participant Worker as Scan Worker
    participant Sandbox as Sandbox
    participant DB as Database
    participant WS as WebSocket

    Client->>API: POST /scan
    API->>Auth: Validate token
    Auth-->>API: User context
    API->>API: Validate target authorization
    API->>Job: Create scan job
    Job->>DB: Store job record
    Job->>Queue: Enqueue job
    Job-->>API: Job created
    API-->>Client: Job ID + WebSocket URL

    Queue->>Worker: Dispatch job
    Worker->>Sandbox: Initialize sandbox
    Worker->>WS: job:started event

    loop During Scan
        Worker->>Sandbox: Execute tools
        Sandbox-->>Worker: Tool output
        Worker->>DB: Store findings
        Worker->>WS: vulnerability:found events
        Worker->>WS: job:progress events
    end

    Worker->>Sandbox: Cleanup
    Worker->>DB: Update job status
    Worker->>WS: job:completed event
    Client->>API: GET /threats
    API->>DB: Query findings
    DB-->>API: Threat data
    API-->>Client: Threat list
```

### Real-time Event Streaming

```mermaid
flowchart TB
    subgraph Publishers["Event Publishers"]
        Job[Job Processors]
        Scan[Scan Workers]
        Analysis[Analysis Engine]
    end

    subgraph Bus["Event Bus"]
        Redis[(Redis Pub/Sub)]
    end

    subgraph Server["WebSocket Server"]
        Auth[Connection Auth]
        Rooms[Job Rooms]
        Broadcast[Broadcast]
    end

    subgraph Clients["WebSocket Clients"]
        Dashboard[Dashboard UI]
        CLI[CLI Tools]
        SIEM[SIEM Integration]
    end

    Job & Scan & Analysis --> Redis
    Redis --> Auth
    Auth --> Rooms
    Rooms --> Broadcast
    Broadcast --> Dashboard & CLI & SIEM
```

**WebSocket Event Types:**

```typescript
type WebSocketEventType =
  | 'job:created'
  | 'job:started'
  | 'job:progress'
  | 'job:completed'
  | 'job:failed'
  | 'job:cancelled'
  | 'tool:started'
  | 'tool:output'
  | 'tool:completed'
  | 'vulnerability:found'
  | 'malware:detected'
  | 'ioc:extracted'
  | 'exploit:success'
  | 'exploit:failed'
  | 'agent:spawned'
  | 'agent:thinking'
  | 'agent:action'
  | 'agent:completed'
  | 'workflow:phase_started'
  | 'workflow:phase_completed'
  | 'nexus:recall'
  | 'nexus:stored';
```

---

## Security Model

### Authentication and Authorization

```mermaid
flowchart TB
    subgraph Auth["Authentication"]
        JWT[JWT Token]
        API[API Key]
    end

    subgraph Roles["User Roles"]
        RedTeam[Red Team Operator]
        BlueTeam[Blue Team Analyst]
        Researcher[Security Researcher]
        Admin[Administrator]
    end

    subgraph Permissions["Capabilities"]
        Scan[Run Scans]
        Pentest[Penetration Testing]
        Malware[Malware Analysis]
        Exploit[Exploit Development]
        Incident[Incident Response]
        Admin2[Administration]
    end

    JWT & API --> RedTeam & BlueTeam & Researcher & Admin

    RedTeam --> Scan & Pentest & Exploit
    BlueTeam --> Scan & Malware & Incident
    Researcher --> Scan & Malware
    Admin --> Scan & Pentest & Malware & Exploit & Incident & Admin2
```

### Target Authorization

CyberAgent requires explicit authorization before scanning any target to prevent unauthorized testing.

```mermaid
sequenceDiagram
    participant User
    participant API as CyberAgent API
    participant Auth as Target Auth Service
    participant DNS as DNS Lookup
    participant DB as Authorization DB

    User->>API: Request scan on target.com
    API->>DB: Check existing authorization
    alt Already Authorized
        DB-->>API: Valid authorization
        API->>API: Proceed with scan
    else Not Authorized
        API-->>User: Authorization required
        User->>API: POST /authorize (dns_txt method)
        API->>User: Add TXT record: _nexus-auth=TOKEN
        User->>DNS: Add DNS TXT record
        User->>API: Verify authorization
        API->>DNS: Lookup _nexus-auth.target.com
        DNS-->>API: TXT record value
        alt Token matches
            API->>DB: Store authorization
            API-->>User: Authorization verified
        else Token mismatch
            API-->>User: Authorization failed
        end
    end
```

**Authorization Methods:**

| Method | Description | Verification |
|--------|-------------|--------------|
| `dns_txt` | DNS TXT record verification | Automatic DNS lookup |
| `file_upload` | Upload authorization document | Manual review |
| `manual` | Administrator approval | Manual verification |

### Audit Logging

All security operations are logged to an immutable audit trail.

```typescript
interface AuditLogEntry {
  timestamp: Date;
  event_type: string;
  user_id: string;
  org_id: string;
  resource_type: string;
  resource_id: string;
  action: string;
  ip_address: string;
  user_agent: string;
  request_id: string;
  details: Record<string, any>;
  result: 'success' | 'failure';
  error_message?: string;
}
```

---

## API Reference

### Base URL

```
https://api.adverant.ai/proxy/nexus-cyberagent/api/v1
```

### Scan Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scan` | Run security scan |
| `GET` | `/scan/:scanId` | Get scan status |
| `DELETE` | `/scan/:scanId` | Cancel scan |

### Threat Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/threats` | List detected threats |
| `GET` | `/threats/:threatId` | Get threat details |
| `PUT` | `/threats/:threatId` | Update threat status |

### Incident Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/incidents` | Create incident report |
| `GET` | `/incidents` | List incidents |
| `GET` | `/incidents/:incidentId` | Get incident details |
| `PUT` | `/incidents/:incidentId` | Update incident |

### Compliance Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/compliance/:framework` | Get compliance status |
| `POST` | `/compliance/assess` | Run compliance assessment |
| `GET` | `/compliance/evidence` | Get evidence package |

### Malware Analysis Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/malware/upload` | Upload sample |
| `GET` | `/malware/:sampleId` | Get analysis results |
| `GET` | `/malware/:sampleId/iocs` | Get extracted IOCs |

### Workflow Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/workflows/execute` | Execute workflow |
| `GET` | `/workflows/:executionId` | Get execution status |
| `POST` | `/workflows/:executionId/approve` | Approve pending step |

---

## Database Schema

### Core Tables

```mermaid
erDiagram
    ScanJob ||--o{ ScanResult : produces
    ScanJob ||--o| AgentSession : has
    ScanJob ||--o| WorkflowExecution : part_of
    MalwareSample ||--o{ IOC : contains
    ScanJob ||--o{ IOC : extracts
    YARARule ||--o{ MalwareSample : matches
    TargetAuthorization ||--o{ ScanJob : authorizes

    ScanJob {
        uuid id PK
        uuid org_id
        uuid user_id
        enum scan_type
        string target
        enum status
        int priority
        enum sandbox_tier
        json tools
        json config
        int progress
        timestamp created_at
        timestamp completed_at
    }

    ScanResult {
        uuid id PK
        uuid job_id FK
        enum finding_type
        enum severity
        string title
        string cve_id
        decimal cvss_score
        json evidence
        boolean verified
        timestamp created_at
    }

    MalwareSample {
        uuid id PK
        uuid org_id
        string sha256
        string file_name
        enum analysis_status
        string malware_family
        enum threat_level
        json yara_matches
        json iocs
        json analysis_results
        timestamp first_seen
    }

    IOC {
        uuid id PK
        uuid malware_sample_id FK
        uuid scan_job_id FK
        enum ioc_type
        string ioc_value
        decimal confidence
        timestamp first_seen
        timestamp last_seen
    }
```

---

## Scaling Characteristics

### Horizontal Scaling

```mermaid
graph TB
    subgraph LB["Load Balancer"]
        HAProxy[HAProxy]
    end

    subgraph API["API Tier (Stateless)"]
        API1[API Instance 1]
        API2[API Instance 2]
        API3[API Instance N]
    end

    subgraph Workers["Worker Tier (Stateless)"]
        W1[Scan Worker 1]
        W2[Scan Worker 2]
        W3[Scan Worker N]
    end

    subgraph State["State Layer"]
        Redis[(Redis Cluster)]
        PG[(PostgreSQL)]
    end

    subgraph Sandboxes["Sandbox Pool"]
        S1[Sandbox Pool T1]
        S2[Sandbox Pool T2]
        S3[Sandbox Pool T3]
    end

    HAProxy --> API1 & API2 & API3
    API1 & API2 & API3 --> Redis & PG
    W1 & W2 & W3 --> Redis & PG
    W1 & W2 & W3 --> S1 & S2 & S3
```

### Performance Benchmarks

| Metric | Single Node | Cluster (3 nodes) | Target |
|--------|-------------|-------------------|--------|
| API Requests/sec | 2,000 | 6,000 | 10,000 |
| Concurrent Scans | 10 | 50 | 100 |
| Malware Analysis/hr | 50 | 200 | 500 |
| WebSocket Connections | 1,000 | 5,000 | 10,000 |
| IOC Correlation Latency | 100ms p95 | 150ms p95 | <200ms |

### Resource Requirements

| Tier | vCPU | Memory | Storage | Endpoints |
|------|------|--------|---------|-----------|
| **Starter** | 4 | 8 GB | 50 GB | Up to 50 |
| **Professional** | 8 | 16 GB | 200 GB | Up to 500 |
| **Enterprise** | 16+ | 32+ GB | 1+ TB | Unlimited |

---

## Integration Points

### SIEM Integration

```mermaid
flowchart LR
    subgraph CyberAgent["CyberAgent"]
        Events[Event Publisher]
        API[REST API]
    end

    subgraph Adapters["SIEM Adapters"]
        Splunk[Splunk HEC]
        Elastic[Elasticsearch]
        QRadar[IBM QRadar]
        Sentinel[Azure Sentinel]
    end

    subgraph SIEM["SIEM Platforms"]
        S1[Splunk]
        S2[Elastic SIEM]
        S3[QRadar]
        S4[Sentinel]
    end

    Events --> Splunk --> S1
    Events --> Elastic --> S2
    Events --> QRadar --> S3
    Events --> Sentinel --> S4
    API --> S1 & S2 & S3 & S4
```

### Threat Intelligence Feeds

| Feed Type | Integration | Update Frequency |
|-----------|-------------|------------------|
| **MISP** | REST API | Real-time |
| **STIX/TAXII** | TAXII Client | Hourly |
| **VirusTotal** | API | On-demand |
| **AlienVault OTX** | API | Hourly |
| **Custom Feeds** | Webhook ingestion | Configurable |

### Webhook Events

```typescript
interface WebhookConfig {
  url: string;
  events: WebhookEvent[];
  secret: string;
  retryPolicy: {
    maxRetries: number;
    backoffMs: number;
  };
}

type WebhookEvent =
  | 'scan.started'
  | 'scan.completed'
  | 'scan.failed'
  | 'vulnerability.critical'
  | 'vulnerability.high'
  | 'malware.detected'
  | 'incident.created'
  | 'compliance.violation';
```

---

## Deployment Architecture

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nexus-cyberagent
  namespace: nexus-plugins
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nexus-cyberagent
  template:
    metadata:
      labels:
        app: nexus-cyberagent
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: cyberagent
          image: adverant/nexus-cyberagent:1.0.0
          ports:
            - containerPort: 8080
          resources:
            requests:
              cpu: "2000m"
              memory: "4096Mi"
            limits:
              cpu: "4000m"
              memory: "8192Mi"
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          env:
            - name: NODE_ENV
              value: "production"
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: cyberagent-secrets
                  key: database-url
          livenessProbe:
            httpGet:
              path: /health/live
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /health/ready
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 5
```

### Hardened Container Configuration

CyberAgent runs in `hardened_docker` execution mode with isolation level 3:

| Security Control | Configuration |
|------------------|---------------|
| **Network Isolation** | Dedicated network namespace |
| **Filesystem** | Read-only root, tmpfs for temp |
| **Capabilities** | All capabilities dropped |
| **Seccomp** | Custom restrictive profile |
| **AppArmor** | Enforcing mode |
| **Resource Limits** | CPU/Memory quotas enforced |

---

## Monitoring and Observability

### Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `cyberagent_scans_total` | Counter | Total scans processed |
| `cyberagent_scan_duration_seconds` | Histogram | Scan execution duration |
| `cyberagent_vulnerabilities_total` | Counter | Vulnerabilities discovered |
| `cyberagent_malware_samples_total` | Counter | Malware samples analyzed |
| `cyberagent_queue_depth` | Gauge | Pending jobs in queue |
| `cyberagent_sandbox_utilization` | Gauge | Sandbox resource utilization |

### Health Checks

```bash
# Liveness - Is the service running?
GET /health/live

# Readiness - Can the service handle requests?
GET /health/ready

# Detailed health with service dependencies
GET /health
```

**Health Response:**

```json
{
  "status": "healthy",
  "timestamp": "2025-01-15T10:30:00Z",
  "version": "1.0.0",
  "services": {
    "database": { "status": "healthy", "latency": 5 },
    "redis": { "status": "healthy", "latency": 2 },
    "graphrag": { "status": "healthy", "latency": 15 },
    "mageagent": { "status": "healthy", "latency": 20 },
    "tier1_sandbox": { "status": "healthy" },
    "tier2_sandbox": { "status": "healthy" },
    "tier3_sandbox": { "status": "healthy" }
  },
  "uptime": 86400
}
```

---

## Further Reading

- **[Quick Start Guide](./QUICKSTART.md)**: Get started in 20 minutes
- **[Use Cases](./USE-CASES.md)**: Real-world implementation examples
- **[API Documentation](https://docs.adverant.ai/plugins/cyberagent/api)**: Complete API reference
- **[Security Guidelines](./docs/security/guidelines.md)**: Security best practices

---

**Questions?** Contact our security architecture team at security-architecture@adverant.ai
