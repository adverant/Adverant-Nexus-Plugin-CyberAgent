# CyberAgent Technical Specification

Complete technical reference for integrating the CyberAgent security operations plugin.

---

## API Reference

### Base URL

```
https://api.adverant.ai/proxy/nexus-cyberagent/api/v1/cyberagent
```

All endpoints require authentication via Bearer token in the Authorization header.

---

### Endpoints

#### Run Security Scan

```http
POST /scan
```

Initiates a security scan against an authorized target.

**Request Body:**
```json
{
  "target": "192.168.1.0/24 | https://example.com | domain.com",
  "scanType": "network | web | container | cloud | dependency",
  "intensity": "light | standard | thorough",
  "tools": ["nmap", "nuclei", "nikto"],
  "config": {
    "ports": "1-65535 | top-1000 | custom",
    "excludePorts": [22, 3389],
    "timeout": 300,
    "maxConcurrent": 10
  },
  "webhookUrl": "string (optional)"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "scanId": "scan_abc123",
    "status": "queued",
    "target": "192.168.1.0/24",
    "scanType": "network",
    "estimatedDuration": 1800,
    "websocketUrl": "wss://api.adverant.ai/proxy/nexus-cyberagent/ws/scan/scan_abc123",
    "createdAt": "2024-01-15T10:30:00Z"
  }
}
```

---

#### Get Scan Results

```http
GET /scan/:scanId
```

**Response:**
```json
{
  "success": true,
  "data": {
    "scanId": "scan_abc123",
    "status": "completed",
    "target": "192.168.1.0/24",
    "scanType": "network",
    "startedAt": "2024-01-15T10:30:00Z",
    "completedAt": "2024-01-15T11:00:00Z",
    "summary": {
      "hostsScanned": 254,
      "hostsUp": 45,
      "vulnerabilities": {
        "critical": 2,
        "high": 8,
        "medium": 15,
        "low": 23,
        "info": 42
      }
    },
    "findings": [
      {
        "id": "finding_xyz789",
        "severity": "critical",
        "title": "Remote Code Execution in Apache Log4j",
        "cveId": "CVE-2021-44228",
        "cvssScore": 10.0,
        "host": "192.168.1.50",
        "port": 8080,
        "service": "http",
        "evidence": {
          "request": "...",
          "response": "...",
          "proofOfConcept": "..."
        },
        "remediation": "Update Log4j to version 2.17.0 or later",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
      }
    ]
  }
}
```

---

#### List Detected Threats

```http
GET /threats
```

**Query Parameters:**
- `severity`: `critical | high | medium | low | info`
- `status`: `open | acknowledged | resolved | false_positive`
- `scanId`: Filter by scan
- `dateFrom`: ISO 8601 date
- `dateTo`: ISO 8601 date
- `limit`: Number of results (default: 50)
- `offset`: Pagination offset

**Response:**
```json
{
  "success": true,
  "data": {
    "threats": [
      {
        "id": "threat_abc123",
        "severity": "critical",
        "title": "SQL Injection Vulnerability",
        "cveId": "CVE-2023-12345",
        "cvssScore": 9.8,
        "status": "open",
        "target": "https://app.example.com/api/users",
        "firstSeen": "2024-01-15T10:30:00Z",
        "lastSeen": "2024-01-15T10:30:00Z",
        "occurrences": 3
      }
    ],
    "pagination": {
      "total": 150,
      "limit": 50,
      "offset": 0
    }
  }
}
```

---

#### Create Incident Report

```http
POST /incidents
```

**Request Body:**
```json
{
  "title": "Potential Data Breach Investigation",
  "severity": "critical | high | medium | low",
  "description": "Detailed description of the incident",
  "affectedAssets": ["192.168.1.50", "db-server-01"],
  "relatedThreats": ["threat_abc123", "threat_def456"],
  "assignee": "user_id (optional)",
  "tags": ["data-breach", "pii-exposure"]
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "incidentId": "inc_xyz789",
    "title": "Potential Data Breach Investigation",
    "severity": "critical",
    "status": "open",
    "createdAt": "2024-01-15T10:30:00Z",
    "timeline": [
      {
        "timestamp": "2024-01-15T10:30:00Z",
        "event": "incident_created",
        "actor": "user@example.com",
        "details": "Incident created from threat correlation"
      }
    ]
  }
}
```

---

#### Get Compliance Status

```http
GET /compliance/:framework
```

**Supported Frameworks:**
- `soc2` - SOC 2 Type II
- `pci-dss` - PCI DSS v4.0
- `hipaa` - HIPAA Security Rule
- `gdpr` - GDPR
- `iso27001` - ISO 27001
- `nist-csf` - NIST Cybersecurity Framework
- `cis` - CIS Controls

**Response:**
```json
{
  "success": true,
  "data": {
    "framework": "soc2",
    "version": "2017",
    "assessmentDate": "2024-01-15T10:30:00Z",
    "overallScore": 85,
    "status": "partial",
    "categories": [
      {
        "name": "CC1 - Control Environment",
        "score": 95,
        "status": "compliant",
        "controls": [
          {
            "id": "CC1.1",
            "name": "COSO Principle 1",
            "status": "compliant",
            "evidence": ["policy-doc-001", "audit-log-002"],
            "lastAssessed": "2024-01-15T10:30:00Z"
          }
        ]
      }
    ],
    "gaps": [
      {
        "controlId": "CC6.1",
        "description": "Logical access security software",
        "remediation": "Implement MFA for all administrative access",
        "priority": "high"
      }
    ]
  }
}
```

---

#### Submit Malware Sample

```http
POST /malware/analyze
Content-Type: multipart/form-data
```

**Form Fields:**
- `file`: Binary file to analyze
- `analysisType`: `quick | standard | full`
- `timeout`: Analysis timeout in seconds (60-600)
- `sandboxTier`: `1 | 2 | 3` (optional)

**Response:**
```json
{
  "success": true,
  "data": {
    "analysisId": "mal_abc123",
    "status": "processing",
    "sha256": "a1b2c3d4...",
    "estimatedTime": 120,
    "sandboxTier": 2
  }
}
```

---

#### Get Malware Analysis Results

```http
GET /malware/:analysisId
```

**Response:**
```json
{
  "success": true,
  "data": {
    "analysisId": "mal_abc123",
    "status": "completed",
    "verdict": "malicious",
    "confidence": 0.97,
    "sha256": "a1b2c3d4...",
    "sha1": "e5f6g7h8...",
    "md5": "i9j0k1l2...",
    "fileSize": 524288,
    "fileType": "PE32 executable",
    "classification": {
      "family": "Emotet",
      "type": "trojan",
      "variant": "Banking",
      "firstSeen": "2023-06-15",
      "prevalence": "high"
    },
    "staticAnalysis": {
      "imports": ["kernel32.dll", "ntdll.dll"],
      "exports": [],
      "sections": [
        {"name": ".text", "entropy": 7.2, "suspicious": true}
      ],
      "strings": {
        "urls": ["https://malware-c2.example.com"],
        "ipAddresses": ["192.168.1.100"],
        "emails": [],
        "suspicious": ["CreateRemoteThread", "VirtualAllocEx"]
      },
      "yaraMatches": ["Emotet_Gen1", "Trojan_Generic"]
    },
    "dynamicAnalysis": {
      "processes": [
        {"name": "sample.exe", "pid": 1234, "parentPid": null}
      ],
      "networkConnections": [
        {"destination": "192.168.1.100:443", "protocol": "tcp"}
      ],
      "fileOperations": [
        {"type": "create", "path": "C:\\Windows\\Temp\\payload.dll"}
      ],
      "registryOperations": [
        {"type": "create", "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware"}
      ],
      "apiCalls": [
        {"function": "CreateRemoteThread", "count": 5}
      ]
    },
    "iocs": {
      "domains": ["malware-c2.example.com"],
      "ips": ["192.168.1.100"],
      "urls": ["https://malware-c2.example.com/beacon"],
      "fileHashes": ["a1b2c3d4..."],
      "registryKeys": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware"],
      "mutexes": ["Global\\EmotetMutex"]
    },
    "mitreAttack": [
      {
        "technique": "T1566.001",
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access"
      },
      {
        "technique": "T1055",
        "name": "Process Injection",
        "tactic": "Defense Evasion"
      }
    ],
    "recommendations": [
      "Block IOC domains and IPs at firewall",
      "Search for mutex on endpoints",
      "Check for persistence mechanism in registry"
    ]
  }
}
```

---

#### Threat Intelligence Lookup

```http
POST /intel/lookup
```

**Request Body:**
```json
{
  "indicators": [
    {"type": "ip", "value": "192.168.1.100"},
    {"type": "domain", "value": "malware.example.com"},
    {"type": "hash", "value": "a1b2c3d4e5f6..."},
    {"type": "url", "value": "https://malware.example.com/beacon"}
  ]
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "results": [
      {
        "indicator": "192.168.1.100",
        "type": "ip",
        "reputation": "malicious",
        "confidence": 0.95,
        "sources": ["virustotal", "alienvault", "misp"],
        "firstSeen": "2023-06-15T00:00:00Z",
        "lastSeen": "2024-01-14T23:59:59Z",
        "tags": ["c2", "emotet", "botnet"],
        "associatedMalware": ["Emotet", "TrickBot"],
        "mitreAttack": ["T1071.001"],
        "geolocation": {
          "country": "US",
          "asn": 12345,
          "asnOrg": "Example Hosting"
        }
      }
    ]
  }
}
```

---

#### Configure SIEM Integration

```http
POST /siem/connect
```

**Request Body:**
```json
{
  "platform": "splunk | elastic | qradar | sentinel",
  "config": {
    "host": "splunk.example.com",
    "port": 8089,
    "token": "HEC_TOKEN",
    "index": "security",
    "sourcetype": "nexus:cyberagent",
    "ssl": true,
    "verifyCert": true
  },
  "events": ["scan.completed", "vulnerability.critical", "malware.detected"]
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "integrationId": "siem_abc123",
    "platform": "splunk",
    "status": "connected",
    "lastSync": null
  }
}
```

---

## Authentication

### Bearer Token

```bash
curl -X POST "https://api.adverant.ai/proxy/nexus-cyberagent/api/v1/cyberagent/scan" \
  -H "Authorization: Bearer YOUR_NEXUS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.0/24", "scanType": "network"}'
```

### Token Scopes

| Scope | Description |
|-------|-------------|
| `security:scan` | Run security scans |
| `security:threats` | View and manage threats |
| `security:incidents` | Create and manage incidents |
| `security:compliance` | Run compliance assessments |
| `security:malware` | Submit and analyze malware |
| `security:intel` | Access threat intelligence |
| `security:siem` | Configure SIEM integrations |
| `security:admin` | Administrative operations |

---

## Rate Limits

| Tier | Requests/Minute | Concurrent Scans | Scans/Month |
|------|-----------------|------------------|-------------|
| Starter | 30 | 1 | 100 |
| Professional | 60 | 5 | 1,000 |
| Enterprise | 120 | 20 | Unlimited |

---

## Data Models

### Scan Job

```typescript
interface ScanJob {
  scanId: string;
  orgId: string;
  userId: string;
  target: string;
  scanType: ScanType;
  status: ScanStatus;
  intensity: 'light' | 'standard' | 'thorough';
  tools: string[];
  config: ScanConfig;
  sandboxTier: 1 | 2 | 3;
  progress: number;
  startedAt?: string;
  completedAt?: string;
  createdAt: string;
}

type ScanType = 'network' | 'web' | 'container' | 'cloud' | 'dependency';
type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
```

### Vulnerability Finding

```typescript
interface VulnerabilityFinding {
  id: string;
  scanId: string;
  severity: Severity;
  title: string;
  description: string;
  cveId?: string;
  cvssScore?: number;
  cvssVector?: string;
  host: string;
  port?: number;
  service?: string;
  evidence: Evidence;
  remediation: string;
  references: string[];
  verified: boolean;
  falsePositive: boolean;
  status: FindingStatus;
  createdAt: string;
}

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
type FindingStatus = 'open' | 'acknowledged' | 'resolved' | 'false_positive';
```

### Malware Sample

```typescript
interface MalwareSample {
  id: string;
  sha256: string;
  sha1: string;
  md5: string;
  fileName: string;
  fileSize: number;
  fileType: string;
  analysisStatus: AnalysisStatus;
  verdict: 'clean' | 'suspicious' | 'malicious';
  confidence: number;
  classification?: MalwareClassification;
  staticAnalysis?: StaticAnalysis;
  dynamicAnalysis?: DynamicAnalysis;
  iocs: IOCSet;
  mitreAttack: MitreTechnique[];
  yaraMatches: string[];
  firstSeen: string;
  lastSeen: string;
}

type AnalysisStatus = 'pending' | 'analyzing' | 'completed' | 'failed';
```

### Incident

```typescript
interface Incident {
  incidentId: string;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  affectedAssets: string[];
  relatedThreats: string[];
  assignee?: string;
  tags: string[];
  timeline: TimelineEvent[];
  createdAt: string;
  updatedAt: string;
  resolvedAt?: string;
}

type IncidentStatus = 'open' | 'investigating' | 'contained' |
                       'eradicated' | 'recovered' | 'closed';
```

### IOC (Indicator of Compromise)

```typescript
interface IOC {
  id: string;
  type: IOCType;
  value: string;
  confidence: number;
  source: string;
  firstSeen: string;
  lastSeen: string;
  tags: string[];
  associatedMalware?: string[];
  mitreAttack?: string[];
}

type IOCType = 'ip' | 'domain' | 'url' | 'hash' | 'email' |
               'registry' | 'mutex' | 'filename';
```

---

## SDK Integration

### JavaScript/TypeScript SDK

```typescript
import { NexusClient } from '@nexus/sdk';

const nexus = new NexusClient({
  apiKey: process.env.NEXUS_API_KEY,
});

// Run a vulnerability scan
const scan = await nexus.cyberagent.scan({
  target: '192.168.1.0/24',
  scanType: 'network',
  intensity: 'standard',
});

// Monitor progress via WebSocket
nexus.cyberagent.onScanProgress(scan.scanId, (event) => {
  if (event.type === 'vulnerability:found') {
    console.log(`Found: ${event.vulnerability.title} (${event.vulnerability.severity})`);
  }
});

// Wait for completion
const results = await nexus.cyberagent.waitForScan(scan.scanId);
console.log(`Found ${results.summary.vulnerabilities.critical} critical vulnerabilities`);

// Submit malware for analysis
const analysis = await nexus.cyberagent.analyzeMalware({
  file: fs.readFileSync('./suspicious.exe'),
  analysisType: 'full',
});

const malwareResults = await nexus.cyberagent.waitForAnalysis(analysis.analysisId);
console.log(`Verdict: ${malwareResults.verdict} (${malwareResults.classification.family})`);

// Threat intelligence lookup
const intel = await nexus.cyberagent.lookupIntel([
  { type: 'ip', value: '192.168.1.100' },
  { type: 'domain', value: 'suspicious.example.com' },
]);

// Check compliance
const compliance = await nexus.cyberagent.getCompliance('soc2');
console.log(`SOC2 Score: ${compliance.overallScore}%`);
```

### Python SDK

```python
from nexus import NexusClient

client = NexusClient(api_key=os.environ["NEXUS_API_KEY"])

# Run vulnerability scan
scan = client.cyberagent.scan(
    target="192.168.1.0/24",
    scan_type="network",
    intensity="standard"
)

# Wait for completion
results = client.cyberagent.wait_for_scan(scan.scan_id)
print(f"Found {results.summary.vulnerabilities.critical} critical vulnerabilities")

# Analyze malware sample
with open("suspicious.exe", "rb") as f:
    analysis = client.cyberagent.analyze_malware(
        file=f.read(),
        analysis_type="full"
    )

malware_results = client.cyberagent.wait_for_analysis(analysis.analysis_id)
print(f"Verdict: {malware_results.verdict}")

# Threat intelligence
intel = client.cyberagent.lookup_intel([
    {"type": "ip", "value": "192.168.1.100"}
])

# Compliance check
compliance = client.cyberagent.get_compliance("soc2")
print(f"SOC2 Score: {compliance.overall_score}%")
```

---

## WebSocket API

### Connection

```javascript
const ws = new WebSocket('wss://api.adverant.ai/proxy/nexus-cyberagent/ws');

ws.onopen = () => {
  ws.send(JSON.stringify({
    type: 'auth',
    token: 'YOUR_API_TOKEN'
  }));
};
```

### Subscribe to Scan Updates

```javascript
ws.send(JSON.stringify({
  type: 'subscribe',
  channel: 'scan',
  scanId: 'scan_abc123'
}));

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);

  switch (message.type) {
    case 'scan:started':
      console.log('Scan started');
      break;
    case 'scan:progress':
      console.log(`Progress: ${message.progress}%`);
      break;
    case 'vulnerability:found':
      console.log(`Found: ${message.vulnerability.title}`);
      break;
    case 'scan:completed':
      console.log(`Scan complete: ${message.summary.total} findings`);
      break;
    case 'scan:failed':
      console.error(`Scan failed: ${message.error}`);
      break;
  }
};
```

### Message Types

| Type | Direction | Description |
|------|-----------|-------------|
| `auth` | Client → Server | Authenticate connection |
| `subscribe` | Client → Server | Subscribe to scan/analysis |
| `scan:started` | Server → Client | Scan initiated |
| `scan:progress` | Server → Client | Progress update |
| `tool:started` | Server → Client | Tool execution started |
| `tool:output` | Server → Client | Real-time tool output |
| `vulnerability:found` | Server → Client | Vulnerability detected |
| `malware:detected` | Server → Client | Malware identified |
| `ioc:extracted` | Server → Client | IOC extracted |
| `scan:completed` | Server → Client | Scan finished |
| `scan:failed` | Server → Client | Scan error |

---

## Error Handling

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_REQUEST` | 400 | Malformed request body |
| `INVALID_TARGET` | 400 | Target format invalid |
| `UNAUTHORIZED_TARGET` | 403 | Target not authorized for scanning |
| `AUTHENTICATION_REQUIRED` | 401 | Missing or invalid token |
| `INSUFFICIENT_PERMISSIONS` | 403 | Token lacks required scope |
| `SCAN_NOT_FOUND` | 404 | Scan does not exist |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `QUOTA_EXCEEDED` | 402 | Monthly scans exceeded |
| `SCAN_FAILED` | 500 | Scan execution error |
| `ANALYSIS_FAILED` | 500 | Malware analysis error |
| `SIEM_CONNECTION_FAILED` | 502 | SIEM platform unreachable |

---

## Target Authorization

Before scanning any target, authorization must be verified.

### Authorization Methods

| Method | Description |
|--------|-------------|
| `dns_txt` | Add TXT record: `_nexus-auth=TOKEN` |
| `file_upload` | Upload authorization document |
| `manual` | Administrator approval |

### Verify Authorization

```http
POST /authorize
```

```json
{
  "target": "example.com",
  "method": "dns_txt"
}
```

---

## Sandbox Tiers

| Tier | Isolation | Network | Use Case |
|------|-----------|---------|----------|
| 1 | High | None | Static analysis, YARA |
| 2 | Very High | Controlled | Behavioral analysis |
| 3 | Maximum | Simulated | Full detonation, C2 |

---

## Deployment Requirements

### Container Specifications

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2000m | 4000m |
| Memory | 4Gi | 8Gi |
| Storage | 20Gi | 100Gi |
| Timeout | 10 min | 60 min |

### Security Configuration

CyberAgent runs in `hardened_docker` execution mode (Isolation Level 3):

- Read-only root filesystem
- All capabilities dropped
- Seccomp profile enforced
- AppArmor enforcing mode
- Network namespace isolation

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `NEXUS_API_KEY` | Yes | Nexus platform API key |
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_URL` | Yes | Redis for job queue |
| `GRAPHRAG_URL` | Yes | GraphRAG service URL |
| `MAGEAGENT_URL` | Yes | MageAgent AI service URL |
| `SANDBOX_POOL_URL` | Yes | Sandbox orchestrator URL |

### Health Checks

```yaml
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

---

## SIEM Integrations

### Supported Platforms

| Platform | Protocol | Events |
|----------|----------|--------|
| Splunk | HEC (HTTP) | All events |
| Elastic SIEM | REST API | All events |
| Microsoft Sentinel | Logic Apps | All events |
| IBM QRadar | REST API | All events |
| Palo Alto XSOAR | Integration Pack | All events |

### Event Types

| Event | Trigger |
|-------|---------|
| `scan.started` | Scan initiated |
| `scan.completed` | Scan finished |
| `vulnerability.critical` | Critical vuln found |
| `vulnerability.high` | High vuln found |
| `malware.detected` | Malware identified |
| `incident.created` | Incident opened |
| `compliance.violation` | Compliance gap |

---

## Quotas and Limits

### Per-Tier Limits

| Limit | Starter | Professional | Enterprise |
|-------|---------|--------------|------------|
| Endpoints | 50 | 500 | Unlimited |
| Scans/Month | 100 | 1,000 | Unlimited |
| Malware Samples/Month | 50 | 500 | Unlimited |
| SIEM Integrations | 1 | 3 | Unlimited |
| Custom YARA Rules | 10 | 100 | Unlimited |
| Sandbox Timeout | 60s | 300s | 600s |
| Concurrent Scans | 1 | 5 | 20 |

---

## Compliance Frameworks

| Framework | Controls | Auto-Assessment |
|-----------|----------|-----------------|
| SOC 2 | Trust Services Criteria | Yes |
| PCI DSS v4.0 | 12 Requirements | Yes |
| HIPAA | Security Rule | Yes |
| GDPR | Article 32 | Yes |
| ISO 27001 | Annex A Controls | Yes |
| NIST CSF | 5 Functions | Yes |
| CIS Controls | 18 Controls | Yes |

---

## Support

- **Documentation**: [docs.adverant.ai/plugins/cyberagent](https://docs.adverant.ai/plugins/cyberagent)
- **Security Advisories**: [security.adverant.ai](https://security.adverant.ai)
- **Support Email**: security-support@adverant.ai
- **Discord**: [discord.gg/adverant](https://discord.gg/adverant)
- **Emergency**: security-emergency@adverant.ai (24/7)
