# Quick Start: CyberAgent - AI Security Operations Center

> **Integration Time**: ~20 minutes | **First Scan**: ~10 minutes after install

Get your AI-powered security operations center running in minutes. This guide walks you through installation, verification, and your first security scan.

---

## Prerequisites

Before you begin, ensure you have:

- **Nexus Account**: Free signup at [adverant.ai](https://adverant.ai)
- **API Key**: Generate from the Nexus Dashboard under Settings > API Keys
- **Node.js 18+** or **Python 3.9+** for SDK usage
- **Network Access**: Target systems must be reachable from your Nexus deployment

### Supported Scan Types

| Scan Type | Target | Requirements |
|-----------|--------|--------------|
| Vulnerability Scanning | Networks, hosts, applications | Network access to targets |
| Penetration Testing | Authorized systems only | Written authorization |
| Compliance Audit | IT infrastructure | System access credentials |
| Threat Intelligence | Logs, network traffic | Log aggregator access |
| Incident Response | Compromised systems | IR authorization |

---

## Installation (60 seconds)

### Via Nexus CLI (Recommended)

```bash
# Install the plugin from Nexus Marketplace
nexus plugin install nexus-cyberagent

# Verify installation
nexus plugin list | grep cyberagent
```

### Via REST API

```bash
curl -X POST "https://api.adverant.ai/plugins/nexus-cyberagent/install" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json"
```

**Response:**
```json
{
  "pluginId": "nexus-cyberagent",
  "version": "1.0.0",
  "status": "installed",
  "endpoints": {
    "basePath": "/api/v1/cyberagent"
  },
  "executionMode": "hardened_docker",
  "isolationLevel": 3
}
```

---

## Verify Installation (60 seconds)

Confirm the plugin is running and ready to accept security operations.

### Health Check

```bash
curl "https://api.adverant.ai/proxy/nexus-cyberagent/health" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

**Expected Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "services": {
    "threatDetection": "ready",
    "vulnerabilityScanner": "ready",
    "incidentResponse": "ready",
    "complianceEngine": "ready",
    "logAnalysis": "ready",
    "threatIntelligence": "ready"
  },
  "uptime": "1h 45m"
}
```

### Readiness Check

```bash
curl "https://api.adverant.ai/proxy/nexus-cyberagent/ready" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

---

## Your First Operation (5-10 minutes)

### Step 1: Run a Security Scan

Execute your first vulnerability scan against a target system.

```bash
curl -X POST "https://api.adverant.ai/proxy/nexus-cyberagent/api/v1/scan" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "scanType": "vulnerability",
    "targets": ["192.168.1.0/24"],
    "scanProfile": "standard",
    "options": {
      "portScan": true,
      "serviceDetection": true,
      "vulnerabilityDetection": true,
      "osFingerprinting": true
    }
  }'
```

**Response:**
```json
{
  "scanId": "scan_7f8a9b2c",
  "status": "running",
  "targetsTotal": 256,
  "targetsScanned": 0,
  "estimatedDuration": 1200,
  "startedAt": "2025-01-15T10:30:00Z"
}
```

### Step 2: Check Scan Progress

Monitor the scan as it executes.

```bash
curl "https://api.adverant.ai/proxy/nexus-cyberagent/api/v1/scan/scan_7f8a9b2c" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

**Response:**
```json
{
  "scanId": "scan_7f8a9b2c",
  "status": "completed",
  "targetsTotal": 256,
  "targetsScanned": 256,
  "hostsDiscovered": 42,
  "vulnerabilitiesFound": 127,
  "criticalCount": 3,
  "highCount": 18,
  "mediumCount": 56,
  "lowCount": 50,
  "completedAt": "2025-01-15T10:50:00Z"
}
```

### Step 3: View Detected Threats

List all vulnerabilities and threats discovered during the scan.

```bash
curl "https://api.adverant.ai/proxy/nexus-cyberagent/api/v1/threats?scanId=scan_7f8a9b2c" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

**Response:**
```json
{
  "threats": [
    {
      "threatId": "threat_001",
      "severity": "critical",
      "cveId": "CVE-2024-1234",
      "title": "Remote Code Execution in Apache Struts",
      "affectedHost": "192.168.1.50",
      "service": "Apache Struts 2.5.30",
      "port": 8080,
      "exploitability": "high",
      "aiAnalysis": {
        "riskScore": 9.8,
        "attackVector": "Network",
        "recommendation": "Immediate patching required. Upgrade to Struts 2.5.33 or later."
      }
    }
  ],
  "totalCount": 127,
  "pagination": {
    "page": 1,
    "pageSize": 20
  }
}
```

### Step 4: Create an Incident Report

Generate a formal incident report for a detected threat.

```bash
curl -X POST "https://api.adverant.ai/proxy/nexus-cyberagent/api/v1/incidents" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "threatIds": ["threat_001"],
    "title": "Critical RCE Vulnerability in Production Server",
    "severity": "critical",
    "assignee": "security-team@company.com",
    "description": "Critical Apache Struts vulnerability requiring immediate remediation"
  }'
```

**Response:**
```json
{
  "incidentId": "inc_abc123",
  "status": "open",
  "title": "Critical RCE Vulnerability in Production Server",
  "severity": "critical",
  "assignee": "security-team@company.com",
  "createdAt": "2025-01-15T11:00:00Z",
  "slaDeadline": "2025-01-15T15:00:00Z",
  "aiRecommendations": [
    "Isolate affected server from network immediately",
    "Apply security patch or disable affected service",
    "Review access logs for signs of exploitation",
    "Conduct forensic analysis of affected system"
  ]
}
```

### Step 5: Check Compliance Status

Verify your infrastructure against compliance frameworks.

```bash
curl "https://api.adverant.ai/proxy/nexus-cyberagent/api/v1/compliance/pci-dss" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

**Response:**
```json
{
  "framework": "PCI-DSS",
  "version": "4.0",
  "overallScore": 78.5,
  "status": "non-compliant",
  "lastAssessment": "2025-01-15T10:50:00Z",
  "controls": {
    "passed": 156,
    "failed": 23,
    "notApplicable": 12
  },
  "criticalFindings": [
    {
      "controlId": "6.2.4",
      "title": "Patch Management",
      "finding": "3 systems missing critical security patches",
      "remediation": "Apply latest security updates to affected systems"
    }
  ]
}
```

---

## SDK Examples

### TypeScript/JavaScript

```typescript
import { NexusCyberAgent } from '@nexus/cyberagent-sdk';

// Initialize client
const cyber = new NexusCyberAgent({
  apiKey: process.env.NEXUS_API_KEY,
  baseUrl: 'https://api.adverant.ai/proxy/nexus-cyberagent'
});

// Run a vulnerability scan
const scan = await cyber.scan.create({
  scanType: 'vulnerability',
  targets: ['10.0.0.0/24'],
  scanProfile: 'aggressive',
  options: {
    portScan: true,
    serviceDetection: true,
    vulnerabilityDetection: true,
    webApplicationScan: true
  }
});

console.log(`Scan started: ${scan.scanId}`);

// Wait for scan completion
const result = await cyber.scan.waitForCompletion(scan.scanId, {
  pollInterval: 5000,
  timeout: 3600000
});

console.log(`Found ${result.vulnerabilitiesFound} vulnerabilities`);

// Get threats
const threats = await cyber.threats.list({
  scanId: scan.scanId,
  severity: ['critical', 'high'],
  sortBy: 'riskScore',
  order: 'desc'
});

// Create incident for critical threats
for (const threat of threats.filter(t => t.severity === 'critical')) {
  const incident = await cyber.incidents.create({
    threatIds: [threat.threatId],
    title: `Critical: ${threat.title}`,
    severity: 'critical',
    assignee: 'security-team@company.com'
  });

  console.log(`Incident created: ${incident.incidentId}`);
}

// Check compliance status
const compliance = await cyber.compliance.check('soc2');
console.log(`SOC 2 Compliance Score: ${compliance.overallScore}%`);
```

### Python

```python
from nexus_cyberagent import NexusCyberAgent
import os

# Initialize client
client = NexusCyberAgent(
    api_key=os.environ['NEXUS_API_KEY'],
    base_url='https://api.adverant.ai/proxy/nexus-cyberagent'
)

# Run a vulnerability scan
scan = client.scan.create(
    scan_type='vulnerability',
    targets=['10.0.0.0/24'],
    scan_profile='standard',
    options={
        'port_scan': True,
        'service_detection': True,
        'vulnerability_detection': True,
        'os_fingerprinting': True
    }
)

print(f"Scan started: {scan.scan_id}")

# Wait for completion
result = client.scan.wait_for_completion(
    scan.scan_id,
    poll_interval=5,
    timeout=3600
)

print(f"Scan complete: {result.vulnerabilities_found} vulnerabilities found")

# Get critical threats
threats = client.threats.list(
    scan_id=scan.scan_id,
    severity=['critical', 'high']
)

for threat in threats:
    print(f"[{threat.severity.upper()}] {threat.title}")
    print(f"  Host: {threat.affected_host}:{threat.port}")
    print(f"  CVE: {threat.cve_id}")
    print(f"  Risk Score: {threat.ai_analysis.risk_score}")
    print()

# Generate compliance report
compliance = client.compliance.check('iso27001')
print(f"ISO 27001 Compliance: {compliance.overall_score}%")
print(f"Controls Passed: {compliance.controls.passed}")
print(f"Controls Failed: {compliance.controls.failed}")

# Export detailed report
report = client.reports.generate(
    scan_id=scan.scan_id,
    format='pdf',
    include_executive_summary=True,
    include_technical_details=True
)

print(f"Report generated: {report.download_url}")
```

---

## Rate Limits

| Tier | Endpoints | Scans/Month | API Calls/min | Concurrent Scans |
|------|-----------|-------------|---------------|------------------|
| **Starter** | 50 | 100 | 100 | 2 |
| **Professional** | 500 | 1,000 | 500 | 10 |
| **Enterprise** | Unlimited | Unlimited | 2,000 | 50 |

### Pricing

| Tier | Monthly Price | Features |
|------|---------------|----------|
| **Starter** | $299/month | Basic scanning, threat alerts |
| **Professional** | $999/month | Advanced detection, incident response, compliance |
| **Enterprise** | Custom | SOC integration, custom rules, 24x7 monitoring |

---

## Next Steps

Now that you have CyberAgent running, explore these advanced capabilities:

1. **[Automated Penetration Testing](/docs/guides/pentest.md)**: Configure AI-powered penetration tests
2. **[Compliance Automation](/docs/guides/compliance.md)**: Set up continuous compliance monitoring
3. **[Threat Intelligence](/docs/guides/threat-intel.md)**: Integrate external threat feeds
4. **[Incident Response](/docs/guides/ir.md)**: Configure automated incident workflows
5. **[SIEM Integration](/docs/guides/siem.md)**: Connect to your existing SIEM platform

### Useful Resources

- **API Reference**: [docs.adverant.ai/plugins/cyberagent/api](https://docs.adverant.ai/plugins/cyberagent/api)
- **Discord Community**: [discord.gg/adverant](https://discord.gg/adverant)
- **GitHub Examples**: [github.com/adverant/cyberagent-examples](https://github.com/adverant/cyberagent-examples)
- **Support**: support@adverant.ai

---

## Troubleshooting

### Scan Not Starting

1. Verify API key has CyberAgent plugin permissions
2. Check that target IP ranges are in your authorized scope
3. Ensure network connectivity to target systems
4. Review scan quota limits for your tier

### No Vulnerabilities Found

1. Verify target hosts are online and responsive
2. Check firewall rules allow scanning traffic
3. Try increasing scan depth with `aggressive` profile
4. Ensure service detection is enabled

### Compliance Check Failures

1. Verify system credentials are correctly configured
2. Ensure CyberAgent has read access to required systems
3. Check that compliance framework is supported
4. Review system agent deployment status

### High Latency Scans

1. Reduce scan scope to smaller IP ranges
2. Use `quick` scan profile for initial assessment
3. Consider deploying edge scanners for distributed scanning
4. Check network bandwidth between scanner and targets

---

**Need help?** Join our [Discord community](https://discord.gg/adverant) or email support@adverant.ai
