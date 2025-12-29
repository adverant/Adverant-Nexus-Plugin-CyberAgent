# Network Isolation Configuration

## Overview

This directory contains network isolation configurations for the Testing Sandbox (Tier 2). The sandbox is isolated from production systems and only allowed to communicate with:

1. **API Gateway** (172.28.0.10:9260) - For job coordination
2. **DNS Services** (port 53) - For domain resolution
3. **Authorized Targets** - Dynamically configured based on scan jobs

## Network Architecture

```
┌─────────────────────────────────────────────────────┐
│  Unified Nexus Network (172.20.0.0/16)             │
│  ┌──────────────┐      ┌───────────────┐          │
│  │ API Gateway  │      │ PostgreSQL    │          │
│  │ 172.20.0.10  │      │ 172.20.0.20   │          │
│  └──────┬───────┘      └───────────────┘          │
│         │                                          │
└─────────┼──────────────────────────────────────────┘
          │
          │ Restricted Communication (Port 9260 only)
          │
┌─────────▼──────────────────────────────────────────┐
│  Testing Sandbox Network (172.28.0.0/16)          │
│  ┌──────────────────────────────────┐             │
│  │  Testing Sandbox Container       │             │
│  │  - Kali Linux                    │             │
│  │  - Security Tools                │             │
│  │  - FastAPI Server (9260)         │             │
│  │  IP: 172.28.0.20                 │             │
│  └──────────────────────────────────┘             │
│                                                    │
│  Egress Filtering:                                │
│  ✅ DNS (53)                                       │
│  ✅ API Gateway (9260)                            │
│  ✅ Authorized Targets (dynamic)                  │
│  ❌ All other traffic BLOCKED                     │
└────────────────────────────────────────────────────┘
          │
          │ Scanning Traffic (Controlled)
          │
┌─────────▼──────────────────────────────────────────┐
│  Scan Targets (External or Test)                  │
│  - Authorized domains/IPs only                     │
│  - Verified via target_authorizations table        │
└────────────────────────────────────────────────────┘
```

## Files

### setup-isolation.sh
Shell script that configures iptables rules for network isolation.

**Usage:**
```bash
sudo ./setup-isolation.sh
```

**What it does:**
- Creates custom `SANDBOX_FILTER` iptables chain
- Blocks all outbound traffic by default
- Allows only DNS and API Gateway communication
- Logs blocked connection attempts

### iptables-rules.conf
Persistent iptables rules configuration file.

**Apply rules:**
```bash
sudo iptables-restore < iptables-rules.conf
```

**Save current rules:**
```bash
sudo iptables-save > iptables-rules.conf
```

## Security Features

### 1. Default Deny Policy
All traffic is blocked by default. Only explicitly allowed connections are permitted.

### 2. Rate Limiting
- Maximum 1000 concurrent connections
- Maximum 1000 connections per second
- Prevents abuse and DoS from compromised sandbox

### 3. Connection Logging
All blocked connection attempts are logged to syslog with prefix `SANDBOX_DROP:` or `SANDBOX_BLOCKED:`.

**View logs:**
```bash
sudo tail -f /var/log/syslog | grep SANDBOX
```

### 4. Dynamic Target Authorization
Scan targets are authorized dynamically by the API Gateway based on the `target_authorizations` table. Unauthorized targets are blocked at the network level.

## Testing Network Isolation

### Test 1: Verify API Gateway Access
```bash
docker exec nexus-testing-sandbox curl -v http://172.28.0.10:9260/health
# Expected: Success (200 OK)
```

### Test 2: Verify Internet Blocking
```bash
docker exec nexus-testing-sandbox curl -v https://google.com
# Expected: Timeout or connection refused
```

### Test 3: Verify DNS Resolution
```bash
docker exec nexus-testing-sandbox nslookup example.com
# Expected: Success (DNS works)
```

### Test 4: Verify Production Network Blocking
```bash
docker exec nexus-testing-sandbox curl -v http://172.20.0.20:5432
# Expected: Connection refused (PostgreSQL blocked)
```

## Troubleshooting

### Issue: Sandbox cannot reach API Gateway
**Check:**
1. Verify iptables rules: `sudo iptables -L SANDBOX_FILTER -n -v`
2. Check Docker network: `docker network inspect cyberagent-test-network`
3. Verify API Gateway is running: `docker ps | grep api-gateway`

**Solution:**
```bash
# Reload iptables rules
sudo ./setup-isolation.sh

# Restart sandbox container
docker restart nexus-testing-sandbox
```

### Issue: Legitimate scan targets are blocked
**Check:**
1. Verify target is authorized in `target_authorizations` table
2. Check iptables logs: `sudo grep SANDBOX /var/log/syslog`
3. Verify dynamic rules are loaded

**Solution:**
Add target to authorization table via API Gateway:
```bash
curl -X POST http://localhost:8250/api/v1/authorizations \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.100", "org_id": "...", "verified": true}'
```

## Maintenance

### Monthly Tasks
- Review iptables logs for anomalies
- Update authorized target list
- Test isolation rules
- Verify no unauthorized traffic

### Updating Rules
1. Edit `iptables-rules.conf`
2. Test in staging: `sudo iptables-restore < iptables-rules.conf`
3. Verify with tests above
4. Deploy to production
5. Save persistent: `sudo iptables-save > /etc/iptables/rules.v4`

## Emergency Procedures

### Disable Isolation (Emergency Only)
```bash
# Flush sandbox rules
sudo iptables -F SANDBOX_FILTER
sudo iptables -X SANDBOX_FILTER

# Re-enable after incident
sudo ./setup-isolation.sh
```

### Monitor Active Connections
```bash
# View all sandbox connections
sudo iptables -L SANDBOX_FILTER -n -v --line-numbers

# Monitor in real-time
watch -n 1 'sudo iptables -L SANDBOX_FILTER -n -v'
```

## Compliance Notes

This network isolation configuration supports:
- **PCI DSS**: Network segmentation (Requirement 1.3)
- **ISO 27001**: Network security controls (A.13.1)
- **NIST CSF**: Network segmentation (PR.AC-5)
- **SOC 2**: Network isolation controls

Isolation logs should be retained for 90 days for audit purposes.
