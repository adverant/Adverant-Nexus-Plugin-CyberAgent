# Nexus-CyberAgent Kubernetes Deployment

Kubernetes manifests and Helm charts for deploying Nexus-CyberAgent to production Kubernetes clusters.

## Overview

This directory contains:
- **helm/**: Helm chart for easy deployment
- **manifests/**: Raw Kubernetes YAML manifests
- **configs/**: ConfigMaps and Secrets templates

## Prerequisites

- Kubernetes 1.28+
- kubectl configured
- Helm 3.12+
- Persistent Volume provisioner
- Ingress controller (nginx/traefik)
- Nexus services deployed and accessible

## Quick Start with Helm

### 1. Add Helm Repository (if publishing)

```bash
helm repo add adverant https://charts.adverant.ai
helm repo update
```

### 2. Create Namespace

```bash
kubectl create namespace nexus-cyberagent
```

### 3. Create Secrets

```bash
# Create secrets from .env file
kubectl create secret generic nexus-secrets \
  --from-env-file=../.env.production \
  -n nexus-cyberagent

# Or create manually
kubectl create secret generic nexus-secrets \
  --from-literal=DATABASE_URL=postgresql://... \
  --from-literal=REDIS_URL=redis://... \
  --from-literal=JWT_SECRET=... \
  --from-literal=ENCRYPTION_MASTER_KEY=... \
  -n nexus-cyberagent
```

### 4. Deploy with Helm

```bash
# Install
helm install nexus-cyberagent ./helm/nexus-cyberagent \
  -n nexus-cyberagent \
  -f ./helm/nexus-cyberagent/values.production.yaml

# Upgrade
helm upgrade nexus-cyberagent ./helm/nexus-cyberagent \
  -n nexus-cyberagent \
  -f ./helm/nexus-cyberagent/values.production.yaml

# Uninstall
helm uninstall nexus-cyberagent -n nexus-cyberagent
```

### 5. Verify Deployment

```bash
# Check pods
kubectl get pods -n nexus-cyberagent

# Check services
kubectl get svc -n nexus-cyberagent

# Check ingress
kubectl get ingress -n nexus-cyberagent

# View logs
kubectl logs -f -l app=nexus-api -n nexus-cyberagent
```

## Manual Deployment with Manifests

If not using Helm:

```bash
# Deploy in order
kubectl apply -f manifests/namespace.yaml
kubectl apply -f manifests/configmap.yaml
kubectl apply -f manifests/secrets.yaml
kubectl apply -f manifests/postgres.yaml
kubectl apply -f manifests/redis.yaml
kubectl apply -f manifests/api.yaml
kubectl apply -f manifests/worker.yaml
kubectl apply -f manifests/ingress.yaml
```

## Configuration

### Helm Values

Edit `helm/nexus-cyberagent/values.production.yaml`:

```yaml
replicaCount:
  api: 3
  worker: 5

image:
  api:
    repository: adverant/nexus-cyberagent-api
    tag: "1.0.0"
  worker:
    repository: adverant/nexus-cyberagent-worker
    tag: "1.0.0"

resources:
  api:
    requests:
      cpu: 1000m
      memory: 2Gi
    limits:
      cpu: 2000m
      memory: 4Gi
  worker:
    requests:
      cpu: 2000m
      memory: 4Gi
    limits:
      cpu: 4000m
      memory: 8Gi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: nexus.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: nexus-tls
      hosts:
        - nexus.example.com
```

### Resource Limits

Recommended resource allocation:

| Component | CPU Request | CPU Limit | Memory Request | Memory Limit |
|-----------|------------|-----------|----------------|--------------|
| API       | 1 core     | 2 cores   | 2 GB          | 4 GB         |
| Worker    | 2 cores    | 4 cores   | 4 GB          | 8 GB         |
| PostgreSQL| 2 cores    | 4 cores   | 4 GB          | 8 GB         |
| Redis     | 500m       | 1 core    | 1 GB          | 2 GB         |

### Persistent Storage

PersistentVolumeClaims for:
- PostgreSQL data: 500 GB
- Redis persistence: 50 GB
- Malware samples storage: 1 TB

## Monitoring

### Prometheus Integration

ServiceMonitor for Prometheus Operator:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: nexus-api
spec:
  selector:
    matchLabels:
      app: nexus-api
  endpoints:
    - port: metrics
      path: /metrics
```

### Grafana Dashboards

Import dashboards from `monitoring/grafana-dashboard.json`.

## High Availability

### Database

Use PostgreSQL with replication:

```yaml
postgresql:
  replication:
    enabled: true
    numSynchronousReplicas: 2
  persistence:
    size: 500Gi
    storageClass: fast-ssd
```

### Redis

Use Redis Sentinel for HA:

```yaml
redis:
  sentinel:
    enabled: true
    quorum: 2
  replica:
    replicaCount: 3
```

### API & Workers

Horizontal Pod Autoscaling:

```bash
kubectl autoscale deployment nexus-api \
  --cpu-percent=70 \
  --min=3 \
  --max=10 \
  -n nexus-cyberagent

kubectl autoscale deployment nexus-worker \
  --cpu-percent=70 \
  --min=5 \
  --max=20 \
  -n nexus-cyberagent
```

## Security

### Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: nexus-network-policy
spec:
  podSelector:
    matchLabels:
      app: nexus
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: nexus-cyberagent
      ports:
        - protocol: TCP
          port: 3000
```

### Pod Security Standards

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: nexus-cyberagent
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### RBAC

Service accounts with minimal permissions:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: nexus-api
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: nexus-api-role
rules:
  - apiGroups: [""]
    resources: ["configmaps", "secrets"]
    verbs: ["get", "list"]
```

## Backup & Disaster Recovery

### Velero Backup

```bash
# Install Velero
velero install \
  --provider aws \
  --bucket nexus-backups \
  --backup-location-config region=us-east-1

# Create backup schedule
velero schedule create nexus-daily \
  --schedule="0 2 * * *" \
  --include-namespaces nexus-cyberagent
```

### Database Backups

CronJob for automated backups:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgres-backup
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: backup
              image: postgres:15
              command:
                - /bin/sh
                - -c
                - pg_dump $DATABASE_URL | gzip > /backups/backup-$(date +%Y%m%d).sql.gz
```

## Troubleshooting

### Common Issues

#### Pods Not Starting

```bash
# Check pod status
kubectl get pods -n nexus-cyberagent

# Describe pod
kubectl describe pod <pod-name> -n nexus-cyberagent

# Check logs
kubectl logs <pod-name> -n nexus-cyberagent
```

#### Database Connection Issues

```bash
# Test database connectivity
kubectl run -it --rm debug --image=postgres:15 --restart=Never -- \
  psql $DATABASE_URL -c "SELECT 1"
```

#### Nexus Services Unreachable

```bash
# Check DNS resolution
kubectl run -it --rm debug --image=busybox --restart=Never -- \
  nslookup nexus-graphrag

# Test connectivity
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://nexus-graphrag:9001/health
```

## Scaling

### Manual Scaling

```bash
# Scale API pods
kubectl scale deployment nexus-api --replicas=5 -n nexus-cyberagent

# Scale worker pods
kubectl scale deployment nexus-worker --replicas=10 -n nexus-cyberagent
```

### Cluster Autoscaler

Enable Cluster Autoscaler for automatic node scaling:

```yaml
apiVersion: autoscaling.k8s.io/v1
kind: ClusterAutoscaler
metadata:
  name: cluster-autoscaler
spec:
  scaleDown:
    enabled: true
    delayAfterAdd: 10m
  scaleUp:
    enabled: true
```

## Maintenance

### Rolling Updates

```bash
# Update API image
kubectl set image deployment/nexus-api \
  api=adverant/nexus-cyberagent-api:1.1.0 \
  -n nexus-cyberagent

# Check rollout status
kubectl rollout status deployment/nexus-api -n nexus-cyberagent

# Rollback if needed
kubectl rollout undo deployment/nexus-api -n nexus-cyberagent
```

### Database Migrations

```bash
# Run migrations as a Job
kubectl apply -f manifests/migration-job.yaml

# Check migration logs
kubectl logs job/db-migration -n nexus-cyberagent
```

## Support

For issues or questions:
- Documentation: `/docs`
- GitHub Issues: https://github.com/adverant/nexus-cyberagent
- Email: support@adverant.ai
