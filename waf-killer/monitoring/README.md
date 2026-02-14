# Shibuya WAF - Monitoring Setup

## Quick Start

### 1. Import Grafana Dashboard

```bash
# Grafana UI
1. Go to Dashboards → Import
2. Upload: monitoring/grafana-dashboard.json
3. Select Prometheus datasource
4. Click Import
```

### 2. Prometheus Metrics

WAF exposes metrics at `http://localhost:9090/metrics`:

- `shibuya_requests_total` - Total requests
- `shibuya_requests_blocked_total` - Blocked requests
- `shibuya_ml_anomaly_score` - ML anomaly scores
- `shibuya_threat_intel_blocks_total` - Threat intel blocks
- `shibuya_request_duration_seconds` - Request latency

### 3. Alerts (Prometheus)

Create `monitoring/alerts.yml`:

```yaml
groups:
  - name: shibuya_alerts
    interval: 30s
    rules:
      - alert: HighBlockRate
        expr: rate(shibuya_requests_blocked_total[5m]) > 100
        for: 2m
        annotations:
          summary: "High block rate detected"
      
      - alert: MLAnomalySpike
        expr: avg(shibuya_ml_anomaly_score) > 0.8
        for: 5m
        annotations:
          summary: "Sustained high ML anomaly scores"
```

## Log Analysis

Logs are JSON-structured:

```bash
# Follow logs
docker logs -f shibuya-waf | jq .

# Count blocks by reason
cat /var/log/shibuya/waf.log | jq -r '.reason' | sort | uniq -c
```
