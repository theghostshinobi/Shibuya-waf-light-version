# Configuration Persistence & Management

WAF Shibuya implements a robust, production-grade configuration management system designed for zero-downtime operations and crash safety.

## 🛡️ Safety Features

### Atomic Writes
All configuration changes are performed atomically:
1. New config is written to a temporary file
2. `fsync` is called to flush to disk
3. `rename` is called to swap the file pointers
**Result**: The configuration file is NEVER in a corrupted state, even if the server crashes or power is lost during a write.

### Automatic Backups
Before any change is applied:
1. The current configuration is backed up to `config/backups/`
2. Backup format: `waf.yaml.YYYYMMDD_HHMMSS.bak`
3. Retention policy: Last 10 backups are kept; older ones are automatically rotated.

### Validation Engine
The WAF rejects usage-breaking configurations BEFORE they are saved.
- **Syntactic**: Invalid types, missing fields
- **Semantic**: Logic errors (e.g., blocking threshold < challenge threshold)
- **Dependency**: Referenced files (certificates, rules, ML models) must exist

## 📜 Audit Logging

Every configuration change is logged to an immutable audit trail.

**Location**: `config/config_changes.jsonl`

**Format**:
```json
{
  "timestamp": "2026-02-05T09:19:00Z",
  "user": "admin",
  "source_ip": "127.0.0.1",
  "changes": [
    {
      "field": "ml.threshold",
      "old_value": "0.7",
      "new_value": "0.85"
    }
  ],
  "backup_path": "config/backups/waf.yaml.20260205_091900.bak",
  "validation_passed": true,
  "applied": true
}
```

## 🔄 Rollback API

If a bad configuration bypasses validation or causes operational issues, you can instantly rollback.

### 1. List Backups
`GET /api/config/backups`

### 2. Rollback
`POST /api/config/rollback`

Payload (Optional):
```json
{
  "backup_timestamp": "waf.yaml.20260205_091900.bak"
}
```
*If no timestamp is provided, rolls back to the most recent backup.*

## 🛠️ Manual Recovery

If the API is inaccessible, you can manually restore configuration via CLI:

1. Stop the WAF: `systemctl stop waf-shibuya`
2. List backups: `ls -l config/backups/`
3. Restore: `cp config/backups/waf.yaml.TARGET.bak config/waf.yaml`
4. Start WAF: `systemctl start waf-shibuya`

## ⚡ Hot Reloading

The following components update instantly without process restart:
- **ML Thresholds**
- **Rate Limit Parameters** (Burst/RPS)
- **Bot Detection Settings**
- **Rule Engine** (Paranoia levels)

*Note: Changing listening ports or TLS certificates still requires a process restart.*
