# Manual Test Procedure: Git Auto-Reload

## Prerequisites
- A Git repository (local or remote) to act as the policy source.
- WAF binary built (`cargo build`).

## Test Steps

### 1. Setup Policy Repo
Create a new directory for the policy repo:
```bash
mkdir -p /tmp/waf-policy-test
cd /tmp/waf-policy-test
git init
mkdir config
# Copy existing waf.yaml to config/waf.yaml
cp /path/to/waf-killer/config/waf.yaml config/
git add .
git commit -m "Initial policy"
```

### 2. Configure WAF
Edit your local `config/waf.yaml` to point to this repo:
```yaml
policy:
  source:
    type: git
    repo: "/tmp/waf-policy-test"
    branch: "master" # or main
    poll_interval_seconds: 5
```

### 3. Start WAF
Run the WAF:
```bash
cargo run --bin waf-killer-core
```
**Verify**:
- Logs show "Cloning policy repository..."
- `policy_repo` directory is created in WAF working directory.

### 4. Trigger Reload
In another terminal, modify the policy repo:
```bash
cd /tmp/waf-policy-test
echo "# Test comment" >> config/waf.yaml
git add .
git commit -m "Update policy config"
```

**Verify**:
- Within 5 seconds, WAF logs should show:
  - "Pulled new changes"
  - "Policy update detected and reload requested"
  - "Configuration reloaded successfully"

### 5. Verify Failure Handling (Optional)
Modify the policy repo with invalid YAML:
```bash
echo "invalid: [ yaml" >> config/waf.yaml
git commit -am "Break config"
```
**Verify**:
- WAF logs an error during reload but **does not crash**.
- Previous configuration remains active.
