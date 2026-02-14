# Git Policy Synchronization

The WAF supports dynamic policy reloading from a Git repository. This allows you to manage your security policies (rules, main configuration) using GitOps workflows.

## Configuration

To enable Git synchronization, configure the `policy.source` section in your `config/waf.yaml`.

### Basic Example (Public Repo)

```yaml
policy:
  source:
    type: git
    repo: "https://github.com/your-org/waf-policies.git"
    branch: "main"
    poll_interval_seconds: 60
```

### Authentication

#### HTTPS with Token/Password

Use environment variables to store sensitive credentials.

```yaml
policy:
  source:
    type: git
    repo: "https://github.com/your-org/waf-policies.git"
    auth:
      type: https
      username: "oauth2" # or your username
      password_env: "GIT_TOKEN" # Name of env var containing the token
```

#### SSH with Private Key

```yaml
policy:
  source:
    type: git
    repo: "git@github.com:your-org/waf-policies.git"
    auth:
      type: ssh
      ssh_key_path: "/etc/waf/secrets/id_rsa"
```

## How It Works

1. **Initialization**: On startup, the WAF clones the repository into a local `policy_repo` directory.
2. **Polling**: A background task checks for updates at the configured `poll_interval_seconds`.
3. **Reload**: If changes are detected (fast-forward pull), the WAF automatically reloads its configuration and rules.

> **Note**: The repository must contain a `config/waf.yaml` file relative to its root, as this is expected by the WAF loader.

## Troubleshooting

- **Logs**: Check WAF logs for `waf_killer_core::config::git_sync` entries.
- **Conflicts**: If the local repo gets into a conflict state, the WAF will log a warning and stop syncing until manually resolved (by deleting `policy_repo` or fixing via git CLI).
