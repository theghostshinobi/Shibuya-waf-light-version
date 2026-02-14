# API Protection Configuration

## Overview

The API Protection module provides runtime security for APIs, including:

- **OpenAPI Validation**: Validates incoming requests against OpenAPI 3.x specifications
- **GraphQL Protection**: Defends against GraphQL-specific attacks (depth bombs, complexity attacks, alias flooding)

Enable it in production for any public-facing API or GraphQL endpoint.

## Configuration Reference

Add the `api_protection` section to your `config/waf.yaml`:

```yaml
api_protection:
  enabled: true
  
  openapi_specs:
    - "rules/openapi/api-v1.yaml"
  
  graphql:
    endpoint: "/graphql"
    max_depth: 10
    max_complexity: 1000
    max_batch_size: 10
    max_aliases: 50
    introspection_enabled: false
    
    rate_limits:
      query:
        requests_per_minute: 1000
        complexity_per_minute: 10000
      mutation:
        requests_per_minute: 100
        complexity_per_minute: 1000
      subscription:
        requests_per_minute: 10
        complexity_per_minute: 500
    
    field_costs:
      "User.posts": 10
      "Post.comments": 5
      "Admin.secrets": 100
    
    auth_rules:
      - field_path: "User.email"
        required_roles: ["authenticated"]
      - field_path: "Admin.*"
        required_roles: ["admin"]
```

## Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Master switch for the module |
| `openapi_specs` | array | `[]` | Paths to OpenAPI 3.x spec files |
| `graphql.endpoint` | string | `/graphql` | GraphQL endpoint path |
| `graphql.max_depth` | int | `10` | Max query nesting depth (1-50) |
| `graphql.max_complexity` | int | `1000` | Max complexity score |
| `graphql.max_batch_size` | int | `10` | Max queries per batch |
| `graphql.max_aliases` | int | `50` | Max aliases per query |
| `graphql.introspection_enabled` | bool | `false` | Allow introspection queries |

## Best Practices

### Production
```yaml
api_protection:
  enabled: true
  graphql:
    introspection_enabled: false
    max_depth: 10
    max_complexity: 1000
```

### Development
```yaml
api_protection:
  enabled: true
  graphql:
    introspection_enabled: true
    max_depth: 20
    max_complexity: 5000
```

## Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| "OpenAPI validation failed" | Request doesn't match spec | Check spec vs actual request format |
| "GraphQL depth limit exceeded" | Query too deeply nested | Refactor query or increase `max_depth` |
| "GraphQL complexity exceeded" | Query too expensive | Reduce query scope or increase `max_complexity` |
| "Field authorization failed" | Missing required role | Verify user has correct roles |
