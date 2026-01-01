# Sentinel Agent SDK

High-level SDK for building Sentinel proxy agents with less boilerplate.

## Features

- **Simplified types**: `Request`, `Response`, and `Decision` provide ergonomic APIs
- **Fluent decision builder**: Chain methods to build complex responses
- **Configuration handling**: Receive config from proxy's KDL file
- **CLI support**: Built-in argument parsing with clap (optional)
- **Logging**: Automatic tracing setup

## Quick Start

```rust
use sentinel_agent_sdk::prelude::*;

struct MyAgent;

#[async_trait]
impl Agent for MyAgent {
    async fn on_request(&self, request: &Request) -> Decision {
        // Block requests to admin paths without token
        if request.path_starts_with("/admin") && request.header("x-admin-token").is_none() {
            Decision::deny().with_body("Admin access required")
        } else {
            Decision::allow()
                .add_request_header("X-Processed-By", "my-agent")
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(MyAgent)
        .with_name("my-agent")
        .with_socket("/tmp/my-agent.sock")
        .run()
        .await
}
```

## API Overview

### Request

Access request data with convenience methods:

```rust
request.method()           // "GET", "POST", etc.
request.path()             // Full path with query string
request.path_only()        // Path without query string
request.query("key")       // Query parameter value
request.header("name")     // Header value (case-insensitive)
request.client_ip()        // Client IP address
request.body_json::<T>()   // Parse body as JSON
```

### Response

Access response data:

```rust
response.status_code()     // HTTP status code
response.is_success()      // 2xx status
response.is_error()        // 4xx or 5xx
response.header("name")    // Header value
response.body_json::<T>()  // Parse body as JSON
```

### Decision

Build agent responses fluently:

```rust
// Allow with modifications
Decision::allow()
    .add_request_header("X-User", "123")
    .add_response_header("X-Processed", "true")
    .with_tag("authenticated")

// Block with status and body
Decision::block(403)
    .with_body("Access denied")

// Convenience methods
Decision::deny()           // 403 Forbidden
Decision::unauthorized()   // 401 Unauthorized
Decision::rate_limited()   // 429 Too Many Requests
Decision::redirect("/login")
```

## Configuration

Agents can receive configuration from the proxy's KDL config:

```kdl
agent "my-agent" type="custom" {
    unix-socket path="/tmp/my-agent.sock"
    config {
        enabled true
        threshold 100
    }
}
```

Handle configuration in your agent:

```rust
#[async_trait]
impl Agent for MyAgent {
    async fn on_configure(&self, config: serde_json::Value) -> Result<(), String> {
        let my_config: MyConfig = serde_json::from_value(config)
            .map_err(|e| format!("Invalid config: {}", e))?;
        // Store config...
        Ok(())
    }
}
```

## Features

- `cli` (default): Enable CLI argument parsing with clap
- `macros` (default): Enable derive macros

## License

Apache-2.0
