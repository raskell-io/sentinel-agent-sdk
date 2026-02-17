# Getting Started with Zentinel Agent Rust SDK

This guide will walk you through creating your first Zentinel agent in Rust.

## Prerequisites

- Rust 1.70 or later
- A running Zentinel proxy instance (or just the SDK for development)

## Installation

Add the SDK to your `Cargo.toml`:

```toml
[dependencies]
zentinel-agent-sdk = { git = "https://github.com/zentinelproxy/zentinel-agent-rust-sdk" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Your First Agent

Create a new file `src/main.rs`:

```rust
use zentinel_agent_sdk::prelude::*;

struct MyAgent;

#[async_trait]
impl Agent for MyAgent {
    fn name(&self) -> &str {
        "my-agent"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        // Block requests to /admin paths
        if request.path_starts_with("/admin") {
            return Decision::deny().with_body("Access denied");
        }

        // Allow all other requests
        Decision::allow()
    }
}

#[tokio::main]
async fn main() {
    AgentRunner::new(MyAgent)
        .with_name("my-agent")
        .run()
        .await
        .unwrap();
}
```

## Running Your Agent

```bash
cargo run -- --socket /tmp/my-agent.sock
```

Your agent is now listening on `/tmp/my-agent.sock` and ready to receive events from Zentinel.

## Understanding the Agent Lifecycle

When Zentinel connects to your agent, the following events can occur:

1. **Configure** - Receive configuration from Zentinel's KDL file
2. **Request Headers** - Inspect incoming request headers
3. **Request Body** - Inspect request body (if enabled)
4. **Response Headers** - Inspect response from upstream
5. **Response Body** - Inspect response body (if enabled)
6. **Request Complete** - Notification when request finishes

## Making Decisions

The `Decision` builder provides a fluent API for constructing responses:

```rust
// Allow the request
Decision::allow()

// Block with 403 Forbidden
Decision::deny()

// Block with custom status
Decision::block(429).with_body("Too many requests")

// Redirect
Decision::redirect("/login")

// Allow with header modifications
Decision::allow()
    .add_request_header("X-User-ID", "12345")
    .add_response_header("X-Cache", "HIT")
    .remove_response_header("Server")

// Add audit metadata
Decision::deny()
    .with_tag("security")
    .with_metadata("reason", serde_json::json!("blocked by rule"))
```

## Working with Requests

The `Request` type provides convenient methods for inspecting HTTP requests:

```rust
async fn on_request(&self, request: &Request) -> Decision {
    // Path inspection
    let path = request.path();
    if request.path_starts_with("/api/") { /* ... */ }
    if request.path_equals("/health") { /* ... */ }

    // Headers (case-insensitive)
    let auth = request.header("Authorization");
    let user_agent = request.user_agent();
    let content_type = request.content_type();

    // Request metadata
    let client_ip = request.client_ip();
    let method = request.method();
    let correlation_id = request.correlation_id();

    Decision::allow()
}
```

## Working with Responses

Inspect upstream responses before they reach the client:

```rust
async fn on_response(&self, request: &Request, response: &Response) -> Decision {
    // Check status code
    if response.status_code() >= 500 {
        return Decision::allow().with_tag("upstream-error");
    }

    // Inspect headers
    let content_type = response.header("Content-Type");

    // Add security headers
    Decision::allow()
        .add_response_header("X-Frame-Options", "DENY")
        .add_response_header("X-Content-Type-Options", "nosniff")
}
```

## Typed Configuration

For agents with configuration, use `ConfigurableAgent`:

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
struct MyConfig {
    rate_limit: u32,
    enabled: bool,
}

struct MyAgent {
    config: std::sync::RwLock<MyConfig>,
}

#[async_trait]
impl Agent for MyAgent {
    fn name(&self) -> &str {
        "my-configurable-agent"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        let config = self.config.read().unwrap();
        if !config.enabled {
            return Decision::allow();
        }
        // Use config.rate_limit...
        Decision::allow()
    }
}
```

## Connecting to Zentinel

Configure Zentinel to use your agent in its KDL configuration:

```kdl
agents {
    agent "my-agent" type="custom" {
        unix-socket path="/tmp/my-agent.sock"
        events "request_headers"
        timeout-ms 100
        failure-mode "open"
    }
}

filters {
    filter "my-filter" {
        type "agent"
        agent "my-agent"
    }
}

routes {
    route "api" {
        matches {
            path-prefix "/api/"
        }
        upstream "backend"
        filters "my-filter"
    }
}
```

## CLI Options

The SDK provides built-in CLI argument parsing:

```bash
# Basic usage
cargo run -- --socket /tmp/my-agent.sock

# With options
cargo run -- \
    --socket /tmp/my-agent.sock \
    --log-level DEBUG \
    --json-logs
```

| Option | Description | Default |
|--------|-------------|---------|
| `--socket PATH` | Unix socket path | `/tmp/zentinel-agent.sock` |
| `--log-level LEVEL` | DEBUG, INFO, WARNING, ERROR | `INFO` |
| `--json-logs` | Output logs as JSON | disabled |

## Error Handling

Use Rust's error handling patterns:

```rust
async fn on_request(&self, request: &Request) -> Decision {
    match validate_token(request.header("Authorization")) {
        Ok(user_id) => {
            Decision::allow()
                .add_request_header("X-User-ID", &user_id)
        }
        Err(e) => {
            Decision::unauthorized()
                .with_body(&format!("Invalid token: {}", e))
                .with_tag("auth-failed")
        }
    }
}
```

## Testing Your Agent

Create unit tests for your agent logic:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_blocks_admin_path() {
        let agent = MyAgent;
        let request = Request::builder()
            .path("/admin/users")
            .build();

        let decision = agent.on_request(&request).await;
        // Assert decision is a block
    }
}
```

## Next Steps

- Read the [API Reference](api.md) for complete documentation
- Browse [Examples](examples.md) for common patterns
- See [Configuration](configuration.md) for Zentinel setup options

## Need Help?

- [GitHub Issues](https://github.com/zentinelproxy/zentinel-agent-rust-sdk/issues)
- [Zentinel Documentation](https://zentinelproxy.io/docs)
