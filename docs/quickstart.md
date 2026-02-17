# Quickstart Guide

This guide will help you create your first Zentinel agent in under 5 minutes.

## Prerequisites

- Rust 1.75+
- Zentinel proxy (for testing with real traffic)

## Step 1: Create a New Project

```bash
cargo new my-agent
cd my-agent
```

Add dependencies to `Cargo.toml`:

```toml
[dependencies]
zentinel-agent-sdk = "0.1"
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
anyhow = "1"
```

## Step 2: Create Your Agent

Replace the contents of `src/main.rs`:

```rust
use zentinel_agent_sdk::prelude::*;

struct MyAgent;

#[async_trait]
impl Agent for MyAgent {
    fn name(&self) -> &str {
        "my-agent"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        // Log the request
        println!("Processing: {} {}", request.method(), request.path());

        // Block requests to sensitive paths
        if request.path_starts_with("/admin") {
            return Decision::deny()
                .with_body("Access denied")
                .with_tag("blocked");
        }

        // Allow with a custom header
        Decision::allow()
            .add_request_header("X-Processed-By", "my-agent")
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(MyAgent)
        .with_socket("/tmp/my-agent.sock")
        .with_log_level("debug")
        .run()
        .await
}
```

## Step 3: Run the Agent

```bash
cargo run -- --socket /tmp/my-agent.sock --log-level debug
```

You should see:

```
[my-agent] INFO: Agent 'my-agent' listening on /tmp/my-agent.sock
```

## Step 4: Configure Zentinel

Add the agent to your Zentinel configuration (`zentinel.kdl`):

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
        timeout-ms 100
        failure-mode "open"
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

## Step 5: Test It

With Zentinel running, send a test request:

```bash
# This should pass through
curl http://localhost:8080/api/users

# This should be blocked
curl http://localhost:8080/api/admin/settings
```

## Command Line Options

The `AgentRunner` supports these CLI arguments:

| Option | Description | Default |
|--------|-------------|---------|
| `--socket PATH` | Unix socket path | `/tmp/zentinel-agent.sock` |
| `--log-level LEVEL` | Log level (trace, debug, info, warn, error) | `info` |
| `--json-logs` | Enable JSON log format | disabled |

## Next Steps

- Read the [API Reference](api.md) for complete documentation
- See [Examples](examples.md) for common patterns
- Learn about [Zentinel Configuration](configuration.md) options
