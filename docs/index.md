# Sentinel Agent Rust SDK

A Rust SDK for building agents that integrate with the [Sentinel](https://github.com/raskell-io/sentinel) reverse proxy.

## Overview

Sentinel agents are external processors that can inspect and modify HTTP traffic passing through the Sentinel proxy. They communicate with Sentinel over Unix sockets using a length-prefixed JSON protocol.

Agents can:

- **Inspect requests** - Examine headers, paths, query parameters, and body content
- **Block requests** - Return custom error responses (403, 401, 429, etc.)
- **Redirect requests** - Send clients to different URLs
- **Modify headers** - Add, remove, or modify request/response headers
- **Add audit metadata** - Attach tags, rule IDs, and custom data for logging

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
sentinel-agent-sdk = "0.1"
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
```

## Quick Example

```rust
use sentinel_agent_sdk::prelude::*;

struct MyAgent;

#[async_trait]
impl Agent for MyAgent {
    fn name(&self) -> &str {
        "my-agent"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        // Block requests to /admin
        if request.path_starts_with("/admin") {
            return Decision::deny().with_body("Access denied");
        }

        // Allow everything else
        Decision::allow()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(MyAgent)
        .with_socket("/tmp/my-agent.sock")
        .run()
        .await
}
```

Run the agent:

```bash
cargo run -- --socket /tmp/my-agent.sock
```

## Documentation

- [Quickstart Guide](quickstart.md) - Get up and running in 5 minutes
- [API Reference](api.md) - Complete API documentation
- [Examples](examples.md) - Common patterns and use cases
- [Sentinel Configuration](configuration.md) - How to configure Sentinel to use agents

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│   Client    │────▶│   Sentinel   │────▶│   Upstream   │
└─────────────┘     └──────────────┘     └──────────────┘
                           │
                           │ Unix Socket
                           ▼
                    ┌──────────────┐
                    │    Agent     │
                    │    (Rust)    │
                    └──────────────┘
```

1. Client sends request to Sentinel
2. Sentinel forwards request headers to agent via Unix socket
3. Agent returns a decision (allow, block, redirect)
4. Sentinel applies the decision and forwards to upstream (if allowed)
5. Agent can also process response headers

## Protocol

The SDK implements version 1 of the Sentinel Agent Protocol:

- **Transport**: Unix domain sockets
- **Encoding**: Length-prefixed JSON (4-byte big-endian length prefix)
- **Max message size**: 10MB

## License

Apache 2.0
