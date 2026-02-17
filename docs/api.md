# API Reference

## Agent

The trait for all Zentinel agents.

```rust
use zentinel_agent_sdk::prelude::*;
```

### Required Methods

#### `name()`

```rust
fn name(&self) -> &str
```

Returns the agent identifier used for logging.

### Event Handlers

#### `on_configure`

```rust
async fn on_configure(&self, config: serde_json::Value) -> Result<(), String>
```

Called when the agent receives configuration from the proxy. Override to validate and store configuration.

**Default**: Returns `Ok(())`

#### `on_request`

```rust
async fn on_request(&self, request: &Request) -> Decision
```

Called when request headers are received. This is the main entry point for request processing.

**Default**: Returns `Decision::allow()`

#### `on_request_body`

```rust
async fn on_request_body(&self, request: &Request) -> Decision
```

Called when the request body is available (requires body inspection to be enabled in Zentinel).

**Default**: Returns `Decision::allow()`

#### `on_response`

```rust
async fn on_response(&self, request: &Request, response: &Response) -> Decision
```

Called when response headers are received from the upstream server.

**Default**: Returns `Decision::allow()`

#### `on_response_body`

```rust
async fn on_response_body(&self, request: &Request, response: &Response) -> Decision
```

Called when the response body is available (requires body inspection to be enabled).

**Default**: Returns `Decision::allow()`

#### `on_request_complete`

```rust
async fn on_request_complete(&self, request: &Request, status: u16, duration_ms: u64)
```

Called when request processing is complete. Use for logging or metrics.

### Example Implementation

```rust
struct MyAgent;

#[async_trait]
impl Agent for MyAgent {
    fn name(&self) -> &str {
        "my-agent"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        Decision::allow()
    }
}
```

---

## ConfigurableAgent

A trait for agents with typed configuration support.

```rust
use zentinel_agent_sdk::{ConfigurableAgent, ConfigurableAgentExt};
use serde::Deserialize;
use tokio::sync::RwLock;

#[derive(Default, Deserialize)]
struct RateLimitConfig {
    requests_per_minute: u32,
    enabled: bool,
}

struct RateLimitAgent {
    config: RwLock<RateLimitConfig>,
}

impl ConfigurableAgent for RateLimitAgent {
    type Config = RateLimitConfig;

    fn config(&self) -> &RwLock<Self::Config> {
        &self.config
    }

    fn on_config_applied(&self, config: &RateLimitConfig) {
        println!("Rate limit set to {}/min", config.requests_per_minute);
    }
}

#[async_trait]
impl Agent for RateLimitAgent {
    fn name(&self) -> &str {
        "rate-limiter"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        let config = self.config.read().await;
        if !config.enabled {
            return Decision::allow();
        }
        // Use config.requests_per_minute...
        Decision::allow()
    }
}
```

### Methods

#### `config()`

```rust
fn config(&self) -> &RwLock<Self::Config>
```

Returns a reference to the RwLock containing the configuration.

#### `on_config_applied()`

```rust
fn on_config_applied(&self, config: &Self::Config)
```

Called after new configuration has been applied.

---

## Decision

Fluent builder for agent decisions.

```rust
use zentinel_agent_sdk::Decision;
```

### Factory Functions

#### `allow()`

Create an allow decision (pass request through).

```rust
Decision::allow()
```

#### `block(status: u16)`

Create a block decision with a status code.

```rust
Decision::block(403)
Decision::block(500)
```

#### `deny()`

Shorthand for `block(403)`.

```rust
Decision::deny()
```

#### `unauthorized()`

Shorthand for `block(401)`.

```rust
Decision::unauthorized()
```

#### `rate_limited()`

Shorthand for `block(429)`.

```rust
Decision::rate_limited()
```

#### `redirect(url: &str)`

Create a redirect decision (302 temporary).

```rust
Decision::redirect("https://example.com/login")
```

#### `redirect_permanent(url: &str)`

Create a permanent redirect (301).

```rust
Decision::redirect_permanent("https://example.com/new-path")
```

#### `challenge(challenge_type: &str, params: HashMap<String, String>)`

Create a challenge decision (e.g., CAPTCHA, JavaScript challenge).

```rust
use std::collections::HashMap;

// Simple challenge with no params
Decision::challenge("js_challenge", HashMap::new())

// Challenge with parameters
let mut params = HashMap::new();
params.insert("site_key".to_string(), "abc123".to_string());
Decision::challenge("captcha", params)
```

### Chaining Methods

All methods return `Decision` for chaining.

#### `with_body(body: &str)`

Set the response body for block decisions.

```rust
Decision::deny().with_body("Access denied")
```

#### `with_json_body(value: &T)`

Set a JSON response body. Automatically sets `Content-Type: application/json`.

```rust
Decision::block(400).with_json_body(&json!({"error": "Invalid request"}))
```

#### `with_block_header(name: &str, value: &str)`

Add a header to the block response.

```rust
Decision::deny().with_block_header("X-Blocked-By", "my-agent")
```

#### `add_request_header(name: &str, value: &str)`

Add a header to the upstream request.

```rust
Decision::allow().add_request_header("X-User-ID", "123")
```

#### `remove_request_header(name: &str)`

Remove a header from the upstream request.

```rust
Decision::allow().remove_request_header("Cookie")
```

#### `add_response_header(name: &str, value: &str)`

Add a header to the client response.

```rust
Decision::allow().add_response_header("X-Frame-Options", "DENY")
```

#### `remove_response_header(name: &str)`

Remove a header from the client response.

```rust
Decision::allow().remove_response_header("Server")
```

### Audit Methods

#### `with_tag(tag: &str)`

Add an audit tag.

```rust
Decision::deny().with_tag("security")
```

#### `with_tags(tags: &[&str])`

Add multiple audit tags.

```rust
Decision::deny().with_tags(&["blocked", "rate-limit"])
```

#### `with_rule_id(rule_id: &str)`

Add a rule ID for audit logging.

```rust
Decision::deny().with_rule_id("SQLI-001")
```

#### `with_confidence(confidence: f64)`

Set a confidence score (0.0 to 1.0).

```rust
Decision::deny().with_confidence(0.95)
```

#### `with_reason_code(code: &str)`

Add a reason code.

```rust
Decision::deny().with_reason_code("IP_BLOCKED")
```

#### `with_metadata(key: &str, value: serde_json::Value)`

Add custom audit metadata.

```rust
Decision::deny().with_metadata("blocked_ip", json!("192.168.1.100"))
```

### Advanced Methods

#### `needs_more_data()`

Indicate that more data is needed before deciding.

```rust
Decision::allow().needs_more_data()
```

#### `with_routing_metadata(key: &str, value: &str)`

Add routing metadata for upstream selection.

```rust
Decision::allow().with_routing_metadata("upstream", "backend-v2")
```

#### `with_request_body_mutation(mutation: BodyMutation)`

Set a mutation for the request body.

```rust
use zentinel_agent_protocol::BodyMutation;

// Replace chunk content
Decision::allow().with_request_body_mutation(BodyMutation::replace(0, "modified body".to_string()))

// Drop a chunk
Decision::allow().with_request_body_mutation(BodyMutation::drop_chunk(0))

// Pass through unchanged
Decision::allow().with_request_body_mutation(BodyMutation::pass_through(0))
```

#### `with_response_body_mutation(mutation: BodyMutation)`

Set a mutation for the response body.

```rust
use zentinel_agent_protocol::BodyMutation;

Decision::allow().with_response_body_mutation(BodyMutation::replace(0, "modified body".to_string()))
```

---

## Request

Represents an incoming HTTP request.

```rust
use zentinel_agent_sdk::Request;
```

### Methods

#### `method()`

The HTTP method (GET, POST, etc.).

```rust
if request.method() == "POST" { ... }
```

#### `path()`

The request path without query string.

```rust
let path = request.path(); // "/api/users"
```

#### `uri()`

The full URI including query string.

```rust
let uri = request.uri(); // "/api/users?page=1"
```

#### `query_string()`

The raw query string.

```rust
let qs = request.query_string(); // "page=1&limit=10"
```

#### `path_starts_with(prefix: &str)`

Check if the path starts with a prefix.

```rust
if request.path_starts_with("/api/") { ... }
```

#### `path_equals(path: &str)`

Check if the path exactly matches.

```rust
if request.path_equals("/health") { ... }
```

### Header Methods

#### `header(name: &str)`

Get a header value (case-insensitive).

```rust
let auth = request.header("authorization");
```

#### `header_all(name: &str)`

Get all values for a header.

```rust
let accepts = request.header_all("accept");
```

#### `has_header(name: &str)`

Check if a header exists.

```rust
if request.has_header("Authorization") { ... }
```

#### `headers()`

Get all headers as a HashMap.

```rust
let headers = request.headers();
```

### Common Headers

```rust
request.host()          // Host header
request.user_agent()    // User-Agent header
request.content_type()  // Content-Type header
request.authorization() // Authorization header
```

### Query Methods

#### `query(name: &str)`

Get a single query parameter.

```rust
let page = request.query("page");
```

#### `query_all(name: &str)`

Get all values for a query parameter.

```rust
let tags = request.query_all("tag");
```

### Body Methods

#### `body()`

Get the request body as bytes.

```rust
if let Some(body) = request.body() {
    // ...
}
```

#### `body_string()`

Get the request body as string.

```rust
if let Some(body) = request.body_string() {
    // ...
}
```

#### `body_json<T>()`

Parse the body as JSON.

```rust
if let Ok(payload) = request.body_json::<serde_json::Value>() {
    // ...
}
```

### Metadata Methods

```rust
request.correlation_id()  // Request correlation ID
request.request_id()      // Unique request ID
request.client_ip()       // Client IP address
request.client_port()     // Client port
request.server_name()     // Server name
request.protocol()        // HTTP protocol version
```

### Content Type Checks

```rust
request.is_json()      // Content-Type contains application/json
request.is_form()      // Content-Type is form-urlencoded
request.is_multipart() // Content-Type is multipart
```

---

## Response

Represents an HTTP response from the upstream.

```rust
use zentinel_agent_sdk::Response;
```

### Methods

#### `status_code()`

The HTTP status code.

```rust
if response.status_code() == 200 { ... }
```

#### `is_success()`

Check if status is 2xx.

#### `is_redirect()`

Check if status is 3xx.

#### `is_client_error()`

Check if status is 4xx.

#### `is_server_error()`

Check if status is 5xx.

#### `is_error()`

Check if status is 4xx or 5xx.

### Header Methods

```rust
response.header(name: &str)
response.header_all(name: &str)
response.has_header(name: &str)
response.headers()
```

### Common Headers

```rust
response.content_type()
response.location()  // For redirects
```

### Content Type Checks

```rust
response.is_json()
response.is_html()
```

### Body Methods

```rust
response.body()
response.body_string()
response.body_json::<T>()
```

---

## AgentRunner

Runner for starting and managing an agent.

```rust
use zentinel_agent_sdk::AgentRunner;
```

### Usage

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(MyAgent)
        .with_name("my-agent")
        .with_socket("/tmp/my-agent.sock")
        .with_log_level("debug")
        .run()
        .await
}
```

### Builder Methods

#### `with_name(name: &str)`

Set the agent name for logging.

#### `with_socket(path: &str)`

Set the Unix socket path.

#### `with_json_logs()`

Enable JSON log format.

#### `with_log_level(level: &str)`

Set the log level (trace, debug, info, warn, error).

---

## run_agent

Convenience function to run an agent with CLI argument parsing.

```rust
use zentinel_agent_sdk::run_agent;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run_agent(MyAgent).await
}
```

This parses `--socket`, `--log-level`, and `--json-logs` from command line arguments.
