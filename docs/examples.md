# Examples

Common patterns and use cases for Sentinel agents.

## Basic Request Blocking

Block requests based on path patterns:

```rust
use sentinel_agent_sdk::prelude::*;

struct BlockingAgent {
    blocked_paths: Vec<&'static str>,
}

impl BlockingAgent {
    fn new() -> Self {
        Self {
            blocked_paths: vec!["/admin", "/internal", "/.git", "/.env"],
        }
    }
}

#[async_trait]
impl Agent for BlockingAgent {
    fn name(&self) -> &str {
        "blocking-agent"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        for blocked in &self.blocked_paths {
            if request.path_starts_with(blocked) {
                return Decision::deny()
                    .with_body("Not Found")
                    .with_tag("path-blocked");
            }
        }
        Decision::allow()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(BlockingAgent::new())
        .with_socket("/tmp/blocking-agent.sock")
        .run()
        .await
}
```

## IP-Based Access Control

Block or allow requests based on client IP:

```rust
use sentinel_agent_sdk::prelude::*;
use std::collections::HashSet;

struct IPFilterAgent {
    allowed_ips: HashSet<String>,
}

impl IPFilterAgent {
    fn new() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert("10.0.0.1".to_string());
        allowed.insert("192.168.1.1".to_string());
        allowed.insert("127.0.0.1".to_string());
        Self { allowed_ips: allowed }
    }
}

#[async_trait]
impl Agent for IPFilterAgent {
    fn name(&self) -> &str {
        "ip-filter"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        let client_ip = request.client_ip();

        if self.allowed_ips.contains(client_ip) {
            return Decision::allow();
        }

        Decision::deny()
            .with_tag("ip-blocked")
            .with_metadata("blocked_ip", json!(client_ip))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(IPFilterAgent::new())
        .with_socket("/tmp/ip-filter.sock")
        .run()
        .await
}
```

## Authentication Validation

Validate JWT tokens:

```rust
use sentinel_agent_sdk::prelude::*;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::Deserialize;

#[derive(Deserialize)]
struct Claims {
    sub: String,
    role: Option<String>,
    exp: usize,
}

struct AuthAgent {
    secret: String,
}

impl AuthAgent {
    fn new(secret: &str) -> Self {
        Self { secret: secret.to_string() }
    }
}

#[async_trait]
impl Agent for AuthAgent {
    fn name(&self) -> &str {
        "auth-agent"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        // Skip auth for public paths
        if request.path_starts_with("/public") {
            return Decision::allow();
        }

        let auth = match request.authorization() {
            Some(a) if a.starts_with("Bearer ") => &a[7..],
            _ => {
                return Decision::unauthorized()
                    .with_body("Missing or invalid Authorization header")
                    .with_tag("auth-missing");
            }
        };

        let key = DecodingKey::from_secret(self.secret.as_bytes());
        let validation = Validation::new(Algorithm::HS256);

        match decode::<Claims>(auth, &key, &validation) {
            Ok(token_data) => {
                Decision::allow()
                    .add_request_header("X-User-ID", &token_data.claims.sub)
                    .add_request_header("X-User-Role", token_data.claims.role.as_deref().unwrap_or(""))
            }
            Err(e) => {
                let tag = if e.to_string().contains("ExpiredSignature") {
                    "auth-expired"
                } else {
                    "auth-invalid"
                };
                Decision::unauthorized()
                    .with_body("Invalid token")
                    .with_tag(tag)
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(AuthAgent::new("your-secret-key"))
        .with_socket("/tmp/auth-agent.sock")
        .run()
        .await
}
```

## Rate Limiting

Simple in-memory rate limiting:

```rust
use sentinel_agent_sdk::prelude::*;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

struct RateLimitAgent {
    max_requests: usize,
    window_seconds: u64,
    requests: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RateLimitAgent {
    fn new() -> Self {
        Self {
            max_requests: 100,
            window_seconds: 60,
            requests: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl Agent for RateLimitAgent {
    fn name(&self) -> &str {
        "rate-limit"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        let key = request.client_ip().to_string();
        let now = Instant::now();
        let window = Duration::from_secs(self.window_seconds);

        let mut requests = self.requests.lock().await;

        // Clean old entries and add current
        let timestamps = requests.entry(key).or_insert_with(Vec::new);
        timestamps.retain(|t| now.duration_since(*t) < window);
        timestamps.push(now);

        if timestamps.len() > self.max_requests {
            return Decision::rate_limited()
                .with_body("Too many requests")
                .with_tag("rate-limited")
                .add_response_header("Retry-After", &self.window_seconds.to_string());
        }

        let remaining = self.max_requests - timestamps.len();
        Decision::allow()
            .add_response_header("X-RateLimit-Limit", &self.max_requests.to_string())
            .add_response_header("X-RateLimit-Remaining", &remaining.to_string())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(RateLimitAgent::new())
        .with_socket("/tmp/rate-limit.sock")
        .run()
        .await
}
```

## Header Modification

Add, remove, or modify headers:

```rust
use sentinel_agent_sdk::prelude::*;

struct HeaderAgent;

#[async_trait]
impl Agent for HeaderAgent {
    fn name(&self) -> &str {
        "header-agent"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        Decision::allow()
            // Add headers for upstream
            .add_request_header("X-Forwarded-By", "sentinel")
            .add_request_header("X-Request-ID", request.correlation_id())
            // Remove sensitive headers
            .remove_request_header("X-Internal-Token")
    }

    async fn on_response(&self, _request: &Request, _response: &Response) -> Decision {
        Decision::allow()
            // Add security headers
            .add_response_header("X-Frame-Options", "DENY")
            .add_response_header("X-Content-Type-Options", "nosniff")
            .add_response_header("X-XSS-Protection", "1; mode=block")
            // Remove server info
            .remove_response_header("Server")
            .remove_response_header("X-Powered-By")
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(HeaderAgent)
        .with_socket("/tmp/header-agent.sock")
        .run()
        .await
}
```

## Configurable Agent

Agent with runtime configuration:

```rust
use sentinel_agent_sdk::prelude::*;
use serde::Deserialize;
use tokio::sync::RwLock;

#[derive(Default, Deserialize, Clone)]
struct Config {
    enabled: bool,
    blocked_paths: Vec<String>,
    log_requests: bool,
}

struct ConfigurableBlocker {
    config: RwLock<Config>,
}

impl ConfigurableBlocker {
    fn new() -> Self {
        Self {
            config: RwLock::new(Config {
                enabled: true,
                blocked_paths: vec!["/admin".to_string()],
                log_requests: false,
            }),
        }
    }
}

impl ConfigurableAgent for ConfigurableBlocker {
    type Config = Config;

    fn config(&self) -> &RwLock<Self::Config> {
        &self.config
    }

    fn on_config_applied(&self, config: &Config) {
        println!("Configuration updated: enabled={}", config.enabled);
    }
}

#[async_trait]
impl Agent for ConfigurableBlocker {
    fn name(&self) -> &str {
        "configurable-blocker"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        let config = self.config.read().await;

        if !config.enabled {
            return Decision::allow();
        }

        if config.log_requests {
            println!("Request: {} {}", request.method(), request.path());
        }

        for blocked in &config.blocked_paths {
            if request.path_starts_with(blocked) {
                return Decision::deny();
            }
        }

        Decision::allow()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(ConfigurableBlocker::new())
        .with_socket("/tmp/configurable-blocker.sock")
        .run()
        .await
}
```

## Request Logging

Log all requests with timing:

```rust
use sentinel_agent_sdk::prelude::*;

struct LoggingAgent;

#[async_trait]
impl Agent for LoggingAgent {
    fn name(&self) -> &str {
        "logging-agent"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        Decision::allow()
            .with_tag(&format!("method:{}", request.method().to_lowercase()))
            .with_metadata("path", json!(request.path()))
            .with_metadata("client_ip", json!(request.client_ip()))
    }

    async fn on_request_complete(&self, request: &Request, status: u16, duration_ms: u64) {
        println!(
            "{} - {} {} -> {} ({}ms)",
            request.client_ip(),
            request.method(),
            request.path(),
            status,
            duration_ms
        );
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(LoggingAgent)
        .with_socket("/tmp/logging-agent.sock")
        .run()
        .await
}
```

## Content-Type Validation

Validate request content types:

```rust
use sentinel_agent_sdk::prelude::*;
use std::collections::HashSet;

struct ContentTypeAgent {
    allowed_types: HashSet<&'static str>,
}

impl ContentTypeAgent {
    fn new() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert("application/json");
        allowed.insert("application/x-www-form-urlencoded");
        allowed.insert("multipart/form-data");
        Self { allowed_types: allowed }
    }
}

#[async_trait]
impl Agent for ContentTypeAgent {
    fn name(&self) -> &str {
        "content-type-validator"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        // Only check methods with body
        let method = request.method();
        if method != "POST" && method != "PUT" && method != "PATCH" {
            return Decision::allow();
        }

        let content_type = match request.content_type() {
            Some(ct) => ct,
            None => {
                return Decision::block(400)
                    .with_body("Content-Type header required");
            }
        };

        // Check against allowed types (ignore params like charset)
        let base_type = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_lowercase();

        if !self.allowed_types.contains(base_type.as_str()) {
            return Decision::block(415)
                .with_body(&format!("Unsupported Content-Type: {}", base_type))
                .with_tag("invalid-content-type");
        }

        Decision::allow()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(ContentTypeAgent::new())
        .with_socket("/tmp/content-type-agent.sock")
        .run()
        .await
}
```

## Redirect Agent

Redirect requests to different URLs:

```rust
use sentinel_agent_sdk::prelude::*;
use std::collections::HashMap;

struct RedirectAgent {
    redirects: HashMap<&'static str, &'static str>,
}

impl RedirectAgent {
    fn new() -> Self {
        let mut redirects = HashMap::new();
        redirects.insert("/old-path", "/new-path");
        redirects.insert("/legacy", "/v2/api");
        redirects.insert("/blog", "https://blog.example.com");
        Self { redirects }
    }
}

#[async_trait]
impl Agent for RedirectAgent {
    fn name(&self) -> &str {
        "redirect-agent"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        if let Some(&target) = self.redirects.get(request.path()) {
            return Decision::redirect(target);
        }

        // Redirect HTTP to HTTPS
        if let Some(proto) = request.header("x-forwarded-proto") {
            if proto == "http" {
                let https_url = format!("https://{}{}", request.host().unwrap_or(""), request.uri());
                return Decision::redirect_permanent(&https_url);
            }
        }

        Decision::allow()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(RedirectAgent::new())
        .with_socket("/tmp/redirect-agent.sock")
        .run()
        .await
}
```

## Bot Protection with Challenge

Issue challenges to suspicious requests:

```rust
use sentinel_agent_sdk::prelude::*;
use std::collections::HashMap;

struct BotProtectionAgent {
    suspicious_user_agents: Vec<&'static str>,
    captcha_site_key: String,
}

impl BotProtectionAgent {
    fn new(site_key: &str) -> Self {
        Self {
            suspicious_user_agents: vec![
                "curl", "wget", "python-requests", "scrapy", "bot",
            ],
            captcha_site_key: site_key.to_string(),
        }
    }

    fn is_suspicious(&self, user_agent: &str) -> bool {
        let ua_lower = user_agent.to_lowercase();
        self.suspicious_user_agents.iter().any(|s| ua_lower.contains(s))
    }
}

#[async_trait]
impl Agent for BotProtectionAgent {
    fn name(&self) -> &str {
        "bot-protection"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        // Check for missing or suspicious User-Agent
        let user_agent = match request.user_agent() {
            Some(ua) => ua,
            None => {
                // No User-Agent - issue JavaScript challenge
                return Decision::challenge("js_challenge", HashMap::new())
                    .with_tag("no-user-agent");
            }
        };

        // Check for known bot patterns
        if self.is_suspicious(user_agent) {
            let mut params = HashMap::new();
            params.insert("site_key".to_string(), self.captcha_site_key.clone());
            params.insert("action".to_string(), "bot_check".to_string());

            return Decision::challenge("captcha", params)
                .with_tag("suspicious-ua")
                .with_confidence(0.75);
        }

        // Check for high request rate from single IP (simplified)
        if request.header("x-high-rate").is_some() {
            let mut params = HashMap::new();
            params.insert("difficulty".to_string(), "medium".to_string());

            return Decision::challenge("proof_of_work", params)
                .with_tag("rate-challenge");
        }

        Decision::allow()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(BotProtectionAgent::new("your-captcha-site-key"))
        .with_socket("/tmp/bot-protection.sock")
        .run()
        .await
}
```

## Combining Multiple Checks

Agent that performs multiple validations:

```rust
use sentinel_agent_sdk::prelude::*;

struct SecurityAgent {
    suspicious_patterns: Vec<&'static str>,
}

impl SecurityAgent {
    fn new() -> Self {
        Self {
            suspicious_patterns: vec!["/../", "/etc/", "/proc/", ".php"],
        }
    }
}

#[async_trait]
impl Agent for SecurityAgent {
    fn name(&self) -> &str {
        "security-agent"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        // Check 1: User-Agent required
        if request.user_agent().is_none() {
            return Decision::block(400).with_body("User-Agent required");
        }

        // Check 2: Block suspicious paths
        let path_lower = request.path().to_lowercase();
        for pattern in &self.suspicious_patterns {
            if path_lower.contains(pattern) {
                return Decision::deny()
                    .with_tag("path-traversal")
                    .with_rule_id("SEC-001");
            }
        }

        // Check 3: Block large requests without content-length
        let method = request.method();
        if method == "POST" || method == "PUT" {
            if !request.has_header("content-length") {
                return Decision::block(411).with_body("Content-Length required");
            }
        }

        // All checks passed
        Decision::allow()
            .with_tag("security-passed")
            .add_response_header("X-Security-Check", "passed")
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(SecurityAgent::new())
        .with_socket("/tmp/security-agent.sock")
        .run()
        .await
}
```

## Login Protection with CAPTCHA

Protect login endpoints with CAPTCHA challenges after failed attempts:

```rust
use sentinel_agent_sdk::prelude::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::Mutex;

struct LoginProtectionAgent {
    captcha_site_key: String,
    challenge_threshold: u32,
    failed_attempts: Mutex<HashMap<String, AtomicU32>>,
}

impl LoginProtectionAgent {
    fn new(site_key: &str) -> Self {
        Self {
            captcha_site_key: site_key.to_string(),
            challenge_threshold: 3,
            failed_attempts: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl Agent for LoginProtectionAgent {
    fn name(&self) -> &str {
        "login-protection"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        // Only protect login endpoint
        if !request.path_equals("/login") || request.method() != "POST" {
            return Decision::allow();
        }

        let client_ip = request.client_ip().to_string();
        let attempts = self.failed_attempts.lock().await;

        let count = attempts
            .get(&client_ip)
            .map(|a| a.load(Ordering::Relaxed))
            .unwrap_or(0);

        // If too many failed attempts, require CAPTCHA
        if count >= self.challenge_threshold {
            let mut params = HashMap::new();
            params.insert("site_key".to_string(), self.captcha_site_key.clone());
            params.insert("action".to_string(), "login".to_string());

            return Decision::challenge("captcha", params)
                .with_tag("login-challenge")
                .with_metadata("failed_attempts", json!(count));
        }

        Decision::allow()
    }

    async fn on_response(&self, request: &Request, response: &Response) -> Decision {
        // Track failed login responses
        if request.path_equals("/login") && request.method() == "POST" {
            let client_ip = request.client_ip().to_string();
            let mut attempts = self.failed_attempts.lock().await;

            if response.status_code() == 401 {
                attempts
                    .entry(client_ip)
                    .or_insert_with(|| AtomicU32::new(0))
                    .fetch_add(1, Ordering::Relaxed);
            } else if response.is_success() {
                // Reset on successful login
                if let Some(counter) = attempts.get(&client_ip) {
                    counter.store(0, Ordering::Relaxed);
                }
            }
        }

        Decision::allow()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(LoginProtectionAgent::new("your-captcha-site-key"))
        .with_socket("/tmp/login-protection.sock")
        .run()
        .await
}
```

## Body Inspection Agent

Inspect request bodies for malicious content:

```rust
use sentinel_agent_sdk::prelude::*;
use regex::Regex;

struct BodyInspectionAgent {
    sql_patterns: Vec<Regex>,
    xss_patterns: Vec<Regex>,
}

impl BodyInspectionAgent {
    fn new() -> Self {
        Self {
            sql_patterns: vec![
                Regex::new(r"(?i)union\s+select").unwrap(),
                Regex::new(r"(?i)or\s+1\s*=\s*1").unwrap(),
                Regex::new(r"(?i)drop\s+table").unwrap(),
                Regex::new(r"(?i)--\s*$").unwrap(),
            ],
            xss_patterns: vec![
                Regex::new(r"(?i)<script").unwrap(),
                Regex::new(r"(?i)javascript:").unwrap(),
                Regex::new(r"(?i)on\w+\s*=").unwrap(),
            ],
        }
    }
}

#[async_trait]
impl Agent for BodyInspectionAgent {
    fn name(&self) -> &str {
        "body-inspector"
    }

    async fn on_request_body(&self, request: &Request) -> Decision {
        let body = match request.body_string() {
            Some(b) => b,
            None => return Decision::allow(),
        };

        // Check for SQL injection
        for pattern in &self.sql_patterns {
            if pattern.is_match(&body) {
                return Decision::deny()
                    .with_tag("sqli-detected")
                    .with_rule_id("SQLI-001")
                    .with_confidence(0.9)
                    .with_metadata("pattern", json!(pattern.as_str()));
            }
        }

        // Check for XSS
        for pattern in &self.xss_patterns {
            if pattern.is_match(&body) {
                return Decision::deny()
                    .with_tag("xss-detected")
                    .with_rule_id("XSS-001")
                    .with_confidence(0.85);
            }
        }

        Decision::allow()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(BodyInspectionAgent::new())
        .with_socket("/tmp/body-inspector.sock")
        .run()
        .await
}
```

## Response Transformation

Transform responses from upstream:

```rust
use sentinel_agent_sdk::prelude::*;
use sentinel_agent_protocol::BodyMutation;
use regex::Regex;

struct ResponseTransformAgent {
    password_pattern: Regex,
}

impl ResponseTransformAgent {
    fn new() -> Self {
        Self {
            password_pattern: Regex::new(r#""password"\s*:\s*"[^"]*""#).unwrap(),
        }
    }
}

#[async_trait]
impl Agent for ResponseTransformAgent {
    fn name(&self) -> &str {
        "response-transform"
    }

    async fn on_response(&self, request: &Request, response: &Response) -> Decision {
        // Add CORS headers for API requests
        if request.path_starts_with("/api/") {
            return Decision::allow()
                .add_response_header("Access-Control-Allow-Origin", "*")
                .add_response_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
                .add_response_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        }

        // Add cache headers for static content
        if let Some(content_type) = response.content_type() {
            if content_type.starts_with("image/") || content_type.starts_with("text/css") {
                return Decision::allow()
                    .add_response_header("Cache-Control", "public, max-age=86400");
            }
        }

        Decision::allow()
    }

    async fn on_response_body(&self, request: &Request, response: &Response) -> Decision {
        // Redact sensitive data from JSON responses
        if response.is_json() {
            if let Some(body) = response.body_string() {
                if self.password_pattern.is_match(&body) {
                    let redacted = self.password_pattern
                        .replace_all(&body, r#""password":"[REDACTED]""#)
                        .to_string();

                    return Decision::allow()
                        .with_response_body_mutation(BodyMutation::replace(0, redacted));
                }
            }
        }

        Decision::allow()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(ResponseTransformAgent::new())
        .with_socket("/tmp/response-transform.sock")
        .run()
        .await
}
```
