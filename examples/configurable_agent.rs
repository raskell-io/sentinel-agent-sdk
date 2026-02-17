//! An agent that demonstrates configuration from proxy's KDL file.
//!
//! Configure in zentinel.kdl:
//! ```kdl
//! agent "rate-checker" type="custom" {
//!     unix-socket path="/tmp/rate-checker.sock"
//!     config {
//!         rate-limit 100
//!         burst 20
//!         block-mode true
//!     }
//! }
//! ```

use zentinel_agent_sdk::prelude::*;
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RateCheckerConfig {
    /// Requests per minute limit
    #[serde(default = "default_rate_limit")]
    rate_limit: u32,
    /// Burst allowance
    #[serde(default = "default_burst")]
    burst: u32,
    /// Block when limit exceeded (vs just logging)
    #[serde(default)]
    block_mode: bool,
}

fn default_rate_limit() -> u32 { 100 }
fn default_burst() -> u32 { 10 }

struct RateCheckerAgent {
    config: RwLock<RateCheckerConfig>,
    request_count: AtomicU64,
}

impl RateCheckerAgent {
    fn new() -> Self {
        Self {
            config: RwLock::new(RateCheckerConfig::default()),
            request_count: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl Agent for RateCheckerAgent {
    fn name(&self) -> &str {
        "rate-checker"
    }

    async fn on_configure(&self, config_json: serde_json::Value) -> Result<(), String> {
        let config: RateCheckerConfig = serde_json::from_value(config_json)
            .map_err(|e| format!("Invalid config: {}", e))?;

        tracing::info!(
            rate_limit = config.rate_limit,
            burst = config.burst,
            block_mode = config.block_mode,
            "Configuration applied"
        );

        *self.config.write().await = config;
        Ok(())
    }

    async fn on_request(&self, request: &Request) -> Decision {
        let count = self.request_count.fetch_add(1, Ordering::Relaxed);
        let config = self.config.read().await;

        // Simple check - in real agent would use sliding window
        if count > (config.rate_limit + config.burst) as u64 {
            if config.block_mode {
                tracing::warn!(
                    client_ip = request.client_ip(),
                    count = count,
                    "Rate limit exceeded, blocking"
                );
                return Decision::rate_limited()
                    .with_body("Rate limit exceeded")
                    .with_tag("rate-limited");
            } else {
                tracing::warn!(
                    client_ip = request.client_ip(),
                    count = count,
                    "Rate limit exceeded, logging only"
                );
            }
        }

        Decision::allow()
            .with_metadata("request_count", serde_json::json!(count))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(RateCheckerAgent::new())
        .with_name("rate-checker")
        .with_socket("/tmp/rate-checker.sock")
        .run()
        .await
}
