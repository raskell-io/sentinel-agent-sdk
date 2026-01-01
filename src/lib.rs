//! Sentinel Agent SDK - Build proxy agents with less boilerplate.
//!
//! This crate provides a high-level SDK for building Sentinel proxy agents.
//! It wraps the low-level protocol with ergonomic types and handles common
//! patterns like CLI parsing, logging setup, and graceful shutdown.
//!
//! # Quick Start
//!
//! ```ignore
//! use sentinel_agent_sdk::prelude::*;
//!
//! struct MyAgent;
//!
//! #[async_trait]
//! impl Agent for MyAgent {
//!     async fn on_request(&self, request: &Request) -> Decision {
//!         if request.path_starts_with("/admin") && request.header("x-admin-token").is_none() {
//!             Decision::deny().with_body("Admin access required")
//!         } else {
//!             Decision::allow()
//!         }
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     AgentRunner::new(MyAgent)
//!         .with_name("my-agent")
//!         .run()
//!         .await
//!         .unwrap();
//! }
//! ```
//!
//! # Features
//!
//! - **Simplified types**: `Request`, `Response`, and `Decision` provide ergonomic APIs
//! - **Fluent decision builder**: Chain methods to build complex responses
//! - **Configuration handling**: Receive config from proxy's KDL file
//! - **CLI support**: Built-in argument parsing with clap (optional)
//! - **Logging**: Automatic tracing setup
//!
//! # Crate Features
//!
//! - `cli` (default): Enable CLI argument parsing with clap
//! - `macros` (default): Enable derive macros

mod agent;
mod decision;
mod request;
mod response;
mod runner;

pub use agent::{Agent, AgentHandler, ConfigurableAgent, ConfigurableAgentExt};
pub use decision::{decisions, Decision};
pub use request::Request;
pub use response::Response;
pub use runner::{AgentRunner, RunnerConfig};

// Re-export commonly used items from dependencies
pub use async_trait::async_trait;
pub use serde;
pub use serde_json;
pub use tokio;
pub use tracing;

// Re-export protocol types that users might need
pub use sentinel_agent_protocol::{
    AgentResponse, ConfigureEvent, Decision as ProtocolDecision, HeaderOp,
    RequestHeadersEvent, RequestMetadata, ResponseHeadersEvent,
};

/// Prelude module for convenient imports.
///
/// ```ignore
/// use sentinel_agent_sdk::prelude::*;
/// ```
pub mod prelude {
    pub use crate::agent::{Agent, ConfigurableAgent, ConfigurableAgentExt};
    pub use crate::decision::{decisions, Decision};
    pub use crate::request::Request;
    pub use crate::response::Response;
    pub use crate::runner::{AgentRunner, RunnerConfig};
    pub use async_trait::async_trait;
}

/// Testing utilities for agent development.
#[cfg(feature = "testing")]
pub mod testing;

#[cfg(test)]
mod tests {
    use super::prelude::*;

    struct ExampleAgent;

    #[async_trait]
    impl Agent for ExampleAgent {
        fn name(&self) -> &str {
            "example"
        }

        async fn on_request(&self, request: &Request) -> Decision {
            // Check for blocked paths
            if request.path_starts_with("/blocked") {
                return Decision::deny().with_body("Access denied");
            }

            // Check for required header
            if request.path_starts_with("/api") {
                if request.header("x-api-key").is_none() {
                    return Decision::unauthorized()
                        .with_body("API key required")
                        .with_tag("missing-api-key");
                }
            }

            // Add request context
            Decision::allow()
                .add_request_header("X-Processed-By", "example-agent")
                .add_request_header("X-Client-IP", request.client_ip())
        }

        async fn on_response(&self, _request: &Request, response: &Response) -> Decision {
            // Add security headers to HTML responses
            if response.is_html() {
                Decision::allow()
                    .add_response_header("X-Content-Type-Options", "nosniff")
                    .add_response_header("X-Frame-Options", "DENY")
            } else {
                Decision::allow()
            }
        }
    }

    #[test]
    fn test_prelude_imports() {
        // Verify prelude provides necessary types
        let _decision: Decision = Decision::allow();
    }
}
