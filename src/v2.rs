//! V2 protocol runner with gRPC and UDS support.
//!
//! This module provides the `AgentRunnerV2` runner that supports both
//! Unix domain sockets and gRPC transport for the v2 agent protocol.
//!
//! Types are re-exported from `zentinel_agent_protocol::v2` for compatibility.

use crate::agent::{Agent, AgentHandler};
use anyhow::Result;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

// Re-export v2 types from the protocol crate for type compatibility
pub use zentinel_agent_protocol::v2::{
    AgentCapabilities,
    AgentFeatures,
    AgentHandlerV2,
    CounterMetric,
    DrainReason,
    GaugeMetric,
    GrpcAgentServerV2,
    HealthStatus,
    HistogramMetric,
    MetricsReport,
    ShutdownReason,
    UdsAgentServerV2,
};

// Alias AgentHandlerV2 as AgentV2 for SDK compatibility
pub use zentinel_agent_protocol::v2::AgentHandlerV2 as AgentV2;

/// Transport configuration for the v2 runner.
#[derive(Debug, Clone)]
pub enum TransportConfig {
    /// gRPC transport only.
    Grpc {
        /// gRPC server address.
        address: SocketAddr,
    },
    /// Unix domain socket transport only.
    Uds {
        /// Path to the Unix socket.
        path: PathBuf,
    },
    /// Both gRPC and UDS transports.
    Both {
        /// gRPC server address.
        grpc_address: SocketAddr,
        /// Path to the Unix socket.
        uds_path: PathBuf,
    },
}

/// Extension trait for building agent capabilities.
pub trait AgentCapabilitiesExt {
    /// Enable request header processing.
    fn with_request_headers(self) -> Self;
    /// Enable response header processing.
    fn with_response_headers(self) -> Self;
    /// Enable request body processing.
    fn with_request_body(self) -> Self;
    /// Enable response body processing.
    fn with_response_body(self) -> Self;
    /// Enable health checks.
    fn with_health_check(self) -> Self;
    /// Enable metrics.
    fn with_metrics(self) -> Self;
}

/// V2 protocol runner for Zentinel agents.
pub struct AgentRunnerV2<A: Agent> {
    agent: A,
    name: String,
    uds_path: Option<PathBuf>,
    grpc_address: Option<SocketAddr>,
    json_logs: bool,
}

impl<A: Agent> AgentRunnerV2<A> {
    /// Create a new v2 runner for the given agent.
    pub fn new(agent: A) -> Self {
        Self {
            agent,
            name: "agent".to_string(),
            uds_path: None,
            grpc_address: None,
            json_logs: false,
        }
    }

    /// Set the agent name (used for logging).
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Enable Unix domain socket transport.
    pub fn with_uds(mut self, path: impl Into<PathBuf>) -> Self {
        self.uds_path = Some(path.into());
        self
    }

    /// Enable gRPC transport.
    pub fn with_grpc(mut self, address: SocketAddr) -> Self {
        self.grpc_address = Some(address);
        self
    }

    /// Enable both gRPC and UDS transports.
    pub fn with_both(mut self, grpc_address: SocketAddr, uds_path: impl Into<PathBuf>) -> Self {
        self.grpc_address = Some(grpc_address);
        self.uds_path = Some(uds_path.into());
        self
    }

    /// Enable JSON logging format.
    pub fn with_json_logs(mut self) -> Self {
        self.json_logs = true;
        self
    }

    /// Run the agent server.
    pub async fn run(self) -> Result<()> {
        // Setup logging
        self.setup_logging();

        match (&self.grpc_address, &self.uds_path) {
            (Some(grpc_addr), Some(uds_path)) => {
                // Both transports
                tracing::info!(
                    agent = %self.name,
                    socket = %uds_path.display(),
                    grpc = %grpc_addr,
                    "Starting agent (v2 protocol, UDS + gRPC)"
                );

                let handler = AgentHandler::new(self.agent);
                let handler = std::sync::Arc::new(handler);

                let uds_server = zentinel_agent_protocol::v2::UdsAgentServerV2::new(
                    self.name.clone(),
                    uds_path.clone(),
                    Box::new(ArcHandler(handler.clone())),
                );
                let grpc_server = zentinel_agent_protocol::v2::GrpcAgentServerV2::new(
                    self.name.clone(),
                    Box::new(ArcHandler(handler)),
                );

                let uds_handle = tokio::spawn(async move { uds_server.run().await });
                let grpc_addr = *grpc_addr;
                let grpc_handle = tokio::spawn(async move { grpc_server.run(grpc_addr).await });

                Self::wait_for_shutdown().await;
                tracing::info!("Shutting down agent");
                uds_handle.abort();
                grpc_handle.abort();
            }
            (Some(grpc_addr), None) => {
                // gRPC only
                tracing::info!(
                    agent = %self.name,
                    grpc = %grpc_addr,
                    "Starting agent (v2 protocol, gRPC)"
                );

                let handler = AgentHandler::new(self.agent);
                let server = zentinel_agent_protocol::v2::GrpcAgentServerV2::new(
                    self.name.clone(),
                    Box::new(handler),
                );

                let grpc_addr = *grpc_addr;
                let server_handle = tokio::spawn(async move { server.run(grpc_addr).await });

                Self::wait_for_shutdown().await;
                tracing::info!("Shutting down agent");
                server_handle.abort();
            }
            _ => {
                // UDS only (default)
                let uds_path = self.uds_path.unwrap_or_else(|| {
                    PathBuf::from(format!("/tmp/zentinel-{}.sock", self.name))
                });

                tracing::info!(
                    agent = %self.name,
                    socket = %uds_path.display(),
                    "Starting agent (v2 protocol, UDS)"
                );

                let handler = AgentHandler::new(self.agent);
                let server = zentinel_agent_protocol::v2::UdsAgentServerV2::new(
                    self.name.clone(),
                    uds_path.clone(),
                    Box::new(handler),
                );

                let server_handle = tokio::spawn(async move { server.run().await });

                Self::wait_for_shutdown().await;
                tracing::info!("Shutting down agent");
                server_handle.abort();

                // Clean up socket file
                if uds_path.exists() {
                    let _ = std::fs::remove_file(&uds_path);
                }
            }
        }

        Ok(())
    }

    fn setup_logging(&self) {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info"));

        if self.json_logs {
            let _ = fmt()
                .with_env_filter(filter)
                .json()
                .try_init();
        } else {
            let _ = fmt()
                .with_env_filter(filter)
                .try_init();
        }
    }

    async fn wait_for_shutdown() {
        let ctrl_c = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }
    }
}

/// Wrapper that delegates `AgentHandlerV2` to an `Arc`-wrapped handler,
/// allowing the same handler to be shared between UDS and gRPC servers.
struct ArcHandler<A: Agent>(std::sync::Arc<AgentHandler<A>>);

#[async_trait::async_trait]
impl<A: Agent> zentinel_agent_protocol::v2::AgentHandlerV2 for ArcHandler<A> {
    fn capabilities(&self) -> AgentCapabilities {
        self.0.capabilities()
    }

    async fn on_configure(&self, config: serde_json::Value, version: Option<String>) -> bool {
        self.0.on_configure(config, version).await
    }

    async fn on_request_headers(
        &self,
        event: zentinel_agent_protocol::RequestHeadersEvent,
    ) -> zentinel_agent_protocol::AgentResponse {
        self.0.on_request_headers(event).await
    }

    async fn on_request_body_chunk(
        &self,
        event: zentinel_agent_protocol::RequestBodyChunkEvent,
    ) -> zentinel_agent_protocol::AgentResponse {
        self.0.on_request_body_chunk(event).await
    }

    async fn on_response_headers(
        &self,
        event: zentinel_agent_protocol::ResponseHeadersEvent,
    ) -> zentinel_agent_protocol::AgentResponse {
        self.0.on_response_headers(event).await
    }

    async fn on_response_body_chunk(
        &self,
        event: zentinel_agent_protocol::ResponseBodyChunkEvent,
    ) -> zentinel_agent_protocol::AgentResponse {
        self.0.on_response_body_chunk(event).await
    }

    async fn on_request_complete(
        &self,
        event: zentinel_agent_protocol::RequestCompleteEvent,
    ) -> zentinel_agent_protocol::AgentResponse {
        self.0.on_request_complete(event).await
    }

    async fn on_guardrail_inspect(
        &self,
        event: zentinel_agent_protocol::GuardrailInspectEvent,
    ) -> zentinel_agent_protocol::AgentResponse {
        self.0.on_guardrail_inspect(event).await
    }
}

/// Prelude module for v2 types.
pub mod prelude {
    pub use super::{
        AgentCapabilitiesExt, AgentRunnerV2, TransportConfig,
    };
    // Re-export all protocol types
    pub use zentinel_agent_protocol::v2::{
        AgentCapabilities, AgentFeatures, AgentHandlerV2, AgentHandlerV2 as AgentV2,
        CounterMetric, DrainReason, GaugeMetric, HealthStatus, HistogramMetric,
        MetricsReport, ShutdownReason,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_config() {
        let _grpc = TransportConfig::Grpc {
            address: "127.0.0.1:50051".parse().unwrap(),
        };
        let _uds = TransportConfig::Uds {
            path: PathBuf::from("/tmp/test.sock"),
        };
    }
}
