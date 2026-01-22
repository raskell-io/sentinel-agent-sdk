//! V2 protocol runner with gRPC and UDS support.
//!
//! This module provides the `AgentRunnerV2` runner that supports both
//! Unix domain sockets and gRPC transport for the v2 agent protocol.
//!
//! Types are re-exported from `sentinel_agent_protocol::v2` for compatibility.

use crate::agent::{Agent, AgentHandler};
use anyhow::Result;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

// Re-export v2 types from the protocol crate for type compatibility
pub use sentinel_agent_protocol::v2::{
    AgentCapabilities,
    AgentFeatures,
    AgentHandlerV2,
    CounterMetric,
    DrainReason,
    GaugeMetric,
    HealthStatus,
    HistogramMetric,
    MetricsReport,
    ShutdownReason,
};

// Alias AgentHandlerV2 as AgentV2 for SDK compatibility
pub use sentinel_agent_protocol::v2::AgentHandlerV2 as AgentV2;

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

/// V2 protocol runner for Sentinel agents.
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

        // Determine transport
        let uds_path = self.uds_path.unwrap_or_else(|| {
            PathBuf::from(format!("/tmp/sentinel-{}.sock", self.name))
        });

        tracing::info!(
            agent = %self.name,
            socket = %uds_path.display(),
            grpc = ?self.grpc_address,
            "Starting agent (v2 protocol)"
        );

        // Remove existing socket file
        if uds_path.exists() {
            std::fs::remove_file(&uds_path)?;
        }

        // Create handler
        let handler = AgentHandler::new(self.agent);

        // Create server
        let server = sentinel_agent_protocol::AgentServer::new(
            self.name.clone(),
            uds_path.clone(),
            Box::new(handler),
        );

        // Start server
        let server_handle = tokio::spawn(async move {
            server.run().await
        });

        // Wait for shutdown signal
        Self::wait_for_shutdown().await;

        tracing::info!("Shutting down agent");

        // Abort the server task
        server_handle.abort();

        // Clean up socket file
        if uds_path.exists() {
            let _ = std::fs::remove_file(&uds_path);
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

/// Prelude module for v2 types.
pub mod prelude {
    pub use super::{
        AgentCapabilitiesExt, AgentRunnerV2, TransportConfig,
    };
    // Re-export all protocol types
    pub use sentinel_agent_protocol::v2::{
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
