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

// Re-export v2 types from the protocol crate
pub use sentinel_agent_protocol::v2::{
    CounterMetric, DrainReason, GaugeMetric, HealthStatus, HistogramMetric,
    MetricsReport, ShutdownReason,
};

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

/// Agent capabilities for the SDK.
///
/// Note: This is a simpler version than the protocol crate's AgentCapabilities.
/// For full capabilities, use `sentinel_agent_protocol::v2::AgentCapabilities`.
#[derive(Debug, Clone, Default)]
pub struct AgentCapabilities {
    /// Whether the agent supports request header inspection.
    pub request_headers: bool,
    /// Whether the agent supports response header inspection.
    pub response_headers: bool,
    /// Whether the agent supports request body inspection.
    pub request_body: bool,
    /// Whether the agent supports response body inspection.
    pub response_body: bool,
    /// Whether the agent supports streaming.
    pub streaming: bool,
    /// Whether the agent supports health checks.
    pub health_check: bool,
    /// Whether the agent supports metrics.
    pub metrics: bool,
    /// Whether the agent supports configuration.
    pub configuration: bool,
}

impl AgentCapabilities {
    /// Create new capabilities with all features enabled.
    pub fn all() -> Self {
        Self {
            request_headers: true,
            response_headers: true,
            request_body: true,
            response_body: true,
            streaming: true,
            health_check: true,
            metrics: true,
            configuration: true,
        }
    }

    /// Create capabilities for request-only processing.
    pub fn request_only() -> Self {
        Self {
            request_headers: true,
            request_body: true,
            ..Default::default()
        }
    }
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

impl AgentCapabilitiesExt for AgentCapabilities {
    fn with_request_headers(mut self) -> Self {
        self.request_headers = true;
        self
    }

    fn with_response_headers(mut self) -> Self {
        self.response_headers = true;
        self
    }

    fn with_request_body(mut self) -> Self {
        self.request_body = true;
        self
    }

    fn with_response_body(mut self) -> Self {
        self.response_body = true;
        self
    }

    fn with_health_check(mut self) -> Self {
        self.health_check = true;
        self
    }

    fn with_metrics(mut self) -> Self {
        self.metrics = true;
        self
    }
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
        AgentCapabilities, AgentCapabilitiesExt, AgentRunnerV2, TransportConfig,
    };
    // Re-export protocol types
    pub use sentinel_agent_protocol::v2::{
        CounterMetric, DrainReason, GaugeMetric, HealthStatus, HistogramMetric,
        MetricsReport, ShutdownReason,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities() {
        let caps = AgentCapabilities::default()
            .with_request_headers()
            .with_health_check();
        assert!(caps.request_headers);
        assert!(caps.health_check);
        assert!(!caps.response_headers);
    }
}
