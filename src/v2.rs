//! V2 protocol runner with gRPC and UDS support.
//!
//! This module provides the `AgentRunnerV2` runner that supports both
//! Unix domain sockets and gRPC transport for the v2 agent protocol.

use crate::agent::{Agent, AgentHandler};
use crate::Decision;
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

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

/// Reason for draining the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainReason {
    /// Proxy initiated graceful shutdown.
    GracefulShutdown,
    /// Agent is being replaced/upgraded.
    Replacement,
    /// Scheduled maintenance.
    Maintenance,
    /// Health check failure.
    HealthFailure,
    /// Manual drain request.
    Manual,
}

/// Reason for shutting down the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// Graceful shutdown requested.
    Graceful,
    /// Immediate shutdown (e.g., SIGTERM).
    Immediate,
    /// Error condition requiring restart.
    Error,
    /// Configuration reload.
    Reload,
}

/// Health status of the agent.
#[derive(Debug, Clone, PartialEq)]
pub struct HealthStatus {
    /// Whether the agent is healthy.
    pub healthy: bool,
    /// Whether the agent is degraded.
    pub degraded: bool,
    /// Agent identifier.
    pub agent_id: String,
    /// Degraded subsystems (if any).
    pub degraded_subsystems: Vec<String>,
    /// Timeout multiplier for degraded state.
    pub timeout_multiplier: f64,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self {
            healthy: true,
            degraded: false,
            agent_id: String::new(),
            degraded_subsystems: Vec::new(),
            timeout_multiplier: 1.0,
        }
    }
}

impl HealthStatus {
    /// Create a healthy status.
    pub fn healthy(agent_id: impl Into<String>) -> Self {
        Self {
            healthy: true,
            degraded: false,
            agent_id: agent_id.into(),
            degraded_subsystems: Vec::new(),
            timeout_multiplier: 1.0,
        }
    }

    /// Create a degraded status.
    pub fn degraded(
        agent_id: impl Into<String>,
        subsystems: Vec<String>,
        timeout_multiplier: f64,
    ) -> Self {
        Self {
            healthy: true,
            degraded: true,
            agent_id: agent_id.into(),
            degraded_subsystems: subsystems,
            timeout_multiplier,
        }
    }

    /// Create an unhealthy status.
    pub fn unhealthy(agent_id: impl Into<String>) -> Self {
        Self {
            healthy: false,
            degraded: false,
            agent_id: agent_id.into(),
            degraded_subsystems: Vec::new(),
            timeout_multiplier: 1.0,
        }
    }

    /// Check if status is healthy.
    pub fn is_healthy(&self) -> bool {
        self.healthy && !self.degraded
    }

    /// Check if status is degraded.
    pub fn is_degraded(&self) -> bool {
        self.degraded
    }
}

/// Counter metric.
#[derive(Debug, Clone)]
pub struct CounterMetric {
    /// Metric name.
    pub name: String,
    /// Metric value.
    pub value: u64,
    /// Optional labels.
    pub labels: HashMap<String, String>,
}

impl CounterMetric {
    /// Create a new counter metric.
    pub fn new(name: impl Into<String>, value: u64) -> Self {
        Self {
            name: name.into(),
            value,
            labels: HashMap::new(),
        }
    }

    /// Add a label to the metric.
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }
}

/// Gauge metric.
#[derive(Debug, Clone)]
pub struct GaugeMetric {
    /// Metric name.
    pub name: String,
    /// Metric value.
    pub value: f64,
    /// Optional labels.
    pub labels: HashMap<String, String>,
}

impl GaugeMetric {
    /// Create a new gauge metric.
    pub fn new(name: impl Into<String>, value: f64) -> Self {
        Self {
            name: name.into(),
            value,
            labels: HashMap::new(),
        }
    }

    /// Add a label to the metric.
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }
}

/// Histogram metric.
#[derive(Debug, Clone)]
pub struct HistogramMetric {
    /// Metric name.
    pub name: String,
    /// Metric values.
    pub values: Vec<f64>,
    /// Optional labels.
    pub labels: HashMap<String, String>,
}

impl HistogramMetric {
    /// Create a new histogram metric.
    pub fn new(name: impl Into<String>, values: Vec<f64>) -> Self {
        Self {
            name: name.into(),
            values,
            labels: HashMap::new(),
        }
    }
}

/// Metrics report from the agent.
#[derive(Debug, Clone, Default)]
pub struct MetricsReport {
    /// Agent identifier.
    pub agent_id: String,
    /// Reporting interval in milliseconds.
    pub interval_ms: u64,
    /// Counter metrics.
    pub counters: Vec<CounterMetric>,
    /// Gauge metrics.
    pub gauges: Vec<GaugeMetric>,
    /// Histogram metrics.
    pub histograms: Vec<HistogramMetric>,
    /// Custom labels for all metrics.
    pub labels: HashMap<String, String>,
}

impl MetricsReport {
    /// Create a new metrics report.
    pub fn new(agent_id: impl Into<String>, interval_ms: u64) -> Self {
        Self {
            agent_id: agent_id.into(),
            interval_ms,
            counters: Vec::new(),
            gauges: Vec::new(),
            histograms: Vec::new(),
            labels: HashMap::new(),
        }
    }

    /// Add a counter metric using builder pattern.
    pub fn counter(mut self, name: impl Into<String>, value: u64) -> Self {
        self.counters.push(CounterMetric::new(name, value));
        self
    }

    /// Add a gauge metric using builder pattern.
    pub fn gauge(mut self, name: impl Into<String>, value: f64) -> Self {
        self.gauges.push(GaugeMetric::new(name, value));
        self
    }

    /// Add a histogram metric using builder pattern.
    pub fn histogram(mut self, name: impl Into<String>, values: Vec<f64>) -> Self {
        self.histograms.push(HistogramMetric::new(name, values));
        self
    }

    /// Add a label.
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }
}

/// Agent capabilities.
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
    /// Custom capabilities.
    pub custom: HashMap<String, String>,
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
            custom: HashMap::new(),
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

/// V2 Agent trait with lifecycle hooks.
#[async_trait]
pub trait AgentV2: Send + Sync + 'static {
    /// Get agent name.
    fn name(&self) -> &str;

    /// Get agent capabilities.
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::default()
    }

    /// Process request headers.
    async fn on_request_headers(
        &self,
        _headers: &HashMap<String, String>,
        _metadata: &HashMap<String, String>,
    ) -> Decision {
        Decision::allow()
    }

    /// Process response headers.
    async fn on_response_headers(
        &self,
        _headers: &HashMap<String, String>,
        _metadata: &HashMap<String, String>,
    ) -> Decision {
        Decision::allow()
    }

    /// Handle health check.
    fn health_status(&self) -> HealthStatus {
        HealthStatus::healthy("agent")
    }

    /// Collect metrics.
    fn collect_metrics(&self) -> MetricsReport {
        MetricsReport::new("agent", 10_000)
    }

    /// Handle drain event.
    fn on_drain(&self, _timeout_ms: u64, _reason: DrainReason) {
        // Default: no-op
    }

    /// Handle shutdown event.
    fn on_shutdown(&self, _reason: ShutdownReason, _timeout_ms: u64) {
        // Default: no-op
    }

    /// Handle configuration update.
    fn on_configure(&self, _config: &HashMap<String, String>) -> Result<()> {
        Ok(())
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
        AgentCapabilities, AgentCapabilitiesExt, AgentRunnerV2, AgentV2,
        CounterMetric, DrainReason, GaugeMetric, HealthStatus, HistogramMetric,
        MetricsReport, ShutdownReason, TransportConfig,
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

    #[test]
    fn test_health_status() {
        let healthy = HealthStatus::healthy("test-agent");
        assert!(healthy.is_healthy());
        assert!(!healthy.is_degraded());

        let degraded = HealthStatus::degraded("test-agent", vec!["db".to_string()], 1.5);
        assert!(!degraded.is_healthy());
        assert!(degraded.is_degraded());
    }

    #[test]
    fn test_metrics_report() {
        let mut report = MetricsReport::new("test-agent", 10_000);
        report.counters.push(CounterMetric::new("requests", 100));
        report.gauges.push(GaugeMetric::new("latency_ms", 42.5));

        assert_eq!(report.agent_id, "test-agent");
        assert_eq!(report.counters.len(), 1);
        assert_eq!(report.counters[0].name, "requests");
        assert_eq!(report.counters[0].value, 100);
        assert_eq!(report.gauges.len(), 1);
        assert_eq!(report.gauges[0].name, "latency_ms");
        assert_eq!(report.gauges[0].value, 42.5);
    }

    #[test]
    fn test_metrics_report_builder() {
        let report = MetricsReport::new("test-agent", 10_000)
            .counter("requests", 100)
            .gauge("latency_ms", 42.5)
            .label("env", "prod");

        assert_eq!(report.counters.len(), 1);
        assert_eq!(report.gauges.len(), 1);
        assert_eq!(report.labels.get("env"), Some(&"prod".to_string()));
    }
}
