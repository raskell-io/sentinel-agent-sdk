//! Agent runner with CLI and server management.

use crate::agent::{Agent, AgentHandler};
use anyhow::Result;
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

/// Configuration for the agent runner.
#[derive(Debug, Clone)]
pub struct RunnerConfig {
    /// Unix socket path for the agent server.
    pub socket_path: PathBuf,
    /// Agent name for logging.
    pub name: String,
    /// Enable JSON logging format.
    pub json_logs: bool,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/tmp/zentinel-agent.sock"),
            name: "agent".to_string(),
            json_logs: false,
        }
    }
}

/// Runner for Zentinel agents.
///
/// Handles CLI parsing, logging setup, and server lifecycle.
///
/// # Example
///
/// ```ignore
/// use zentinel_agent_sdk::{AgentRunner, Agent, Request, Decision};
/// use async_trait::async_trait;
///
/// struct MyAgent;
///
/// #[async_trait]
/// impl Agent for MyAgent {
///     async fn on_request(&self, _request: &Request) -> Decision {
///         Decision::allow()
///     }
/// }
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     AgentRunner::new(MyAgent)
///         .with_name("my-agent")
///         .with_socket("/tmp/my-agent.sock")
///         .run()
///         .await
/// }
/// ```
pub struct AgentRunner<A: Agent> {
    agent: A,
    config: RunnerConfig,
}

impl<A: Agent> AgentRunner<A> {
    /// Create a new runner for the given agent.
    pub fn new(agent: A) -> Self {
        Self {
            agent,
            config: RunnerConfig::default(),
        }
    }

    /// Set the agent name (used for logging).
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.config.name = name.into();
        self
    }

    /// Set the Unix socket path.
    pub fn with_socket(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.socket_path = path.into();
        self
    }

    /// Enable JSON logging format.
    pub fn with_json_logs(mut self) -> Self {
        self.config.json_logs = true;
        self
    }

    /// Apply a full configuration.
    pub fn with_config(mut self, config: RunnerConfig) -> Self {
        self.config = config;
        self
    }

    /// Run the agent server.
    ///
    /// This method:
    /// 1. Sets up logging
    /// 2. Removes any existing socket file
    /// 3. Starts the Unix socket server
    /// 4. Handles graceful shutdown on SIGINT/SIGTERM
    pub async fn run(self) -> Result<()> {
        // Setup logging
        self.setup_logging();

        tracing::info!(
            agent = %self.config.name,
            socket = %self.config.socket_path.display(),
            "Starting agent"
        );

        // Remove existing socket file
        if self.config.socket_path.exists() {
            std::fs::remove_file(&self.config.socket_path)?;
        }

        // Create handler
        let handler = AgentHandler::new(self.agent);

        // Create server
        let server = zentinel_agent_protocol::AgentServer::new(
            self.config.name.clone(),
            self.config.socket_path.clone(),
            Box::new(handler),
        );

        // Start server with graceful shutdown
        let server_handle = tokio::spawn(async move {
            server.run().await
        });

        // Wait for shutdown signal
        Self::wait_for_shutdown().await;

        tracing::info!("Shutting down agent");

        // Abort the server task
        server_handle.abort();

        // Clean up socket file
        if self.config.socket_path.exists() {
            let _ = std::fs::remove_file(&self.config.socket_path);
        }

        Ok(())
    }

    fn setup_logging(&self) {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info"));

        if self.config.json_logs {
            fmt()
                .with_env_filter(filter)
                .json()
                .init();
        } else {
            fmt()
                .with_env_filter(filter)
                .init();
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

/// CLI argument parser for agents.
///
/// Use with the `cli` feature to get automatic argument parsing.
#[cfg(feature = "cli")]
pub mod cli {
    use super::*;
    use clap::Parser;

    /// Standard CLI arguments for Zentinel agents.
    #[derive(Parser, Debug)]
    #[command(author, version, about)]
    pub struct AgentArgs {
        /// Unix socket path for the agent server
        #[arg(short, long, default_value = "/tmp/zentinel-agent.sock")]
        pub socket: PathBuf,

        /// Enable JSON logging format
        #[arg(long)]
        pub json_logs: bool,
    }

    impl From<AgentArgs> for RunnerConfig {
        fn from(args: AgentArgs) -> Self {
            Self {
                socket_path: args.socket,
                json_logs: args.json_logs,
                ..Default::default()
            }
        }
    }

    /// Parse CLI arguments and create a runner config.
    pub fn parse_args() -> AgentArgs {
        AgentArgs::parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runner_config_default() {
        let config = RunnerConfig::default();
        assert_eq!(config.socket_path, PathBuf::from("/tmp/zentinel-agent.sock"));
        assert!(!config.json_logs);
    }

    #[test]
    fn test_runner_builder() {
        struct TestAgent;

        #[async_trait::async_trait]
        impl Agent for TestAgent {
            async fn on_request(&self, _: &crate::Request) -> crate::Decision {
                crate::Decision::allow()
            }
        }

        let runner = AgentRunner::new(TestAgent)
            .with_name("test")
            .with_socket("/tmp/test.sock")
            .with_json_logs();

        assert_eq!(runner.config.name, "test");
        assert_eq!(runner.config.socket_path, PathBuf::from("/tmp/test.sock"));
        assert!(runner.config.json_logs);
    }
}
