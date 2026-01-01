//! Simplified agent trait and handler definitions.
//!
//! This module provides a more ergonomic interface for building agents
//! compared to the low-level protocol handler.

use crate::{Decision, Request, Response};
use async_trait::async_trait;
use sentinel_agent_protocol::{AgentResponse, Decision as ProtocolDecision, PROTOCOL_VERSION};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A simplified agent trait for processing HTTP traffic.
///
/// Implement this trait to create a Sentinel agent. The SDK handles
/// protocol details, connection management, and error handling.
///
/// # Example
///
/// ```ignore
/// use sentinel_agent_sdk::{Agent, Request, Decision};
/// use async_trait::async_trait;
///
/// struct MyAgent;
///
/// #[async_trait]
/// impl Agent for MyAgent {
///     async fn on_request(&self, request: &Request) -> Decision {
///         if request.path_starts_with("/admin") {
///             Decision::deny()
///         } else {
///             Decision::allow()
///         }
///     }
/// }
/// ```
#[async_trait]
pub trait Agent: Send + Sync + 'static {
    /// Agent name for logging and identification.
    fn name(&self) -> &str {
        std::any::type_name::<Self>()
    }

    /// Called when the agent receives configuration from the proxy.
    ///
    /// Return `Ok(())` to accept the configuration, or `Err(message)`
    /// to reject it (which will prevent the proxy from starting).
    ///
    /// The default implementation accepts any configuration.
    async fn on_configure(&self, _config: serde_json::Value) -> Result<(), String> {
        Ok(())
    }

    /// Called for each incoming request (after headers received).
    ///
    /// This is the main entry point for request processing.
    /// Return a decision to allow, block, or modify the request.
    async fn on_request(&self, request: &Request) -> Decision {
        let _ = request;
        Decision::allow()
    }

    /// Called when the request body is available.
    ///
    /// Only called if body inspection is enabled for this agent.
    /// The request includes the accumulated body.
    async fn on_request_body(&self, request: &Request) -> Decision {
        let _ = request;
        Decision::allow()
    }

    /// Called when response headers are received from upstream.
    ///
    /// Allows modifying response headers before sending to client.
    async fn on_response(&self, request: &Request, response: &Response) -> Decision {
        let _ = (request, response);
        Decision::allow()
    }

    /// Called when the response body is available.
    ///
    /// Only called if response body inspection is enabled.
    async fn on_response_body(&self, request: &Request, response: &Response) -> Decision {
        let _ = (request, response);
        Decision::allow()
    }
}

/// A configurable agent that deserializes its configuration.
///
/// This trait extends `Agent` with typed configuration handling.
///
/// # Example
///
/// ```ignore
/// use sentinel_agent_sdk::{ConfigurableAgent, Request, Decision};
/// use serde::Deserialize;
///
/// #[derive(Default, Deserialize)]
/// #[serde(rename_all = "kebab-case")]
/// struct MyConfig {
///     enabled: bool,
///     threshold: u32,
/// }
///
/// struct MyAgent {
///     config: tokio::sync::RwLock<MyConfig>,
/// }
///
/// impl ConfigurableAgent for MyAgent {
///     type Config = MyConfig;
///
///     fn config(&self) -> &tokio::sync::RwLock<Self::Config> {
///         &self.config
///     }
/// }
/// ```
pub trait ConfigurableAgent: Agent {
    /// The configuration type for this agent.
    type Config: DeserializeOwned + Send + Sync + Default;

    /// Get a reference to the configuration storage.
    fn config(&self) -> &RwLock<Self::Config>;

    /// Called after configuration is successfully applied.
    ///
    /// Override this to perform additional setup after config changes.
    fn on_config_applied(&self, _config: &Self::Config) {}
}

/// Extension trait providing default `on_configure` for configurable agents.
#[async_trait]
pub trait ConfigurableAgentExt: ConfigurableAgent {
    /// Parse and apply configuration.
    async fn apply_config(&self, config_json: serde_json::Value) -> Result<(), String> {
        let config: Self::Config = serde_json::from_value(config_json)
            .map_err(|e| format!("Failed to parse config: {}", e))?;

        self.on_config_applied(&config);
        *self.config().write().await = config;
        Ok(())
    }
}

impl<T: ConfigurableAgent> ConfigurableAgentExt for T {}

/// Handler adapter that bridges the simplified Agent trait to the protocol.
///
/// This type holds a reference to your agent and stores request context
/// for correlation between request and response events.
pub struct AgentHandler<A: Agent> {
    agent: Arc<A>,
    /// Cache of request headers by correlation ID for response events
    request_cache: RwLock<HashMap<String, Request>>,
}

impl<A: Agent> AgentHandler<A> {
    /// Create a new handler wrapping the given agent.
    pub fn new(agent: A) -> Self {
        Self {
            agent: Arc::new(agent),
            request_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Get a reference to the underlying agent.
    pub fn agent(&self) -> &A {
        &self.agent
    }
}

#[async_trait]
impl<A: Agent> sentinel_agent_protocol::AgentHandler for AgentHandler<A> {
    async fn on_configure(
        &self,
        event: sentinel_agent_protocol::ConfigureEvent,
    ) -> AgentResponse {
        match self.agent.on_configure(event.config).await {
            Ok(()) => AgentResponse::default_allow(),
            Err(msg) => AgentResponse {
                version: PROTOCOL_VERSION,
                decision: ProtocolDecision::Block {
                    status: 500,
                    body: Some(msg),
                    headers: None,
                },
                request_headers: vec![],
                response_headers: vec![],
                routing_metadata: HashMap::new(),
                audit: Default::default(),
                needs_more: false,
                request_body_mutation: None,
                response_body_mutation: None,
                websocket_decision: None,
            },
        }
    }

    async fn on_request_headers(
        &self,
        event: sentinel_agent_protocol::RequestHeadersEvent,
    ) -> AgentResponse {
        let request = Request::from_headers_event(&event);

        // Cache the request for later response processing
        let correlation_id = request.correlation_id().to_string();
        self.request_cache.write().await.insert(correlation_id, request.clone());

        self.agent.on_request(&request).await.build()
    }

    async fn on_request_body_chunk(
        &self,
        event: sentinel_agent_protocol::RequestBodyChunkEvent,
    ) -> AgentResponse {
        // Get cached request and add body
        let cache = self.request_cache.read().await;
        if let Some(request) = cache.get(&event.correlation_id) {
            // Decode base64 body
            let body = base64_decode(&event.data).unwrap_or_default();
            let request_with_body = request.clone().with_body(body);
            drop(cache);
            return self.agent.on_request_body(&request_with_body).await.build();
        }
        AgentResponse::default_allow()
    }

    async fn on_response_headers(
        &self,
        event: sentinel_agent_protocol::ResponseHeadersEvent,
    ) -> AgentResponse {
        let response = Response::from_headers_event(&event);

        // Get cached request
        let cache = self.request_cache.read().await;
        if let Some(request) = cache.get(&event.correlation_id) {
            return self.agent.on_response(request, &response).await.build();
        }
        AgentResponse::default_allow()
    }

    async fn on_response_body_chunk(
        &self,
        event: sentinel_agent_protocol::ResponseBodyChunkEvent,
    ) -> AgentResponse {
        // For response body, we need both request and response context
        // This is a simplified implementation - full implementation would
        // also cache response headers
        let cache = self.request_cache.read().await;
        if let Some(request) = cache.get(&event.correlation_id) {
            // Create a minimal response with body
            let body = base64_decode(&event.data).unwrap_or_default();
            let response = Response::from_headers_event(&sentinel_agent_protocol::ResponseHeadersEvent {
                correlation_id: event.correlation_id.clone(),
                status: 200,
                headers: HashMap::new(),
            }).with_body(body);
            return self.agent.on_response_body(request, &response).await.build();
        }
        AgentResponse::default_allow()
    }

    async fn on_request_complete(
        &self,
        event: sentinel_agent_protocol::RequestCompleteEvent,
    ) -> AgentResponse {
        // Clean up cache when request completes
        self.request_cache.write().await.remove(&event.correlation_id);
        AgentResponse::default_allow()
    }
}

/// Decode base64 string to bytes
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use std::io::Read;
    let bytes = s.as_bytes();
    let mut decoder = base64::read::DecoderReader::new(bytes, &base64::engine::general_purpose::STANDARD);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).ok()?;
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestAgent;

    #[async_trait]
    impl Agent for TestAgent {
        fn name(&self) -> &str {
            "test-agent"
        }

        async fn on_request(&self, request: &Request) -> Decision {
            if request.path_starts_with("/blocked") {
                Decision::deny().with_body("Blocked")
            } else {
                Decision::allow()
            }
        }
    }

    #[tokio::test]
    async fn test_agent_handler() {
        let handler = AgentHandler::new(TestAgent);
        assert_eq!(handler.agent().name(), "test-agent");
    }
}
