//! Decision builder with fluent API.
//!
//! Provides an ergonomic way to construct agent responses.

use sentinel_agent_protocol::{AgentResponse, AuditMetadata, Decision as ProtocolDecision, HeaderOp, PROTOCOL_VERSION};
use std::collections::HashMap;

/// A builder for constructing agent decisions.
///
/// # Examples
///
/// ```ignore
/// use sentinel_agent_sdk::Decision;
///
/// // Simple allow
/// let decision = Decision::allow();
///
/// // Block with status
/// let decision = Decision::block(403)
///     .with_body("Access denied");
///
/// // Allow with header modifications
/// let decision = Decision::allow()
///     .add_request_header("X-User-ID", "12345")
///     .add_response_header("X-Processed-By", "my-agent")
///     .with_tag("authenticated");
/// ```
#[derive(Debug, Clone, Default)]
pub struct Decision {
    decision: DecisionType,
    status_code: Option<u16>,
    body: Option<String>,
    block_headers: Option<HashMap<String, String>>,
    add_request_headers: HashMap<String, String>,
    remove_request_headers: Vec<String>,
    add_response_headers: HashMap<String, String>,
    remove_response_headers: Vec<String>,
    tags: Vec<String>,
    custom_metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default)]
enum DecisionType {
    #[default]
    Allow,
    Block,
    Redirect(String),
}

impl Decision {
    /// Create an allow decision.
    ///
    /// The request will continue to the upstream.
    pub fn allow() -> Self {
        Self {
            decision: DecisionType::Allow,
            ..Default::default()
        }
    }

    /// Create a block decision with a status code.
    ///
    /// The request will be rejected with the given status code.
    pub fn block(status_code: u16) -> Self {
        Self {
            decision: DecisionType::Block,
            status_code: Some(status_code),
            ..Default::default()
        }
    }

    /// Create a deny decision (403 Forbidden).
    ///
    /// Convenience method for `Decision::block(403)`.
    pub fn deny() -> Self {
        Self::block(403)
    }

    /// Create an unauthorized decision (401 Unauthorized).
    ///
    /// Convenience method for `Decision::block(401)`.
    pub fn unauthorized() -> Self {
        Self::block(401)
    }

    /// Create a rate limited decision (429 Too Many Requests).
    ///
    /// Convenience method for `Decision::block(429)`.
    pub fn rate_limited() -> Self {
        Self::block(429)
    }

    /// Create a redirect decision.
    ///
    /// The request will be redirected to the given URL with 302 status.
    pub fn redirect(url: impl Into<String>) -> Self {
        Self {
            decision: DecisionType::Redirect(url.into()),
            status_code: Some(302),
            ..Default::default()
        }
    }

    /// Create a permanent redirect (301).
    pub fn redirect_permanent(url: impl Into<String>) -> Self {
        Self {
            decision: DecisionType::Redirect(url.into()),
            status_code: Some(301),
            ..Default::default()
        }
    }

    /// Set the response body for block/error responses.
    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Set the response body as JSON.
    pub fn with_json_body<T: serde::Serialize>(mut self, value: &T) -> Self {
        if let Ok(json) = serde_json::to_string(value) {
            self.body = Some(json);
        }
        self
    }

    /// Add a header to the block response.
    pub fn with_block_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.block_headers
            .get_or_insert_with(HashMap::new)
            .insert(name.into(), value.into());
        self
    }

    /// Add a header to the request (sent to upstream).
    pub fn add_request_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.add_request_headers.insert(name.into(), value.into());
        self
    }

    /// Remove a header from the request.
    pub fn remove_request_header(mut self, name: impl Into<String>) -> Self {
        self.remove_request_headers.push(name.into());
        self
    }

    /// Add a header to the response (sent to client).
    pub fn add_response_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.add_response_headers.insert(name.into(), value.into());
        self
    }

    /// Remove a header from the response.
    pub fn remove_response_header(mut self, name: impl Into<String>) -> Self {
        self.remove_response_headers.push(name.into());
        self
    }

    /// Add an audit tag for logging/tracing.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Add multiple audit tags.
    pub fn with_tags(mut self, tags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.tags.extend(tags.into_iter().map(|t| t.into()));
        self
    }

    /// Add custom metadata for logging/tracing.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<serde_json::Value>) -> Self {
        self.custom_metadata.insert(key.into(), value.into());
        self
    }

    /// Build the protocol response.
    pub fn build(self) -> AgentResponse {
        let decision = match &self.decision {
            DecisionType::Allow => ProtocolDecision::Allow,
            DecisionType::Block => ProtocolDecision::Block {
                status: self.status_code.unwrap_or(403),
                body: self.body.clone(),
                headers: self.block_headers.clone(),
            },
            DecisionType::Redirect(url) => ProtocolDecision::Redirect {
                url: url.clone(),
                status: self.status_code.unwrap_or(302),
            },
        };

        let request_headers = self.build_request_mutations();
        let response_headers = self.build_response_mutations();

        AgentResponse {
            version: PROTOCOL_VERSION,
            decision,
            request_headers,
            response_headers,
            routing_metadata: HashMap::new(),
            audit: AuditMetadata {
                tags: self.tags,
                rule_ids: vec![],
                confidence: None,
                reason_codes: vec![],
                custom: self.custom_metadata,
            },
            needs_more: false,
            request_body_mutation: None,
            response_body_mutation: None,
            websocket_decision: None,
        }
    }

    fn build_request_mutations(&self) -> Vec<HeaderOp> {
        let mut mutations = Vec::new();

        for (name, value) in &self.add_request_headers {
            mutations.push(HeaderOp::Set {
                name: name.clone(),
                value: value.clone(),
            });
        }

        for name in &self.remove_request_headers {
            mutations.push(HeaderOp::Remove { name: name.clone() });
        }

        mutations
    }

    fn build_response_mutations(&self) -> Vec<HeaderOp> {
        let mut mutations = Vec::new();

        for (name, value) in &self.add_response_headers {
            mutations.push(HeaderOp::Set {
                name: name.clone(),
                value: value.clone(),
            });
        }

        for name in &self.remove_response_headers {
            mutations.push(HeaderOp::Remove { name: name.clone() });
        }

        mutations
    }
}

impl From<Decision> for AgentResponse {
    fn from(decision: Decision) -> Self {
        decision.build()
    }
}

/// Shorthand functions for common decisions.
pub mod decisions {
    use super::*;

    /// Allow the request.
    pub fn allow() -> AgentResponse {
        Decision::allow().build()
    }

    /// Block with 403 Forbidden.
    pub fn deny() -> AgentResponse {
        Decision::deny().build()
    }

    /// Block with 401 Unauthorized.
    pub fn unauthorized() -> AgentResponse {
        Decision::unauthorized().build()
    }

    /// Block with 429 Too Many Requests.
    pub fn rate_limited() -> AgentResponse {
        Decision::rate_limited().build()
    }

    /// Block with custom status and body.
    pub fn block(status_code: u16, body: impl Into<String>) -> AgentResponse {
        Decision::block(status_code).with_body(body).build()
    }

    /// Redirect to URL.
    pub fn redirect(url: impl Into<String>) -> AgentResponse {
        Decision::redirect(url).build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow() {
        let response = Decision::allow().build();
        assert!(matches!(response.decision, ProtocolDecision::Allow));
    }

    #[test]
    fn test_block() {
        let response = Decision::block(403)
            .with_body("Access denied")
            .build();

        match &response.decision {
            ProtocolDecision::Block { status, body, .. } => {
                assert_eq!(*status, 403);
                assert_eq!(body.as_deref(), Some("Access denied"));
            }
            _ => panic!("Expected block"),
        }
    }

    #[test]
    fn test_redirect() {
        let response = Decision::redirect("https://example.com/login").build();

        match &response.decision {
            ProtocolDecision::Redirect { url, status } => {
                assert_eq!(url, "https://example.com/login");
                assert_eq!(*status, 302);
            }
            _ => panic!("Expected redirect"),
        }
    }

    #[test]
    fn test_header_mutations() {
        let response = Decision::allow()
            .add_request_header("X-User-ID", "123")
            .remove_request_header("Cookie")
            .add_response_header("X-Processed", "true")
            .build();

        assert_eq!(response.request_headers.len(), 2);
        assert_eq!(response.response_headers.len(), 1);
    }

    #[test]
    fn test_tags_and_metadata() {
        let response = Decision::allow()
            .with_tag("authenticated")
            .with_tags(["verified", "admin"])
            .with_metadata("user_id", serde_json::json!("123"))
            .build();

        assert_eq!(response.audit.tags.len(), 3);
        assert!(response.audit.custom.contains_key("user_id"));
    }

    #[test]
    fn test_convenience_functions() {
        let _allow = decisions::allow();
        let _deny = decisions::deny();
        let _unauth = decisions::unauthorized();
        let _limited = decisions::rate_limited();
        let _block = decisions::block(500, "Error");
        let _redirect = decisions::redirect("/login");
    }

    #[test]
    fn test_json_body() {
        #[derive(serde::Serialize)]
        struct Error { code: u16, message: String }

        let response = Decision::block(400)
            .with_json_body(&Error { code: 400, message: "Bad request".into() })
            .build();

        match &response.decision {
            ProtocolDecision::Block { body, .. } => {
                assert!(body.as_ref().unwrap().contains("Bad request"));
            }
            _ => panic!("Expected block"),
        }
    }
}
