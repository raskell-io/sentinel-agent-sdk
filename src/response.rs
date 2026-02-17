//! Simplified response types for agent handlers.
//!
//! These types wrap the protocol events with a more ergonomic API.

use zentinel_agent_protocol::ResponseHeadersEvent;
use std::collections::HashMap;

/// A simplified view of an HTTP response for agent processing.
///
/// This wraps the protocol's `ResponseHeadersEvent` with convenience methods.
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP status code
    status_code: u16,
    /// Response headers (lowercase keys)
    headers: HashMap<String, Vec<String>>,
    /// Response body (if available)
    body: Option<Vec<u8>>,
    /// Correlation ID for tracing
    correlation_id: String,
}

impl Response {
    /// Create a new Response from protocol event.
    pub fn from_headers_event(event: &ResponseHeadersEvent) -> Self {
        Self {
            status_code: event.status,
            headers: event.headers.clone(),
            body: None,
            correlation_id: event.correlation_id.clone(),
        }
    }

    /// Add body data to the response.
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Get the HTTP status code.
    #[inline]
    pub fn status_code(&self) -> u16 {
        self.status_code
    }

    /// Check if the response is successful (2xx).
    #[inline]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    /// Check if the response is a redirect (3xx).
    #[inline]
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status_code)
    }

    /// Check if the response is a client error (4xx).
    #[inline]
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.status_code)
    }

    /// Check if the response is a server error (5xx).
    #[inline]
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.status_code)
    }

    /// Check if the response is an error (4xx or 5xx).
    #[inline]
    pub fn is_error(&self) -> bool {
        self.status_code >= 400
    }

    /// Get a header value.
    ///
    /// Header names are case-insensitive. Returns the first value if multiple exist.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_lowercase())
            .and_then(|v| v.first().map(|s| s.as_str()))
    }

    /// Get all values for a header.
    pub fn header_all(&self, name: &str) -> Option<&[String]> {
        self.headers.get(&name.to_lowercase()).map(|v| v.as_slice())
    }

    /// Get all headers.
    pub fn headers(&self) -> &HashMap<String, Vec<String>> {
        &self.headers
    }

    /// Check if a header exists.
    pub fn has_header(&self, name: &str) -> bool {
        self.headers.contains_key(&name.to_lowercase())
    }

    /// Get the Content-Type header.
    #[inline]
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Check if the response is JSON.
    pub fn is_json(&self) -> bool {
        self.content_type()
            .map(|ct| ct.contains("application/json"))
            .unwrap_or(false)
    }

    /// Check if the response is HTML.
    pub fn is_html(&self) -> bool {
        self.content_type()
            .map(|ct| ct.contains("text/html"))
            .unwrap_or(false)
    }

    /// Get the Content-Length header as a number.
    pub fn content_length(&self) -> Option<usize> {
        self.header("content-length")
            .and_then(|v| v.parse().ok())
    }

    /// Get the Location header (for redirects).
    #[inline]
    pub fn location(&self) -> Option<&str> {
        self.header("location")
    }

    /// Get the correlation ID for tracing.
    #[inline]
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    /// Get the response body if available.
    #[inline]
    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }

    /// Get the response body as a UTF-8 string.
    pub fn body_str(&self) -> Option<&str> {
        self.body.as_ref().and_then(|b| std::str::from_utf8(b).ok())
    }

    /// Parse the response body as JSON.
    pub fn body_json<T: serde::de::DeserializeOwned>(&self) -> Option<T> {
        self.body.as_ref().and_then(|b| serde_json::from_slice(b).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(status: u16, headers: Vec<(&str, &str)>) -> ResponseHeadersEvent {
        let mut header_map = HashMap::new();
        for (k, v) in headers {
            header_map.entry(k.to_lowercase()).or_insert_with(Vec::new).push(v.to_string());
        }

        ResponseHeadersEvent {
            correlation_id: "test-123".to_string(),
            status,
            headers: header_map,
        }
    }

    #[test]
    fn test_basic_response() {
        let event = make_event(200, vec![("content-type", "application/json")]);
        let res = Response::from_headers_event(&event);

        assert_eq!(res.status_code(), 200);
        assert!(res.is_success());
        assert!(!res.is_error());
        assert!(res.is_json());
    }

    #[test]
    fn test_status_categories() {
        let ok = Response::from_headers_event(&make_event(200, vec![]));
        assert!(ok.is_success());

        let redirect = Response::from_headers_event(&make_event(302, vec![("location", "/new")]));
        assert!(redirect.is_redirect());
        assert_eq!(redirect.location(), Some("/new"));

        let not_found = Response::from_headers_event(&make_event(404, vec![]));
        assert!(not_found.is_client_error());
        assert!(not_found.is_error());

        let server_error = Response::from_headers_event(&make_event(500, vec![]));
        assert!(server_error.is_server_error());
        assert!(server_error.is_error());
    }

    #[test]
    fn test_headers() {
        let event = make_event(
            200,
            vec![
                ("content-type", "text/html"),
                ("x-custom", "value1"),
                ("x-custom", "value2"),
            ],
        );
        let res = Response::from_headers_event(&event);

        assert!(res.is_html());
        assert!(res.has_header("Content-Type")); // Case insensitive
        assert_eq!(res.header("x-custom"), Some("value1"));
        assert_eq!(res.header_all("x-custom"), Some(&["value1".to_string(), "value2".to_string()][..]));
    }

    #[test]
    fn test_body() {
        let event = make_event(200, vec![("content-type", "application/json")]);
        let res = Response::from_headers_event(&event)
            .with_body(b"{\"status\": \"ok\"}".to_vec());

        assert!(res.body().is_some());
        assert_eq!(res.body_str(), Some("{\"status\": \"ok\"}"));

        #[derive(serde::Deserialize)]
        struct Status { status: String }
        let data: Option<Status> = res.body_json();
        assert_eq!(data.map(|d| d.status), Some("ok".to_string()));
    }
}
