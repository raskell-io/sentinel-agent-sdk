//! Simplified request types for agent handlers.
//!
//! These types wrap the protocol events with a more ergonomic API.

use sentinel_agent_protocol::RequestHeadersEvent;
use std::collections::HashMap;

/// A simplified view of an HTTP request for agent processing.
///
/// This wraps the protocol's `RequestHeadersEvent` with convenience methods.
#[derive(Debug, Clone)]
pub struct Request {
    /// The request method (GET, POST, etc.)
    method: String,
    /// The request path including query string
    path: String,
    /// The path without query string
    path_only: String,
    /// Query string (without leading ?)
    query_string: Option<String>,
    /// Parsed query parameters
    query_params: HashMap<String, Vec<String>>,
    /// Request headers (lowercase keys)
    headers: HashMap<String, Vec<String>>,
    /// Client IP address
    client_ip: String,
    /// Correlation ID for tracing
    correlation_id: String,
    /// Request body (if available)
    body: Option<Vec<u8>>,
}

impl Request {
    /// Create a new Request from protocol event.
    pub fn from_headers_event(event: &RequestHeadersEvent) -> Self {
        let path = event.uri.clone();
        let (path_only, query_string) = match path.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (path.clone(), None),
        };

        let query_params = query_string
            .as_ref()
            .map(|qs| parse_query_string(qs))
            .unwrap_or_default();

        Self {
            method: event.method.clone(),
            path,
            path_only,
            query_string,
            query_params,
            headers: event.headers.clone(),
            client_ip: event.metadata.client_ip.clone(),
            correlation_id: event.metadata.correlation_id.clone(),
            body: None,
        }
    }

    /// Add body data to the request.
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Get the HTTP method.
    #[inline]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Check if this is a GET request.
    #[inline]
    pub fn is_get(&self) -> bool {
        self.method.eq_ignore_ascii_case("GET")
    }

    /// Check if this is a POST request.
    #[inline]
    pub fn is_post(&self) -> bool {
        self.method.eq_ignore_ascii_case("POST")
    }

    /// Get the full path including query string.
    #[inline]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Get the path without query string.
    #[inline]
    pub fn path_only(&self) -> &str {
        &self.path_only
    }

    /// Get the query string (without leading ?).
    #[inline]
    pub fn query_string(&self) -> Option<&str> {
        self.query_string.as_deref()
    }

    /// Get a query parameter value.
    ///
    /// Returns the first value if multiple exist.
    pub fn query(&self, name: &str) -> Option<&str> {
        self.query_params.get(name).and_then(|v| v.first().map(|s| s.as_str()))
    }

    /// Get all values for a query parameter.
    pub fn query_all(&self, name: &str) -> Option<&[String]> {
        self.query_params.get(name).map(|v| v.as_slice())
    }

    /// Get all query parameters.
    pub fn query_params(&self) -> &HashMap<String, Vec<String>> {
        &self.query_params
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

    /// Get the Host header.
    #[inline]
    pub fn host(&self) -> Option<&str> {
        self.header("host")
    }

    /// Get the User-Agent header.
    #[inline]
    pub fn user_agent(&self) -> Option<&str> {
        self.header("user-agent")
    }

    /// Get the Content-Type header.
    #[inline]
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Get the Content-Length header as a number.
    pub fn content_length(&self) -> Option<usize> {
        self.header("content-length")
            .and_then(|v| v.parse().ok())
    }

    /// Get the Authorization header.
    #[inline]
    pub fn authorization(&self) -> Option<&str> {
        self.header("authorization")
    }

    /// Get the client IP address.
    #[inline]
    pub fn client_ip(&self) -> &str {
        &self.client_ip
    }

    /// Get the correlation ID for tracing.
    #[inline]
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    /// Get the request body if available.
    #[inline]
    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }

    /// Get the request body as a UTF-8 string.
    pub fn body_str(&self) -> Option<&str> {
        self.body.as_ref().and_then(|b| std::str::from_utf8(b).ok())
    }

    /// Parse the request body as JSON.
    pub fn body_json<T: serde::de::DeserializeOwned>(&self) -> Option<T> {
        self.body.as_ref().and_then(|b| serde_json::from_slice(b).ok())
    }

    /// Check if the path starts with a prefix.
    pub fn path_starts_with(&self, prefix: &str) -> bool {
        self.path_only.starts_with(prefix)
    }

    /// Check if the path matches exactly.
    pub fn path_equals(&self, path: &str) -> bool {
        self.path_only == path
    }
}

/// Parse a query string into key-value pairs.
fn parse_query_string(qs: &str) -> HashMap<String, Vec<String>> {
    let mut params: HashMap<String, Vec<String>> = HashMap::new();

    for pair in qs.split('&') {
        if pair.is_empty() {
            continue;
        }

        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };

        // URL decode (basic)
        let key = urlish_decode(key);
        let value = urlish_decode(value);

        params.entry(key).or_default().push(value);
    }

    params
}

/// Basic URL decoding (handles %XX sequences).
fn urlish_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_agent_protocol::RequestMetadata;

    fn make_event(method: &str, uri: &str, headers: Vec<(&str, &str)>) -> RequestHeadersEvent {
        let mut header_map = HashMap::new();
        for (k, v) in headers {
            header_map.entry(k.to_lowercase()).or_insert_with(Vec::new).push(v.to_string());
        }

        RequestHeadersEvent {
            metadata: RequestMetadata {
                correlation_id: "test-123".to_string(),
                request_id: "req-456".to_string(),
                client_ip: "192.168.1.100".to_string(),
                client_port: 54321,
                server_name: Some("example.com".to_string()),
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: Some("default".to_string()),
                upstream_id: Some("backend".to_string()),
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            },
            method: method.to_string(),
            uri: uri.to_string(),
            headers: header_map,
        }
    }

    #[test]
    fn test_basic_request() {
        let event = make_event("GET", "/api/users", vec![("host", "example.com")]);
        let req = Request::from_headers_event(&event);

        assert_eq!(req.method(), "GET");
        assert!(req.is_get());
        assert!(!req.is_post());
        assert_eq!(req.path(), "/api/users");
        assert_eq!(req.path_only(), "/api/users");
        assert_eq!(req.query_string(), None);
        assert_eq!(req.host(), Some("example.com"));
        assert_eq!(req.client_ip(), "192.168.1.100");
    }

    #[test]
    fn test_query_params() {
        let event = make_event("GET", "/search?q=rust&limit=10&q=programming", vec![]);
        let req = Request::from_headers_event(&event);

        assert_eq!(req.path_only(), "/search");
        assert_eq!(req.query_string(), Some("q=rust&limit=10&q=programming"));
        assert_eq!(req.query("q"), Some("rust"));
        assert_eq!(req.query_all("q"), Some(&["rust".to_string(), "programming".to_string()][..]));
        assert_eq!(req.query("limit"), Some("10"));
        assert_eq!(req.query("missing"), None);
    }

    #[test]
    fn test_url_decoding() {
        let event = make_event("GET", "/search?q=hello%20world&name=foo%2Bbar", vec![]);
        let req = Request::from_headers_event(&event);

        assert_eq!(req.query("q"), Some("hello world"));
        assert_eq!(req.query("name"), Some("foo+bar"));
    }

    #[test]
    fn test_headers() {
        let event = make_event(
            "POST",
            "/api/data",
            vec![
                ("content-type", "application/json"),
                ("authorization", "Bearer token123"),
                ("x-custom", "value1"),
                ("x-custom", "value2"),
            ],
        );
        let req = Request::from_headers_event(&event);

        assert_eq!(req.content_type(), Some("application/json"));
        assert_eq!(req.authorization(), Some("Bearer token123"));
        assert_eq!(req.header("X-Custom"), Some("value1")); // Case insensitive
        assert_eq!(req.header_all("x-custom"), Some(&["value1".to_string(), "value2".to_string()][..]));
        assert!(req.has_header("Content-Type"));
        assert!(!req.has_header("X-Missing"));
    }

    #[test]
    fn test_body() {
        let event = make_event("POST", "/api/data", vec![]);
        let req = Request::from_headers_event(&event)
            .with_body(b"{\"name\": \"test\"}".to_vec());

        assert!(req.body().is_some());
        assert_eq!(req.body_str(), Some("{\"name\": \"test\"}"));

        #[derive(serde::Deserialize)]
        struct Data { name: String }
        let data: Option<Data> = req.body_json();
        assert_eq!(data.map(|d| d.name), Some("test".to_string()));
    }

    #[test]
    fn test_path_matching() {
        let event = make_event("GET", "/api/v1/users/123", vec![]);
        let req = Request::from_headers_event(&event);

        assert!(req.path_starts_with("/api"));
        assert!(req.path_starts_with("/api/v1"));
        assert!(!req.path_starts_with("/v1"));
        assert!(!req.path_equals("/api/v1/users"));
        assert!(req.path_equals("/api/v1/users/123"));
    }
}
