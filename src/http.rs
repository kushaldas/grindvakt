//! Framework-agnostic HTTP request/response types and an outbound client trait.
//!
//! Keeping these decoupled from actix lets the core and plugin crates be unit
//! tested without spinning up a server, and lets the OIDC library issue
//! outbound calls through an injected client.

use std::collections::BTreeMap;

/// A parsed inbound HTTP request, normalized for the proxy flow.
#[derive(Debug, Clone, Default)]
pub struct HttpRequestData {
    /// Request path with the leading slash stripped, e.g. `Saml2/acs/post`.
    pub path: String,
    /// HTTP method, uppercased.
    pub method: String,
    /// Full request URI (scheme://host/path?query) when available.
    pub uri: String,
    /// Query-string parameters.
    pub query: BTreeMap<String, String>,
    /// Parsed form body parameters (application/x-www-form-urlencoded).
    pub form: BTreeMap<String, String>,
    /// Raw request body.
    pub body: Vec<u8>,
    /// Lower-cased header name -> value.
    pub headers: BTreeMap<String, String>,
    /// Parsed cookies: name -> value.
    pub cookies: BTreeMap<String, String>,
}

impl HttpRequestData {
    /// Look up a parameter from the query string first, then the form body.
    pub fn param(&self, key: &str) -> Option<&str> {
        self.query
            .get(key)
            .or_else(|| self.form.get(key))
            .map(|s| s.as_str())
    }

    /// The value of the `Authorization` header, if present.
    pub fn authorization(&self) -> Option<&str> {
        self.headers.get("authorization").map(|s| s.as_str())
    }

    /// Extract a Bearer token from the Authorization header.
    pub fn bearer_token(&self) -> Option<&str> {
        let auth = self.authorization()?;
        let (scheme, token) = auth.split_once(' ')?;
        if scheme.eq_ignore_ascii_case("Bearer") {
            Some(token.trim())
        } else {
            None
        }
    }
}

/// A framework-agnostic HTTP response produced by a handler.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// 302 redirect to `location`.
    pub fn redirect(location: impl Into<String>) -> Self {
        Response::new(302).with_header("location", location)
    }

    /// A `text/html` response.
    pub fn html(body: impl Into<String>) -> Self {
        let body = body.into();
        Response::new(200)
            .with_header("content-type", "text/html; charset=utf-8")
            .with_body(body.into_bytes())
    }

    /// An `application/json` response from a serializable value.
    pub fn json<T: serde::Serialize>(value: &T) -> crate::error::Result<Self> {
        let body = serde_json::to_vec(value)?;
        Ok(Response::new(200)
            .with_header("content-type", "application/json")
            .with_body(body))
    }

    /// An `application/json` response with an explicit status.
    pub fn json_status<T: serde::Serialize>(
        status: u16,
        value: &T,
    ) -> crate::error::Result<Self> {
        let mut r = Response::json(value)?;
        r.status = status;
        Ok(r)
    }

    /// A plain-text response.
    pub fn text(status: u16, body: impl Into<String>) -> Self {
        Response::new(status)
            .with_header("content-type", "text/plain; charset=utf-8")
            .with_body(body.into().into_bytes())
    }
}

/// Trait for an outbound HTTP client, injected into the OIDC/federation logic so
/// the protocol library stays runtime-agnostic. Implemented in the binary with
/// `reqwest`.
#[async_trait::async_trait]
pub trait HttpClient: Send + Sync {
    /// Issue a GET and return the body bytes (and status).
    async fn get(&self, url: &str) -> crate::error::Result<HttpFetchResponse>;

    /// Issue a form-encoded POST.
    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        headers: &[(String, String)],
    ) -> crate::error::Result<HttpFetchResponse>;
}

/// The result of an outbound fetch.
#[derive(Debug, Clone)]
pub struct HttpFetchResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
}

impl HttpFetchResponse {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> crate::error::Result<T> {
        serde_json::from_slice(&self.body).map_err(crate::error::Error::from)
    }
}
