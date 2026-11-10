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
    /// Ordered query-string parameters. Protocol parsers must consume this
    /// representation so duplicate names remain visible for rejection.
    pub query_pairs: Vec<(String, String)>,
    /// Convenience query map for non-protocol application lookups. Duplicate
    /// names have already been flattened; do not use it at a protocol boundary.
    pub query: BTreeMap<String, String>,
    /// Ordered form body parameters. Token endpoint handlers must consume this
    /// representation so duplicate names remain visible for rejection.
    pub form_pairs: Vec<(String, String)>,
    /// Convenience form map for non-protocol application lookups. Duplicate
    /// names have already been flattened; do not use it at a protocol boundary.
    pub form: BTreeMap<String, String>,
    /// Raw request body.
    pub body: Vec<u8>,
    /// Lower-cased header name -> value.
    pub headers: BTreeMap<String, String>,
    /// Parsed cookies: name -> value.
    pub cookies: BTreeMap<String, String>,
}

impl HttpRequestData {
    /// Look up a convenience parameter from the flattened query/form maps.
    /// Protocol handlers must instead pass `query_pairs` or `form_pairs` to
    /// their duplicate-rejecting entry points.
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
    pub fn json_status<T: serde::Serialize>(status: u16, value: &T) -> crate::error::Result<Self> {
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
///
/// # Redirects and credentials
///
/// The library validates request URLs against the issuer policy, but it cannot
/// validate where a server redirects to. Implementors **must** follow these
/// rules; the library cannot enforce them:
///
/// - **`post_form`** carries credentials in the body (`client_secret`,
///   `client_assertion`, the authorization code and PKCE verifier) and often an
///   `Authorization` header. Do not follow redirects to a different origin at
///   all, including method-preserving `307` and `308` redirects, which
///   resend the body; fail the request instead. Stripping `Authorization` or
///   dropping the body only on a method change (`301`/`302`/`303`) is **not**
///   enough. The simplest correct policy is to not follow redirects for
///   `post_form`.
/// - **`post_json`** has the same exposure as `post_form`: do not follow
///   redirects to a different origin.
/// - **`get_with_headers`** may carry `Authorization: Bearer`. Either do not
///   follow redirects or strip `Authorization` (and any other credential
///   header) when a redirect crosses origins.
///
/// Otherwise a redirecting endpoint receives the credential.
#[async_trait::async_trait]
pub trait HttpClient: Send + Sync {
    /// Issue a GET and return the body bytes (and status).
    async fn get(&self, url: &str) -> crate::error::Result<HttpFetchResponse>;

    /// Issue a form-encoded POST.
    ///
    /// The form and headers can hold credentials: do not follow cross-origin
    /// redirects, including `307` and `308` (see the trait documentation).
    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        headers: &[(String, String)],
    ) -> crate::error::Result<HttpFetchResponse>;

    /// Issue a GET carrying request headers (e.g. `Authorization: Bearer`).
    ///
    /// The default implementation returns an error; override it to enable GET
    /// UserInfo requests. Implementations must not forward these headers when
    /// following redirects to another origin (see the trait documentation):
    /// override this only if your client strips `Authorization` on a
    /// cross-origin redirect or does not follow redirects.
    async fn get_with_headers(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> crate::error::Result<HttpFetchResponse> {
        let _ = (url, headers);
        Err(crate::error::Error::Config(
            "this HttpClient does not implement get_with_headers".into(),
        ))
    }

    /// Issue a POST with an `application/json` body.
    ///
    /// The default implementation returns an error; override it to enable
    /// JSON POSTs (for example to an AuthZEN policy decision point).
    /// Implementations must set `Content-Type: application/json` and, like
    /// `post_form`, must not follow cross-origin redirects, including `307`
    /// and `308`, because the body and headers can hold credentials (see the
    /// trait documentation).
    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
        headers: &[(String, String)],
    ) -> crate::error::Result<HttpFetchResponse> {
        let _ = (url, body, headers);
        Err(crate::error::Error::Config(
            "this HttpClient does not implement post_json".into(),
        ))
    }
}

/// The result of an outbound fetch.
///
/// `HttpClient` implementations should fill in both `content_type` and
/// `headers`. Prefer [`HttpFetchResponse::new`] and
/// [`HttpFetchResponse::with_header`], or a struct literal ending in
/// `..Default::default()`, so new fields do not break the construction site.
/// `content_type` stays authoritative for existing readers such as
/// `federation::fetch_signed_jwks`; `headers` carries everything else
/// (for example `Cache-Control`).
#[derive(Debug, Clone, Default)]
pub struct HttpFetchResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
    /// Response headers, names lower-cased, in order; repeated headers kept.
    pub headers: Vec<(String, String)>,
}

impl HttpFetchResponse {
    /// A response with a status and body and no headers.
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            body: body.into(),
            ..Default::default()
        }
    }

    /// Append a header. The stored name is lower-cased. A `Content-Type`
    /// header also sets `content_type` when it is still unset.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into().to_ascii_lowercase();
        let value = value.into();
        if name == "content-type" && self.content_type.is_none() {
            self.content_type = Some(value.clone());
        }
        self.headers.push((name, value));
        self
    }

    /// The first header value with this name, compared case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// All header values with this name, in order, compared case-insensitively.
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// The `Cache-Control` value, if present. Multiple field lines are joined
    /// with `", "` (a comma-separated list, RFC 9110 §5.3).
    pub fn cache_control(&self) -> Option<String> {
        let values = self.header_values("cache-control");
        if values.is_empty() {
            None
        } else {
            Some(values.join(", "))
        }
    }

    /// The `Age` header (RFC 9111 §5.1) in seconds. Only a trimmed,
    /// digits-only value counts, and the first `Age` header wins; a value too
    /// large for `u64` saturates to `u64::MAX` ("very old") rather than being
    /// ignored. `None` when absent or malformed.
    pub fn age(&self) -> Option<u64> {
        self.header("age")
            .map(str::trim)
            .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
            .map(|v| v.parse::<u64>().unwrap_or(u64::MAX))
    }

    /// Freshness lifetime advertised by `Cache-Control`, ignoring `Age` and
    /// **not capped** (an upstream controls it). `Some(0)` for `no-store` or
    /// `no-cache`; `None` when absent or without a usable `max-age`. Same
    /// rules as `JwksResponse::advertised_ttl_secs`.
    pub fn advertised_ttl_secs(&self) -> Option<u64> {
        crate::rp::advertised_ttl(self.cache_control().as_deref())
    }

    /// Remaining freshness in seconds: the advertised lifetime minus
    /// [`HttpFetchResponse::age`], saturating at 0, limited to `ceiling`.
    /// `None` when `Cache-Control` gives no usable lifetime.
    pub fn cache_ttl_secs_max(&self, ceiling: u64) -> Option<u64> {
        self.advertised_ttl_secs()
            .map(|ttl| ttl.saturating_sub(self.age().unwrap_or(0)).min(ceiling))
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> crate::error::Result<T> {
        serde_json::from_slice(&self.body).map_err(crate::error::Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn age_parsing() {
        let r = |v: &str| HttpFetchResponse::new(200, "").with_header("Age", v).age();
        assert_eq!(HttpFetchResponse::new(200, "").age(), None);
        assert_eq!(r(" 60 "), Some(60));
        assert_eq!(r("0"), Some(0));
        assert_eq!(r("abc"), None);
        assert_eq!(r("-1"), None);
        assert_eq!(r("+1"), None);
        assert_eq!(r(""), None);
        assert_eq!(r("99999999999999999999999"), Some(u64::MAX));
        let repeated = HttpFetchResponse::new(200, "")
            .with_header("Age", "5")
            .with_header("age", "9");
        assert_eq!(repeated.age(), Some(5));
        let bad_first = HttpFetchResponse::new(200, "")
            .with_header("Age", "x")
            .with_header("Age", "9");
        assert_eq!(bad_first.age(), None);
    }

    struct BasicClient;

    #[async_trait::async_trait]
    impl HttpClient for BasicClient {
        async fn get(&self, _url: &str) -> crate::error::Result<HttpFetchResponse> {
            Ok(HttpFetchResponse::new(200, "get"))
        }

        async fn post_form(
            &self,
            _url: &str,
            _form: &[(String, String)],
            _headers: &[(String, String)],
        ) -> crate::error::Result<HttpFetchResponse> {
            Ok(HttpFetchResponse::new(200, "post"))
        }
    }

    #[derive(Default)]
    struct RecordingClient {
        seen: Mutex<Vec<(String, String)>>,
        body: Mutex<Option<serde_json::Value>>,
    }

    #[async_trait::async_trait]
    impl HttpClient for RecordingClient {
        async fn get(&self, _url: &str) -> crate::error::Result<HttpFetchResponse> {
            Ok(HttpFetchResponse::new(200, "get"))
        }

        async fn post_form(
            &self,
            _url: &str,
            _form: &[(String, String)],
            _headers: &[(String, String)],
        ) -> crate::error::Result<HttpFetchResponse> {
            Ok(HttpFetchResponse::new(200, "post"))
        }

        async fn get_with_headers(
            &self,
            _url: &str,
            headers: &[(String, String)],
        ) -> crate::error::Result<HttpFetchResponse> {
            *self.seen.lock().unwrap() = headers.to_vec();
            Ok(HttpFetchResponse::new(200, "headers"))
        }

        async fn post_json(
            &self,
            _url: &str,
            body: &serde_json::Value,
            headers: &[(String, String)],
        ) -> crate::error::Result<HttpFetchResponse> {
            *self.seen.lock().unwrap() = headers.to_vec();
            *self.body.lock().unwrap() = Some(body.clone());
            Ok(HttpFetchResponse::new(200, "json"))
        }
    }

    #[tokio::test]
    async fn post_json_defaults_to_error() {
        let err = BasicClient
            .post_json(
                "https://pdp.example/evaluation",
                &serde_json::json!({}),
                &[],
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("post_json"), "{err}");
    }

    #[tokio::test]
    async fn get_with_headers_defaults_to_error() {
        let err = BasicClient
            .get_with_headers("https://op.example/userinfo", &[])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("get_with_headers"), "{err}");
    }

    #[tokio::test]
    async fn post_json_override_receives_body_and_headers() {
        let c = RecordingClient::default();
        let h = vec![("Authorization".to_string(), "Bearer t".to_string())];
        let body = serde_json::json!({"a": 1});
        let r = c
            .post_json("https://pdp.example/evaluation", &body, &h)
            .await
            .unwrap();
        assert_eq!(r.body, b"json");
        assert_eq!(*c.seen.lock().unwrap(), h);
        assert_eq!(c.body.lock().unwrap().as_ref(), Some(&body));
    }

    #[tokio::test]
    async fn get_with_headers_override_receives_headers() {
        let c = RecordingClient::default();
        let h = vec![("Authorization".to_string(), "Bearer t".to_string())];
        let r = c
            .get_with_headers("https://op.example/userinfo", &h)
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(*c.seen.lock().unwrap(), h);
    }

    #[test]
    fn header_lookup_is_case_insensitive_and_returns_first() {
        let r = HttpFetchResponse::new(200, "x")
            .with_header("X-Thing", "one")
            .with_header("x-thing", "two");
        assert_eq!(r.header("X-THING"), Some("one"));
        assert_eq!(r.headers.len(), 2);
        assert_eq!(r.header("missing"), None);
    }

    #[test]
    fn cache_control_reads_header() {
        let r = HttpFetchResponse::new(200, Vec::new()).with_header("Cache-Control", "max-age=60");
        assert_eq!(r.cache_control().as_deref(), Some("max-age=60"));
        assert_eq!(HttpFetchResponse::default().cache_control(), None);
    }

    #[test]
    fn header_values_returns_all_in_order() {
        let r = HttpFetchResponse::new(200, "x")
            .with_header("X-Thing", "one")
            .with_header("Other", "z")
            .with_header("x-thing", "two");
        assert_eq!(r.header_values("X-THING"), vec!["one", "two"]);
        assert!(r.header_values("missing").is_empty());
    }

    #[test]
    fn cache_control_joins_multiple_lines() {
        let r = HttpFetchResponse::new(200, "x")
            .with_header("Cache-Control", "max-age=3600")
            .with_header("cache-control", "no-store");
        assert_eq!(r.cache_control().as_deref(), Some("max-age=3600, no-store"));
    }

    #[test]
    fn content_type_header_fills_content_type() {
        let r = HttpFetchResponse::new(200, Vec::new()).with_header("Content-Type", "text/plain");
        assert_eq!(r.content_type.as_deref(), Some("text/plain"));
        assert_eq!(r.headers[0].0, "content-type");
    }

    #[test]
    fn default_has_empty_headers() {
        let r = HttpFetchResponse::default();
        assert!(r.headers.is_empty());
        assert_eq!(r.status, 0);
    }
}
