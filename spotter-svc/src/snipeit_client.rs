// pattern: Imperative Shell

//! Authenticated Snipe-IT HTTP transport.

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use reqwest::{Client, Response, StatusCode, Url};

const MAX_SUCCESS_BODY_BYTES: usize = 1024 * 1024;
const MAX_ERROR_BODY_BYTES: usize = 16 * 1024;
const PAGE_SIZE: usize = 100;
const MAX_PAGE_REQUESTS: usize = 100;
const MAX_TOTAL_ROWS: usize = 10_000;
const PAGINATION_DEADLINE: Duration = Duration::from_secs(60);
use secrecy::{ExposeSecret as _, SecretString};
use serde::de::DeserializeOwned;
use spotter_core::{
    snipeit::{
        Asset, AssetModel, AssetPatchRequest, Category, CheckinRequest, CheckoutRequest,
        Manufacturer, SnipeItError, parse_asset_by_serial, parse_asset_patch,
        parse_checkin_response, parse_checkout_response,
    },
    validate_snipeit_url,
};

pub struct SnipeItClient {
    client: Client,
    base_url: Url,
    token: SecretString,
}

impl SnipeItClient {
    /// Construct an authenticated client with a 30-second request timeout.
    ///
    /// # Errors
    /// Returns an error when the HTTP client cannot be built or URL is invalid.
    pub fn new(base_url: impl Into<String>, token: SecretString) -> Result<Self> {
        Self::with_timeout(base_url, token, Duration::from_secs(30))
    }

    #[cfg(test)]
    pub(crate) fn new_loopback_http_for_test(
        base_url: impl Into<String>,
        token: SecretString,
    ) -> Result<Self> {
        Self::with_timeout_and_loopback_http_for_test(base_url, token, Duration::from_secs(30))
    }

    #[cfg(test)]
    pub(crate) fn with_timeout_and_loopback_http_for_test(
        base_url: impl Into<String>,
        token: SecretString,
        timeout: Duration,
    ) -> Result<Self> {
        let base_url = Url::parse(base_url.into().trim()).context("invalid Snipe-IT URL")?;
        if base_url.scheme() != "http"
            || base_url.username() != ""
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || !base_url
                .host_str()
                .and_then(|host| host.parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback())
        {
            anyhow::bail!("test HTTP URL must target loopback without credentials or query")
        }
        Ok(Self {
            client: Client::builder()
                .timeout(timeout)
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            base_url,
            token,
        })
    }

    fn with_timeout(
        base_url: impl Into<String>,
        token: SecretString,
        timeout: Duration,
    ) -> Result<Self> {
        let base_url_text = base_url.into();
        validate_snipeit_url(&base_url_text)
            .map_err(|_| anyhow::anyhow!("Snipe-IT URL must use HTTPS"))?;
        let base_url = Url::parse(base_url_text.trim()).context("invalid Snipe-IT URL")?;
        if base_url.scheme() != "https"
            || base_url.username() != ""
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || base_url.host().is_none()
        {
            anyhow::bail!("Snipe-IT URL must be a valid HTTPS endpoint")
        }
        let client = Self::build_https_client(base_url.clone(), timeout, None)?;
        Ok(Self {
            client,
            base_url,
            token,
        })
    }

    /// Test-only construction sharing the production builder and HTTPS
    /// validation, adding `ca_pem` as the sole request-level trust root via
    /// the native-tls backend so hostname/CA verification stays on the
    /// production path.
    ///
    /// # Errors
    /// Returns the same errors as production when the URL or builder is
    /// invalid; never relaxes validation.
    #[cfg(test)]
    pub(crate) fn with_timeout_custom_trust(
        base_url: impl Into<String>,
        token: SecretString,
        timeout: Duration,
        ca_pem: &str,
    ) -> Result<Self> {
        let base_url_text = base_url.into();
        validate_snipeit_url(&base_url_text)
            .map_err(|_| anyhow::anyhow!("Snipe-IT URL must use HTTPS"))?;
        let base_url = Url::parse(base_url_text.trim()).context("invalid Snipe-IT URL")?;
        if base_url.scheme() != "https"
            || base_url.username() != ""
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || base_url.host().is_none()
        {
            anyhow::bail!("Snipe-IT URL must be a valid HTTPS endpoint")
        }
        let client = Self::build_https_client(base_url.clone(), timeout, Some(ca_pem))?;
        Ok(Self {
            client,
            base_url,
            token,
        })
    }

    fn build_https_client(
        _base_url: Url,
        timeout: Duration,
        additional_ca_pem: Option<&str>,
    ) -> Result<Client> {
        let mut builder = Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .use_native_tls();
        if let Some(ca_pem) = additional_ca_pem {
            let certificate = reqwest::Certificate::from_pem(ca_pem.as_bytes())?;
            builder = builder.add_root_certificate(certificate);
        }
        Ok(builder.build()?)
    }

    /// Find an asset by exact serial.
    ///
    /// # Errors
    /// Returns [`SnipeItError`] for network, HTTP, or response-classification failures.
    pub async fn find_asset_by_serial(&self, serial: &str) -> Result<Asset, SnipeItError> {
        validate_serial(serial)?;
        let mut url = self.endpoint_url(&["api", "v1", "hardware", "byserial"])?;
        url.path_segments_mut()
            .map_err(|()| safe_invalid("base URL cannot contain path segments"))?
            .push(serial);
        let response = self.send(reqwest::Method::GET, url).await?;
        decode_response(response, parse_asset_by_serial).await
    }

    /// Get one asset by numeric ID.
    ///
    /// # Errors
    /// Returns [`SnipeItError`] for network, HTTP, or response-classification failures.
    pub async fn get_asset(&self, asset_id: u64) -> Result<Asset, SnipeItError> {
        let url = self.endpoint_url(&["api", "v1", "hardware", &asset_id.to_string()])?;
        let response = self.send(reqwest::Method::GET, url).await?;
        decode_response(response, parse_asset_by_serial).await
    }

    /// Patch an existing asset.
    ///
    /// # Errors
    /// Returns [`SnipeItError`] for network, HTTP, or response-classification failures.
    pub async fn patch_asset(
        &self,
        asset_id: u64,
        request: &AssetPatchRequest,
    ) -> Result<Asset, SnipeItError> {
        let url = self.endpoint_url(&["api", "v1", "hardware", &asset_id.to_string()])?;
        let response = self
            .request(reqwest::Method::PATCH, url)
            .json(request)
            .send()
            .await
            .map_err(network)?;
        decode_response(response, parse_asset_patch).await
    }

    /// Check out a monitor asset to a computer asset.
    ///
    /// # Errors
    /// Returns [`SnipeItError`] for network, HTTP, or response-classification failures.
    pub async fn checkout_asset(
        &self,
        source_id: u64,
        request: &CheckoutRequest,
    ) -> Result<(), SnipeItError> {
        let url =
            self.endpoint_url(&["api", "v1", "hardware", &source_id.to_string(), "checkout"])?;
        let response = self
            .request(reqwest::Method::POST, url)
            .json(request)
            .send()
            .await
            .map_err(network)?;
        decode_response(response, parse_checkout_response).await
    }

    /// Check in a monitor asset.
    ///
    /// # Errors
    /// Returns [`SnipeItError`] for network, HTTP, or response-classification failures.
    pub async fn checkin_asset(
        &self,
        source_id: u64,
        request: &CheckinRequest,
    ) -> Result<(), SnipeItError> {
        let url =
            self.endpoint_url(&["api", "v1", "hardware", &source_id.to_string(), "checkin"])?;
        let response = self
            .request(reqwest::Method::POST, url)
            .json(request)
            .send()
            .await
            .map_err(network)?;
        decode_response(response, parse_checkin_response).await
    }

    /// List manufacturers matching a name.
    ///
    /// # Errors
    /// Returns [`SnipeItError`] for network, HTTP, or response-classification failures.
    pub async fn find_manufacturers(&self, name: &str) -> Result<Vec<Manufacturer>, SnipeItError> {
        self.paginated("api/v1/manufacturers", name).await
    }

    /// List categories matching a name.
    ///
    /// # Errors
    /// Returns [`SnipeItError`] for network, HTTP, or response-classification failures.
    pub async fn find_categories(&self, name: &str) -> Result<Vec<Category>, SnipeItError> {
        self.paginated("api/v1/categories", name).await
    }

    /// List models matching a name.
    ///
    /// # Errors
    /// Returns [`SnipeItError`] for network, HTTP, or response-classification failures.
    pub async fn find_models(&self, name: &str) -> Result<Vec<AssetModel>, SnipeItError> {
        self.paginated("api/v1/models", name).await
    }

    async fn paginated<T: DeserializeOwned>(
        &self,
        endpoint: &str,
        search: &str,
    ) -> Result<Vec<T>, SnipeItError> {
        #[derive(serde::Deserialize)]
        struct Rows<T> {
            rows: Vec<T>,
        }
        let endpoint = endpoint.split('/').collect::<Vec<_>>();
        let started = Instant::now();
        let mut values = Vec::new();
        for request_index in 0..MAX_PAGE_REQUESTS {
            if started.elapsed() >= PAGINATION_DEADLINE {
                return Err(safe_invalid("pagination deadline exceeded"));
            }
            let mut url = self.endpoint_url(&endpoint)?;
            url.query_pairs_mut()
                .append_pair("search", search)
                .append_pair("limit", &PAGE_SIZE.to_string())
                .append_pair("offset", &(request_index * PAGE_SIZE).to_string());
            let response = tokio::time::timeout_at(
                tokio::time::Instant::from_std(started + PAGINATION_DEADLINE),
                self.send(reqwest::Method::GET, url),
            )
            .await
            .map_err(|_| safe_invalid("pagination deadline exceeded"))??;
            let (status, retry, body) = read_response(response).await?;
            if !StatusCode::from_u16(status).is_ok_and(|status| status.is_success()) {
                return Err(classify_status(status, retry));
            }
            let page: Rows<T> = serde_json::from_slice(&body)
                .map_err(|_| safe_invalid("response body is not valid JSON"))?;
            let count = page.rows.len();
            if count > PAGE_SIZE {
                return Err(safe_invalid("pagination page exceeds requested limit"));
            }
            if values.len().saturating_add(count) > MAX_TOTAL_ROWS {
                return Err(safe_invalid("pagination row limit exceeded"));
            }
            values.extend(page.rows);
            if count < PAGE_SIZE {
                return Ok(values);
            }
            if request_index + 1 == MAX_PAGE_REQUESTS {
                return Err(safe_invalid("pagination request limit exceeded"));
            }
        }
        Err(safe_invalid("pagination request limit exceeded"))
    }

    fn endpoint_url(&self, segments: &[&str]) -> Result<Url, SnipeItError> {
        let mut url = self.base_url.clone();
        url.set_query(None);
        url.set_fragment(None);
        let mut path = url
            .path_segments_mut()
            .map_err(|()| safe_invalid("base URL cannot contain path segments"))?;
        path.pop_if_empty();
        for segment in segments {
            path.push(segment);
        }
        drop(path);
        Ok(url)
    }

    async fn send(&self, method: reqwest::Method, url: Url) -> Result<Response, SnipeItError> {
        self.request(method, url).send().await.map_err(network)
    }

    fn request(&self, method: reqwest::Method, url: Url) -> reqwest::RequestBuilder {
        self.client
            .request(method, url)
            .bearer_auth(self.token.expose_secret())
            .header("Accept", "application/json")
    }

    /// Test-only bounded probe: performs a GET against `path` and reports
    /// whether the transport completed, exercising real TLS/handshake paths
    /// through the production client construction.
    ///
    /// # Errors
    /// Returns the transport error text for classification in tests.
    #[cfg(test)]
    pub(crate) async fn request_json_for_test(&self, path: &str) -> Result<()> {
        let url = self
            .endpoint_url(&[path])
            .map_err(|error| anyhow::anyhow!("test probe URL construction failed: {error}"))?;
        let response = self
            .send(reqwest::Method::GET, url)
            .await
            .map_err(|error| anyhow::anyhow!("test probe transport error: {error}"))?;
        let (_status, _retry, _body) = read_response(response)
            .await
            .map_err(|error| anyhow::anyhow!("test probe response error: {error}"))?;
        Ok(())
    }
}

async fn decode_response<T>(
    response: Response,
    parser: fn(u16, &str, Option<u64>) -> Result<T, SnipeItError>,
) -> Result<T, SnipeItError> {
    let (status, retry, body) = read_response(response).await?;
    let body =
        std::str::from_utf8(&body).map_err(|_| safe_invalid("response body is not valid UTF-8"))?;
    parser(status, body, retry)
}

async fn read_response(
    mut response: Response,
) -> Result<(u16, Option<u64>, Vec<u8>), SnipeItError> {
    let status = response.status();
    let retry = retry_after(&response);
    let limit = if status.is_success() {
        MAX_SUCCESS_BODY_BYTES
    } else {
        MAX_ERROR_BODY_BYTES
    };
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(body_limit_error(status.as_u16(), retry));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(network)? {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(body_limit_error(status.as_u16(), retry));
        }
        body.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        return Err(classify_status(status.as_u16(), retry));
    }
    Ok((status.as_u16(), retry, body))
}

fn classify_status(status: u16, retry: Option<u64>) -> SnipeItError {
    match status {
        401 => SnipeItError::AuthFailure,
        403 => SnipeItError::PermissionDenied,
        404 => SnipeItError::NotFound,
        429 => SnipeItError::RateLimited { retry_after: retry },
        500..=599 => SnipeItError::ServerError {
            status,
            message: String::from("upstream server rejected the request"),
        },
        400 | 409 | 422 => SnipeItError::Validation {
            message: String::from("upstream rejected the request"),
        },
        _ => safe_invalid("unexpected HTTP status"),
    }
}

fn body_limit_error(status: u16, retry: Option<u64>) -> SnipeItError {
    if (200..=299).contains(&status) {
        safe_invalid("response body exceeds limit")
    } else {
        classify_status(status, retry)
    }
}

fn safe_invalid(message: &str) -> SnipeItError {
    SnipeItError::InvalidResponse {
        message: String::from(message),
    }
}

fn validate_serial(serial: &str) -> Result<(), SnipeItError> {
    if matches!(serial, "." | "..") || serial.chars().any(char::is_control) {
        return Err(SnipeItError::Validation {
            message: String::from("serial is not a safe URL segment"),
        });
    }
    Ok(())
}

fn retry_after(response: &Response) -> Option<u64> {
    response
        .headers()
        .get("retry-after")?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "reqwest map_err supplies an owned error"
)]
fn network(error: reqwest::Error) -> SnipeItError {
    let kind = if error.is_timeout() {
        spotter_core::snipeit::NetworkErrorKind::Timeout
    } else if error.is_connect() {
        spotter_core::snipeit::NetworkErrorKind::Connect
    } else {
        spotter_core::snipeit::NetworkErrorKind::Other
    };
    SnipeItError::NetworkError { kind }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path, query_param},
    };

    #[test]
    fn production_constructors_reject_http_before_client_creation() {
        let token = SecretString::from(String::from("token"));
        let Err(error) = SnipeItClient::new("http://127.0.0.1:1", token.clone()) else {
            panic!("production constructor must reject HTTP");
        };
        assert!(error.to_string().contains("HTTPS"));
        let Err(error) =
            SnipeItClient::with_timeout("http://127.0.0.1:1", token, Duration::from_millis(1))
        else {
            panic!("custom-timeout constructor must reject HTTP");
        };
        assert!(error.to_string().contains("HTTPS"));
    }

    #[tokio::test]
    async fn tls_fixture_self_test() -> anyhow::Result<()> {
        let server = crate::tls_test_fixture::TlsLoopbackServer::start().await?;
        assert_eq!(server.connection_count(), 0);
        let base = server.base_url.clone();
        let ca = server.ca_pem.clone();
        let client = crate::tls_test_fixture::client_trusting_ca(
            format!("{base}/ok"),
            SecretString::from(String::from("token")),
            &ca,
            Duration::from_secs(5),
        )?;
        crate::tls_test_fixture::request_bounded(&client, "/ok", Duration::from_secs(5))
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        assert_eq!(server.connection_count(), 1);
        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn https_client_accepts_trusted_localhost() -> anyhow::Result<()> {
        let server = crate::tls_test_fixture::TlsLoopbackServer::start().await?;
        let client = crate::tls_test_fixture::client_trusting_ca(
            format!("{}/ok", server.base_url),
            SecretString::from(String::from("token")),
            &server.ca_pem,
            Duration::from_secs(5),
        )?;
        // The fixture answers /ok with 200 JSON through the full production
        // TLS construction: native-tls handshake, hostname verification, and
        // bounded response reading.
        crate::tls_test_fixture::request_bounded(&client, "/ok", Duration::from_secs(5))
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        assert_eq!(server.connection_count(), 1);
        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn https_client_rejects_untrusted_ca() -> anyhow::Result<()> {
        let server = crate::tls_test_fixture::TlsLoopbackServer::start().await?;
        let client = crate::tls_test_fixture::client_trusting_ca(
            format!("{}/ok", server.base_url),
            SecretString::from(String::from("token")),
            &crate::tls_test_fixture::TlsLoopbackServer::start()
                .await?
                .ca_pem,
            Duration::from_secs(5),
        )?;
        let outcome =
            crate::tls_test_fixture::request_bounded(&client, "/ok", Duration::from_secs(5)).await;
        assert!(outcome.is_err(), "untrusted CA must fail the handshake");
        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn https_client_rejects_hostname_mismatch() -> anyhow::Result<()> {
        // The fixture leaf carries only the DNS SAN "localhost"; connecting
        // by IP address exercises the hostname-verification failure path on
        // the production native-tls backend.
        let server = crate::tls_test_fixture::TlsLoopbackServer::start().await?;
        let mismatched = server
            .base_url
            .replace("https://localhost:", "https://127.0.0.1:");
        let client = crate::tls_test_fixture::client_trusting_ca(
            format!("{mismatched}/ok"),
            SecretString::from(String::from("token")),
            &server.ca_pem,
            Duration::from_secs(5),
        )?;
        let outcome =
            crate::tls_test_fixture::request_bounded(&client, "/ok", Duration::from_secs(5)).await;
        assert!(
            outcome.is_err(),
            "IP-address host against DNS-only leaf must fail hostname verification"
        );
        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn https_redirect_and_body_bounds() -> anyhow::Result<()> {
        let server = crate::tls_test_fixture::TlsLoopbackServer::start().await?;
        let client = crate::tls_test_fixture::client_trusting_ca(
            format!("{}/redirect", server.base_url),
            SecretString::from(String::from("token")),
            &server.ca_pem,
            Duration::from_secs(5),
        )?;
        let outcome =
            crate::tls_test_fixture::request_bounded(&client, "/redirect", Duration::from_secs(5))
                .await;
        assert!(
            outcome.is_err(),
            "redirects must be refused by production policy"
        );
        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn lookup_and_error_classification() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/hardware/byserial/ABC"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"id":7,"serial":"ABC"})),
            )
            .mount(&server)
            .await;
        let client = SnipeItClient::new_loopback_http_for_test(
            server.uri(),
            SecretString::from(String::from("token")),
        )?;
        assert_eq!(client.find_asset_by_serial("ABC").await?.id, 7);
        Ok(())
    }

    #[tokio::test]
    async fn classifies_not_found_auth_and_server_responses() -> Result<()> {
        for (status, body, expected) in [
            (
                200,
                serde_json::json!({"message":"Asset not found"}),
                SnipeItError::NotFound,
            ),
            (
                401,
                serde_json::json!({"message":"unauthorized"}),
                SnipeItError::AuthFailure,
            ),
            (
                500,
                serde_json::json!({"message":"failed"}),
                SnipeItError::ServerError {
                    status: 500,
                    message: String::from("upstream server rejected the request"),
                },
            ),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/v1/hardware/byserial/ABC"))
                .respond_with(ResponseTemplate::new(status).set_body_json(body))
                .mount(&server)
                .await;
            let client = SnipeItClient::new_loopback_http_for_test(
                server.uri(),
                SecretString::from(String::from("token")),
            )?;
            assert_eq!(client.find_asset_by_serial("ABC").await, Err(expected));
        }
        Ok(())
    }

    #[tokio::test]
    async fn timeout_is_reported_as_network_error() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/hardware/byserial/SLOW"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(2))
                    .set_body_json(serde_json::json!({"id":7,"serial":"SLOW"})),
            )
            .mount(&server)
            .await;
        let client = SnipeItClient::with_timeout_and_loopback_http_for_test(
            server.uri(),
            SecretString::from(String::from("token")),
            Duration::from_millis(100),
        )?;
        assert!(matches!(
            client.find_asset_by_serial("SLOW").await,
            Err(SnipeItError::NetworkError { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn oversized_rate_limit_preserves_retry_after() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/hardware/byserial/OVERSIZED"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "17")
                    .set_body_string("x".repeat(MAX_ERROR_BODY_BYTES + 1)),
            )
            .mount(&server)
            .await;
        let client = SnipeItClient::new_loopback_http_for_test(
            server.uri(),
            SecretString::from(String::from("token")),
        )?;
        assert_eq!(
            client.find_asset_by_serial("OVERSIZED").await,
            Err(SnipeItError::RateLimited {
                retry_after: Some(17)
            })
        );
        Ok(())
    }

    #[tokio::test]
    async fn rate_limit_preserves_retry_after() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/hardware/byserial/ABC"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "9")
                    .set_body_json(serde_json::json!({"message":"slow down"})),
            )
            .mount(&server)
            .await;
        let client = SnipeItClient::new_loopback_http_for_test(
            server.uri(),
            SecretString::from(String::from("token")),
        )?;
        assert_eq!(
            client.find_asset_by_serial("ABC").await,
            Err(SnipeItError::RateLimited {
                retry_after: Some(9)
            })
        );
        Ok(())
    }

    #[tokio::test]
    async fn byserial_collection_response_with_multiple_rows_is_ambiguous() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/hardware/byserial/SER1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"total":2,"rows":[{"id":11,"serial":"SER1"},{"id":12,"serial":"SER1"}]}),
                ),
            )
            .mount(&server)
            .await;
        let client = SnipeItClient::new_loopback_http_for_test(
            server.uri(),
            SecretString::from(String::from("t")),
        )?;
        assert_eq!(
            client.find_asset_by_serial("SER1").await,
            Err(SnipeItError::AmbiguousResponse)
        );
        Ok(())
    }

    #[tokio::test]
    async fn patch_asset_returns_updated_asset() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/hardware/42"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"payload":{"id":42,"serial":"NEW","name":"PC"}}),
                ),
            )
            .mount(&server)
            .await;
        let client = SnipeItClient::new_loopback_http_for_test(
            server.uri(),
            SecretString::from(String::from("t")),
        )?;
        let request = AssetPatchRequest {
            serial: Some(String::from("NEW")),
            ..Default::default()
        };
        let asset = client.patch_asset(42, &request).await?;
        assert_eq!(asset.id, 42);
        assert_eq!(asset.serial.as_deref(), Some("NEW"));
        Ok(())
    }

    #[tokio::test]
    async fn patch_asset_propagates_auth_and_rate_limit_errors() -> Result<()> {
        let request = AssetPatchRequest {
            serial: Some(String::from("X")),
            ..Default::default()
        };
        for (status, header, expected) in [
            (401, None, SnipeItError::AuthFailure),
            (
                429,
                Some(("Retry-After", "5")),
                SnipeItError::RateLimited {
                    retry_after: Some(5),
                },
            ),
            (
                500,
                None,
                SnipeItError::ServerError {
                    status: 500,
                    message: String::from("upstream server rejected the request"),
                },
            ),
        ] {
            let server = MockServer::start().await;
            let mut template = ResponseTemplate::new(status)
                .set_body_json(serde_json::json!({"message":"internal"}));
            if let Some((k, v)) = header {
                template = template.insert_header(k, v);
            }
            Mock::given(method("PATCH"))
                .and(path("/api/v1/hardware/7"))
                .respond_with(template)
                .mount(&server)
                .await;
            let client = SnipeItClient::new_loopback_http_for_test(
                server.uri(),
                SecretString::from(String::from("t")),
            )?;
            assert_eq!(client.patch_asset(7, &request).await, Err(expected));
        }
        Ok(())
    }

    #[tokio::test]
    async fn checkout_asset_succeeds_on_rows_response() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/hardware/200/checkout"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"rows":[{"id":100}]})),
            )
            .mount(&server)
            .await;
        let client = SnipeItClient::new_loopback_http_for_test(
            server.uri(),
            SecretString::from(String::from("t")),
        )?;
        let request = CheckoutRequest {
            checkout_to_type: String::from("asset"),
            assigned_asset: 100,
            status_id: 3,
        };
        client.checkout_asset(200, &request).await?;
        Ok(())
    }

    #[tokio::test]
    async fn checkout_asset_propagates_errors() -> Result<()> {
        for (status, header, expected) in [
            (401, None, SnipeItError::AuthFailure),
            (
                429,
                Some(("Retry-After", "12")),
                SnipeItError::RateLimited {
                    retry_after: Some(12),
                },
            ),
        ] {
            let server = MockServer::start().await;
            let mut template =
                ResponseTemplate::new(status).set_body_json(serde_json::json!({"message":"err"}));
            if let Some((k, v)) = header {
                template = template.insert_header(k, v);
            }
            Mock::given(method("POST"))
                .and(path("/api/v1/hardware/5/checkout"))
                .respond_with(template)
                .mount(&server)
                .await;
            let client = SnipeItClient::new_loopback_http_for_test(
                server.uri(),
                SecretString::from(String::from("t")),
            )?;
            let request = CheckoutRequest {
                checkout_to_type: String::from("asset"),
                assigned_asset: 1,
                status_id: 1,
            };
            assert_eq!(client.checkout_asset(5, &request).await, Err(expected));
        }
        Ok(())
    }

    #[tokio::test]
    async fn checkin_asset_succeeds_on_status_success_response() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/hardware/300/checkin"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"status":"success","payload":{"id":300}})),
            )
            .mount(&server)
            .await;
        let client = SnipeItClient::new_loopback_http_for_test(
            server.uri(),
            SecretString::from(String::from("t")),
        )?;
        let request = CheckinRequest { status_id: 4 };
        client.checkin_asset(300, &request).await?;
        Ok(())
    }

    #[tokio::test]
    async fn checkin_asset_succeeds_on_rows_response() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/hardware/301/checkin"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"rows":[{"id":301}]})),
            )
            .mount(&server)
            .await;
        let client = SnipeItClient::new_loopback_http_for_test(
            server.uri(),
            SecretString::from(String::from("t")),
        )?;
        let request = CheckinRequest { status_id: 4 };
        client.checkin_asset(301, &request).await?;
        Ok(())
    }

    #[tokio::test]
    async fn checkin_asset_propagates_errors() -> Result<()> {
        for (status, header, expected) in [
            (401, None, SnipeItError::AuthFailure),
            (403, None, SnipeItError::PermissionDenied),
            (
                429,
                Some(("Retry-After", "30")),
                SnipeItError::RateLimited {
                    retry_after: Some(30),
                },
            ),
            (
                500,
                None,
                SnipeItError::ServerError {
                    status: 500,
                    message: String::from("upstream server rejected the request"),
                },
            ),
        ] {
            let server = MockServer::start().await;
            let mut template =
                ResponseTemplate::new(status).set_body_json(serde_json::json!({"message":"err"}));
            if let Some((k, v)) = header {
                template = template.insert_header(k, v);
            }
            Mock::given(method("POST"))
                .and(path("/api/v1/hardware/9/checkin"))
                .respond_with(template)
                .mount(&server)
                .await;
            let client = SnipeItClient::new_loopback_http_for_test(
                server.uri(),
                SecretString::from(String::from("t")),
            )?;
            let request = CheckinRequest { status_id: 1 };
            assert_eq!(client.checkin_asset(9, &request).await, Err(expected));
        }
        Ok(())
    }

    #[tokio::test]
    async fn find_manufacturers_returns_all_rows() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/manufacturers"))
            .and(query_param("search", "Dell"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"rows":[{"id":1,"name":"Dell Inc"},{"id":2,"name":"Dell EMC"}]}),
            ))
            .mount(&server)
            .await;
        let client = SnipeItClient::new_loopback_http_for_test(
            server.uri(),
            SecretString::from(String::from("t")),
        )?;
        let results = client.find_manufacturers("Dell").await?;
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].id, 1);
        Ok(())
    }

    #[tokio::test]
    async fn find_models_paginates_across_pages() -> Result<()> {
        let server = MockServer::start().await;
        // First page: exactly 100 rows
        let rows_page1: Vec<_> = (1_u64..=100)
            .map(|id| serde_json::json!({"id": id, "name": format!("Model{id}")}))
            .collect();
        Mock::given(method("GET"))
            .and(path("/api/v1/models"))
            .and(query_param("search", "ThinkPad"))
            .and(query_param("offset", "0"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"rows": rows_page1})),
            )
            .mount(&server)
            .await;
        // Second page: 2 rows (stops pagination)
        Mock::given(method("GET"))
            .and(path("/api/v1/models"))
            .and(query_param("search", "ThinkPad"))
            .and(query_param("offset", "100"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"rows":[{"id":101,"name":"ThinkPad T14"},{"id":102,"name":"ThinkPad T15"}]}),
                ),
            )
            .mount(&server)
            .await;
        let client = SnipeItClient::new_loopback_http_for_test(
            server.uri(),
            SecretString::from(String::from("t")),
        )?;
        let results = client.find_models("ThinkPad").await?;
        assert_eq!(results.len(), 102);
        assert_eq!(results[100].id, 101);
        Ok(())
    }

    #[tokio::test]
    async fn taxonomy_lookup_propagates_auth_error() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/categories"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({"message":"unauthorized"})),
            )
            .mount(&server)
            .await;
        let client = SnipeItClient::new_loopback_http_for_test(
            server.uri(),
            SecretString::from(String::from("t")),
        )?;
        assert_eq!(
            client.find_categories("Monitor").await,
            Err(SnipeItError::AuthFailure)
        );
        Ok(())
    }

    #[tokio::test]
    async fn mutations_send_bearer_auth_and_expected_json_bodies() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/hardware/42"))
            .and(header("authorization", "Bearer token"))
            .and(body_json(serde_json::json!({"serial":"NEW"})))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"payload":{"id":42,"serial":"NEW"}})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/hardware/42/checkout"))
            .and(header("authorization", "Bearer token"))
            .and(body_json(serde_json::json!({
                "checkout_to_type": "asset",
                "assigned_asset": 100,
                "status_id": 3
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"rows":[{"id":42}]})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/hardware/42/checkin"))
            .and(header("authorization", "Bearer token"))
            .and(body_json(serde_json::json!({"status_id":4})))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"status":"success","payload":{"id":42}})),
            )
            .mount(&server)
            .await;

        let client = SnipeItClient::new_loopback_http_for_test(
            server.uri(),
            SecretString::from(String::from("token")),
        )?;
        let patch = AssetPatchRequest {
            serial: Some(String::from("NEW")),
            ..Default::default()
        };
        client.patch_asset(42, &patch).await?;
        client
            .checkout_asset(
                42,
                &CheckoutRequest {
                    checkout_to_type: String::from("asset"),
                    assigned_asset: 100,
                    status_id: 3,
                },
            )
            .await?;
        client
            .checkin_asset(42, &CheckinRequest { status_id: 4 })
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_body_caps_all_routes() -> Result<()> {
        let oversized = "x".repeat(1_048_576 + 1);
        for endpoint in [
            "/api/v1/hardware/byserial/CAP",
            "/api/v1/hardware/7",
            "/api/v1/manufacturers",
            "/api/v1/categories",
            "/api/v1/models",
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path(endpoint))
                .respond_with(ResponseTemplate::new(200).set_body_string(oversized.clone()))
                .mount(&server)
                .await;
            let client = SnipeItClient::new_loopback_http_for_test(
                server.uri(),
                SecretString::from(String::from("t")),
            )?;
            let result = match endpoint {
                "/api/v1/hardware/byserial/CAP" => {
                    client.find_asset_by_serial("CAP").await.map(|_| ())
                }
                "/api/v1/hardware/7" => client.get_asset(7).await.map(|_| ()),
                "/api/v1/manufacturers" => client.find_manufacturers("x").await.map(|_| ()),
                "/api/v1/categories" => client.find_categories("x").await.map(|_| ()),
                _ => client.find_models("x").await.map(|_| ()),
            };
            assert_eq!(
                result,
                Err(SnipeItError::InvalidResponse {
                    message: String::from("response body exceeds limit")
                })
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn chunked_response_enforces_cumulative_cap() -> Result<()> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).await?;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await?;
            let chunk = vec![b'x'; 65_536];
            for _ in 0..=16 {
                stream.write_all(b"10000\r\n").await?;
                stream.write_all(&chunk).await?;
                stream.write_all(b"\r\n").await?;
            }
            let _ = stream.write_all(b"0\r\n\r\n").await;
            Ok::<_, std::io::Error>(())
        });
        let client = SnipeItClient::new_loopback_http_for_test(
            format!("http://{address}"),
            SecretString::from(String::from("t")),
        )?;
        assert_eq!(
            client.get_asset(7).await,
            Err(SnipeItError::InvalidResponse {
                message: String::from("response body exceeds limit")
            })
        );
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn pagination_limits_and_total_deadline() -> Result<()> {
        let server = MockServer::start().await;
        let rows: Vec<_> = (0..101)
            .map(|id| serde_json::json!({"id":id + 1,"name":"x"}))
            .collect();
        Mock::given(method("GET"))
            .and(path("/api/v1/models"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"rows":rows})),
            )
            .mount(&server)
            .await;
        let client = SnipeItClient::new_loopback_http_for_test(
            server.uri(),
            SecretString::from(String::from("t")),
        )?;
        assert_eq!(
            client.find_models("x").await,
            Err(SnipeItError::InvalidResponse {
                message: String::from("pagination page exceeds requested limit")
            })
        );
        Ok(())
    }

    #[tokio::test]
    async fn serial_url_segment_contract() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"id":7,"serial":"value"})),
            )
            .mount(&server)
            .await;
        let client = SnipeItClient::new_loopback_http_for_test(
            format!("{}/prefix/", server.uri()),
            SecretString::from(String::from("t")),
        )?;
        for serial in ["a/b?c#d", "50%", "日本語"] {
            assert_eq!(client.find_asset_by_serial(serial).await?.id, 7);
        }
        let requests = server
            .received_requests()
            .await
            .ok_or_else(|| anyhow::anyhow!("request recording is disabled"))?;
        let paths = requests
            .iter()
            .map(|request| request.url.path().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(paths[0], "/prefix/api/v1/hardware/byserial/a%2Fb%3Fc%23d");
        assert_eq!(paths[1], "/prefix/api/v1/hardware/byserial/50%25");
        assert!(paths[2].starts_with("/prefix/api/v1/hardware/byserial/%"));
        assert!(requests.iter().all(|request| request.url.query().is_none()));
        let client = SnipeItClient::new_loopback_http_for_test(
            format!("{}/prefix/", server.uri()),
            SecretString::from(String::from("t")),
        )?;
        for serial in [".", "..", "bad\nvalue"] {
            assert!(matches!(
                client.find_asset_by_serial(serial).await,
                Err(SnipeItError::Validation { .. })
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn redirects_never_forward_requests() -> Result<()> {
        let destination = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id":7})))
            .mount(&destination)
            .await;
        let source = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/stolen", destination.uri()).as_str())
                    .set_body_string("redirect-secret"),
            )
            .mount(&source)
            .await;
        let client = SnipeItClient::new_loopback_http_for_test(
            source.uri(),
            SecretString::from(String::from("t")),
        )?;
        assert!(matches!(
            client.get_asset(7).await,
            Err(SnipeItError::InvalidResponse { .. })
        ));
        assert!(
            destination
                .received_requests()
                .await
                .is_some_and(|requests| requests.is_empty())
        );
        Ok(())
    }

    #[tokio::test]
    async fn mutation_timeouts_are_network_errors() -> Result<()> {
        for (endpoint, method_name) in [
            ("/api/v1/hardware/42", "PATCH"),
            ("/api/v1/hardware/42/checkout", "POST"),
            ("/api/v1/hardware/42/checkin", "POST"),
        ] {
            let server = MockServer::start().await;
            Mock::given(method(method_name))
                .and(path(endpoint))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_delay(Duration::from_secs(2))
                        .set_body_json(serde_json::json!({"status":"success","payload":{"id":42}})),
                )
                .mount(&server)
                .await;
            let client = SnipeItClient::with_timeout_and_loopback_http_for_test(
                server.uri(),
                SecretString::from(String::from("token")),
                Duration::from_millis(100),
            )?;
            let result = match method_name {
                "PATCH" => client
                    .patch_asset(
                        42,
                        &AssetPatchRequest {
                            serial: Some(String::from("X")),
                            ..Default::default()
                        },
                    )
                    .await
                    .map(|_| ()),
                _ if endpoint.ends_with("checkout") => {
                    client
                        .checkout_asset(
                            42,
                            &CheckoutRequest {
                                checkout_to_type: String::from("asset"),
                                assigned_asset: 100,
                                status_id: 3,
                            },
                        )
                        .await
                }
                _ => {
                    client
                        .checkin_asset(42, &CheckinRequest { status_id: 4 })
                        .await
                }
            };
            assert!(matches!(result, Err(SnipeItError::NetworkError { .. })));
        }
        Ok(())
    }
}
