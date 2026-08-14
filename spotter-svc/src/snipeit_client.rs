// pattern: Imperative Shell

//! Authenticated Snipe-IT HTTP transport.

use std::time::Duration;

use anyhow::Result;
use reqwest::{Client, Response, StatusCode};
use secrecy::{ExposeSecret as _, SecretString};
use serde::de::DeserializeOwned;
use spotter_core::snipeit::{
    Asset, AssetModel, AssetPatchRequest, Category, CheckinRequest, CheckoutRequest, Manufacturer,
    SnipeItError, parse_asset_by_serial, parse_asset_patch, parse_checkin_response,
    parse_checkout_response,
};

pub struct SnipeItClient {
    client: Client,
    base_url: String,
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

    fn with_timeout(
        base_url: impl Into<String>,
        token: SecretString,
        timeout: Duration,
    ) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
            anyhow::bail!("Snipe-IT URL must use HTTP or HTTPS")
        }
        Ok(Self {
            client: Client::builder().timeout(timeout).build()?,
            base_url,
            token,
        })
    }

    /// Find an asset by exact serial.
    ///
    /// # Errors
    /// Returns [`SnipeItError`] for network, HTTP, or response-classification failures.
    pub async fn find_asset_by_serial(&self, serial: &str) -> Result<Asset, SnipeItError> {
        let response = self
            .get(&format!("api/v1/hardware/byserial/{serial}"))
            .await?;
        let status = response.status().as_u16();
        let retry = retry_after(&response);
        let body = response.text().await.map_err(network)?;
        parse_asset_by_serial(status, &body, retry)
    }

    /// Get one asset by numeric ID.
    ///
    /// # Errors
    /// Returns [`SnipeItError`] for network, HTTP, or response-classification failures.
    pub async fn get_asset(&self, asset_id: u64) -> Result<Asset, SnipeItError> {
        let response = self.get(&format!("api/v1/hardware/{asset_id}")).await?;
        let status = response.status().as_u16();
        let retry = retry_after(&response);
        let body = response.text().await.map_err(network)?;
        parse_asset_by_serial(status, &body, retry)
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
        let response = self
            .request(
                reqwest::Method::PATCH,
                &format!("api/v1/hardware/{asset_id}"),
            )
            .json(request)
            .send()
            .await
            .map_err(network)?;
        let status = response.status().as_u16();
        let retry = retry_after(&response);
        let body = response.text().await.map_err(network)?;
        parse_asset_patch(status, &body, retry)
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
        let response = self
            .request(
                reqwest::Method::POST,
                &format!("api/v1/hardware/{source_id}/checkout"),
            )
            .json(request)
            .send()
            .await
            .map_err(network)?;
        classify_mutation(response, true).await
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
        let response = self
            .request(
                reqwest::Method::POST,
                &format!("api/v1/hardware/{source_id}/checkin"),
            )
            .json(request)
            .send()
            .await
            .map_err(network)?;
        classify_mutation(response, false).await
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
        let mut offset = 0_u64;
        let mut values = Vec::new();
        loop {
            let response = self
                .request(reqwest::Method::GET, endpoint)
                .query(&[
                    ("search", search),
                    ("limit", "100"),
                    ("offset", &offset.to_string()),
                ])
                .send()
                .await
                .map_err(network)?;
            let status = response.status();
            if !status.is_success() {
                return Err(classify_http_error(response).await);
            }
            let page: Rows<T> =
                response
                    .json()
                    .await
                    .map_err(|error| SnipeItError::InvalidResponse {
                        message: error.to_string(),
                    })?;
            let count = page.rows.len();
            values.extend(page.rows);
            if count < 100 {
                break;
            }
            offset += 100;
        }
        Ok(values)
    }

    async fn get(&self, endpoint: &str) -> Result<Response, SnipeItError> {
        self.request(reqwest::Method::GET, endpoint)
            .send()
            .await
            .map_err(network)
    }

    fn request(&self, method: reqwest::Method, endpoint: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}/{}", self.base_url, endpoint))
            .bearer_auth(self.token.expose_secret())
            .header("Accept", "application/json")
    }
}

async fn classify_mutation(response: Response, checkout: bool) -> Result<(), SnipeItError> {
    let status = response.status().as_u16();
    let retry = retry_after(&response);
    let body = response.text().await.map_err(network)?;
    if checkout {
        parse_checkout_response(status, &body, retry)
    } else {
        parse_checkin_response(status, &body, retry)
    }
}

async fn classify_http_error(response: Response) -> SnipeItError {
    let status = response.status();
    let retry = retry_after(&response);
    let body = response.text().await.unwrap_or_default();
    match status {
        StatusCode::UNAUTHORIZED => SnipeItError::AuthFailure,
        StatusCode::FORBIDDEN => SnipeItError::PermissionDenied,
        StatusCode::NOT_FOUND => SnipeItError::NotFound,
        StatusCode::TOO_MANY_REQUESTS => SnipeItError::RateLimited { retry_after: retry },
        status if status.is_server_error() => SnipeItError::ServerError {
            status: status.as_u16(),
            message: body,
        },
        _ => SnipeItError::Validation { message: body },
    }
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
    SnipeItError::NetworkError {
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

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
        let client = SnipeItClient::new(server.uri(), SecretString::from(String::from("token")))?;
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
                    message: String::from("failed"),
                },
            ),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/v1/hardware/byserial/ABC"))
                .respond_with(ResponseTemplate::new(status).set_body_json(body))
                .mount(&server)
                .await;
            let client =
                SnipeItClient::new(server.uri(), SecretString::from(String::from("token")))?;
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
        let client = SnipeItClient::with_timeout(
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
        let client = SnipeItClient::new(server.uri(), SecretString::from(String::from("token")))?;
        assert_eq!(
            client.find_asset_by_serial("ABC").await,
            Err(SnipeItError::RateLimited {
                retry_after: Some(9)
            })
        );
        Ok(())
    }
}
