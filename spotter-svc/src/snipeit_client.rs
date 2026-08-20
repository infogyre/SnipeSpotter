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
        matchers::{body_json, header, method, path, query_param},
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

    #[tokio::test]
    async fn byserial_collection_response_returns_first_row() -> Result<()> {
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
        let client = SnipeItClient::new(server.uri(), SecretString::from(String::from("t")))?;
        assert_eq!(client.find_asset_by_serial("SER1").await?.id, 11);
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
        let client = SnipeItClient::new(server.uri(), SecretString::from(String::from("t")))?;
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
                    message: String::from("internal"),
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
            let client = SnipeItClient::new(server.uri(), SecretString::from(String::from("t")))?;
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
        let client = SnipeItClient::new(server.uri(), SecretString::from(String::from("t")))?;
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
            let client = SnipeItClient::new(server.uri(), SecretString::from(String::from("t")))?;
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
        let client = SnipeItClient::new(server.uri(), SecretString::from(String::from("t")))?;
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
        let client = SnipeItClient::new(server.uri(), SecretString::from(String::from("t")))?;
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
                    message: String::from("err"),
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
            let client = SnipeItClient::new(server.uri(), SecretString::from(String::from("t")))?;
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
        let client = SnipeItClient::new(server.uri(), SecretString::from(String::from("t")))?;
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
        let client = SnipeItClient::new(server.uri(), SecretString::from(String::from("t")))?;
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
        let client = SnipeItClient::new(server.uri(), SecretString::from(String::from("t")))?;
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

        let client = SnipeItClient::new(server.uri(), SecretString::from(String::from("token")))?;
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
            let client = SnipeItClient::with_timeout(
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
