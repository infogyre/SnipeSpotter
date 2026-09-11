//! Real TLS loopback fixture for production-construction HTTPS tests.
//!
//! Generates a short-lived CA and a localhost leaf at runtime with rcgen,
//! serves TLS through tokio-native-tls on an ephemeral loopback port, and
//! exposes helpers that share the production request/builder path. Trust is
//! never installed into any system store; everything is bounded to this test
//! process and cleaned up on drop.
// pattern: Mixed (unavoidable)
// Reason: TLS handshake, listener accept loop, and certificate generation are
// inherently side-effecting; the fixture exists only inside cfg(test) builds.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[cfg_attr(not(windows), expect(unused_imports))]
use anyhow::Context as _;
use native_tls::Identity;
use rcgen::{
    BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PKCS_RSA_SHA256, RsaKeySize,
};
use secrecy::SecretString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_native_tls::TlsAcceptor;

pub(crate) struct TlsLoopbackServer {
    pub(crate) base_url: String,
    pub(crate) ca_pem: String,
    requests: Arc<AtomicUsize>,
    shutdown: oneshot::Sender<()>,
    accept_loop: tokio::task::JoinHandle<()>,
}

impl TlsLoopbackServer {
    /// Start the TLS fixture on an ephemeral loopback port.
    ///
    /// # Errors
    /// Returns an error when certificate generation, listener binding, or
    /// acceptor construction fails.
    pub(crate) async fn start() -> anyhow::Result<Self> {
        // native-tls on Windows imports private keys through the legacy
        // CryptoAPI (PROV_RSA_FULL / PKCS_RSA_PRIVATE_KEY), which supports
        // RSA only; ECDSA keys fail schannel import. Generate RSA-2048 keys
        // via the rsa crate (dev-only) and hand them to rcgen as PKCS8 DER.
        let ca_key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)?;
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "SnipeSpotter Test CA");
        let ca_cert = ca_params.self_signed(&ca_key)?;
        let ca_issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)?;
        let mut leaf_params = CertificateParams::new(vec![String::from("localhost")])?;
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        leaf_params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_issuer)?;
        let ca_pem = ca_cert.pem();

        // Identity input format is backend-specific: Windows schannel parses
        // DER (CertCreateCertificateContext) and rejects PEM with "ASN1 bad
        // tag value met"; the DER key must be the PKCS#8 form — decode
        // rcgen's PKCS#8 PEM body to DER (serialize_der() emits SEC1 for
        // EC keys, which schallery rejects as "not a PKCS#8 key").
        #[cfg(windows)]
        let identity = {
            let pkcs8_pem = leaf_key.serialize_pem();
            let der_body = pkcs8_pem
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<String>();
            use base64::Engine as _;
            let pkcs8_der = base64::engine::general_purpose::STANDARD
                .decode(der_body.trim())
                .context("failed to decode fixture PKCS#8 key")?;
            Identity::from_pkcs8(&pkcs8_der, leaf_cert.der().as_ref())?
        };
        #[cfg(not(windows))]
        let identity = Identity::from_pkcs8(
            leaf_cert.pem().as_bytes(),
            leaf_key.serialize_pem().as_bytes(),
        )?;
        let acceptor = Arc::new(TlsAcceptor::from(
            native_tls::TlsAcceptor::builder(identity).build()?,
        ));
        let listener =
            match TcpListener::bind(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 0))).await {
                Ok(listener) => listener,
                Err(_) => TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?,
            };
        let port = listener.local_addr()?.port();
        let requests = Arc::new(AtomicUsize::new(0));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let connection_count = Arc::clone(&requests);

        let accept_loop = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let acceptor = Arc::clone(&acceptor);
                        let connections = Arc::clone(&connection_count);
                        tokio::spawn(async move {
                            connections.fetch_add(1, Ordering::SeqCst);
                            let Ok(mut tls) = acceptor.accept(stream).await else {
                                return;
                            };
                            let mut buffer = [0u8; 8192];
                            let read = tls.read(&mut buffer).await.unwrap_or(0);
                            let request = String::from_utf8_lossy(&buffer[..read]);
                            let (status_line, body) = if request.contains("/ok") {
                                ("HTTP/1.1 200 OK\r\n", "{}")
                            } else if request.contains("/redirect") {
                                (
                                    "HTTP/1.1 302 Found\r\nLocation: https://localhost/elsewhere\r\n",
                                    "{}",
                                )
                            } else {
                                ("HTTP/1.1 404 Not Found\r\n", "{}")
                            };
                            let response = format!(
                                "{status_line}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len(),
                            );
                            let _ = tls.write_all(response.as_bytes()).await;
                            let _ = tls.flush().await;
                        });
                    }
                    _ = &mut shutdown_rx => break,
                }
            }
        });

        Ok(Self {
            base_url: format!("https://localhost:{port}"),
            ca_pem,
            requests,
            shutdown: shutdown_tx,
            accept_loop,
        })
    }

    /// Number of accepted TLS connections so far.
    pub(crate) fn connection_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    /// Shut the listener down and await accept-loop termination.
    ///
    /// # Errors
    /// Returns an error when the accept-loop task panics.
    pub(crate) async fn shutdown(self) -> anyhow::Result<()> {
        drop(self.shutdown);
        self.accept_loop.await?;
        Ok(())
    }
}

/// Build a self-signed certificate for hostname-mismatch fixtures.
///
/// Retained for elevated Windows lifecycle probes that serve a name-mismatched
/// leaf deliberately; unused on Linux where the mismatch is exercised through
/// IP-vs-DNS SAN construction.
///
/// # Errors
/// Returns an error when key generation fails.
#[expect(dead_code, reason = "elevated Windows lifecycle probe helper")]
pub(crate) fn mismatched_localhost_identity() -> anyhow::Result<native_tls::Identity> {
    let leaf_key = KeyPair::generate()?;
    let params = CertificateParams::new(vec![String::from("other-host")])?;
    let cert = params.self_signed(&leaf_key)?;
    #[cfg(windows)]
    let identity = {
        let pkcs8_pem = leaf_key.serialize_pem();
        let der_body = pkcs8_pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        use base64::Engine as _;
        let pkcs8_der = base64::engine::general_purpose::STANDARD
            .decode(der_body.trim())
            .context("failed to decode fixture PKCS#8 key")?;
        Identity::from_pkcs8(&pkcs8_der, cert.der().as_ref())?
    };
    #[cfg(not(windows))]
    let identity =
        Identity::from_pkcs8(cert.pem().as_bytes(), leaf_key.serialize_pem().as_bytes())?;
    Ok(identity)
}

/// Shared assertion helper: connect with a client and expect success or
/// failure within the bounded timeout.
///
/// Requires `client_trusting_ca`-constructed clients so the CA is added at
/// the request level while sharing the production builder path.
///
/// # Errors
/// Returns the transport error text for classification in tests.
pub(crate) async fn request_bounded(
    client: &crate::snipeit_client::SnipeItClient,
    path: &str,
    timeout: Duration,
) -> Result<(), String> {
    let outcome = tokio::time::timeout(timeout, client.request_json_for_test(path)).await;
    match outcome {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err(String::from("request exceeded test timeout")),
    }
}

/// Build a production-validated HTTPS client whose request-level trust store
/// contains only the fixture CA. The builder path, redirect refusal, and URL
/// validation are identical to production; validation never softens.
///
/// # Errors
/// Returns an error when the client cannot be built or the URL is invalid.
pub(crate) fn client_trusting_ca(
    base_url: impl Into<String>,
    token: SecretString,
    ca_pem: &str,
    timeout: Duration,
) -> anyhow::Result<crate::snipeit_client::SnipeItClient> {
    crate::snipeit_client::SnipeItClient::with_timeout_custom_trust(
        base_url, token, timeout, ca_pem,
    )
}
