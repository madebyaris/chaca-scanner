//! Standalone TLS certificate probe.
//!
//! Performs its own TLS handshake so Chaca can report the negotiated
//! protocol, issuer, subject alternative names, and certificate expiry in
//! the Target Intelligence panel.

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct TlsProbeResult {
    pub protocol: String,
    pub issuer: String,
    pub san: Vec<String>,
    pub not_after: String,
    pub days_to_expiry: i64,
}

/// Probe `host:port` with a bounded handshake. Returns `None` when the probe
/// could not be completed (non-TLS port, DNS failure, timeout, ...).
pub async fn probe(host: &str, port: u16, accept_invalid_certs: bool) -> Option<TlsProbeResult> {
    let handshake = async {
        let stream = tokio::net::TcpStream::connect((host, port)).await?;
        let config = build_client_config(accept_invalid_certs)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(host.to_string())?;
        let tls = connector.connect(server_name, stream).await?;
        Ok::<_, Box<dyn std::error::Error>>(tls)
    };
    let tls = tokio::time::timeout(Duration::from_secs(15), handshake)
        .await
        .ok()?
        .ok()?;

    let (_, common) = tls.get_ref();

    let protocol = match common.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_1) => "TLSv1.1".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_0) => "TLSv1.0".to_string(),
        _ => String::new(),
    };

    let certs: Vec<Vec<u8>> = common
        .peer_certificates()
        .map(|certs| certs.iter().map(|c| c.to_vec()).collect())
        .unwrap_or_default();
    let Some(leaf) = certs.first() else {
        return Some(TlsProbeResult {
            protocol,
            ..Default::default()
        });
    };

    use x509_parser::prelude::*;
    let Ok((_, cert)) = X509Certificate::from_der(leaf) else {
        return Some(TlsProbeResult {
            protocol,
            ..Default::default()
        });
    };

    let issuer = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|atv| atv.as_str().ok())
        .unwrap_or_default()
        .to_string();

    let san: Vec<String> = match cert.subject_alternative_name() {
        Ok(Some(ext)) => ext
            .value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                x509_parser::extensions::GeneralName::DNSName(name) => Some(name.to_string()),
                _ => None,
            })
            .take(10)
            .collect(),
        _ => Vec::new(),
    };

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let not_after_secs = cert.validity().not_after.timestamp();
    let days_to_expiry = not_after_secs.saturating_sub(now_secs) / 86_400;
    let not_after_str = format_timestamp(not_after_secs);

    Some(TlsProbeResult {
        protocol,
        issuer,
        san,
        not_after: not_after_str,
        days_to_expiry,
    })
}

#[derive(Debug)]
struct NoVerifyVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            ECDSA_NISTP256_SHA256,
            RSA_PSS_SHA256,
            RSA_PKCS1_SHA256,
            ECDSA_NISTP384_SHA384,
            RSA_PSS_SHA384,
            RSA_PKCS1_SHA384,
            ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA512,
            RSA_PKCS1_SHA512,
            ED25519,
            ED448,
            ECDSA_SHA1_Legacy,
            RSA_PKCS1_SHA1,
        ]
    }
}

fn build_client_config(accept_invalid_certs: bool) -> Result<ClientConfig, String> {
    if accept_invalid_certs {
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifyVerifier))
            .with_no_client_auth();
        return Ok(config);
    }

    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}

fn format_timestamp(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.format("%b %e, %Y %H:%M UTC").to_string())
        .unwrap_or_default()
}
