use super::*;
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};

#[derive(Debug)]
struct PinnedVerifier {
    pins: &'static [&'static str],
    verify_chain: bool,
    webpki: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        certificate: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.verify_chain {
            self.webpki
                .verify_server_cert(certificate, intermediates, name, ocsp, now)?;
        }
        let (_, parsed) = parse_x509_certificate(certificate.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let pin = BASE64.encode(Sha256::digest(parsed.tbs_certificate.subject_pki.raw));
        if !self.pins.contains(&pin.as_str()) {
            return Err(rustls::Error::General("Proton TLS pin mismatch".into()));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls12_signature(message, cert, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls13_signature(message, cert, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

pub(super) fn config(alternative: bool) -> NativeResult<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|error| {
            NativeError::new(
                "api_client_unavailable",
                "Unable to initialize Proton TLS verifier",
            )
            .with_source(error)
        })?;
    let verifier = PinnedVerifier {
        pins: if alternative {
            ALTERNATIVE_TLS_PINS
        } else {
            TLS_PINS
        },
        verify_chain: !alternative,
        webpki,
    };
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| {
            NativeError::new(
                "api_client_unavailable",
                "Unable to initialize Proton TLS versions",
            )
            .with_source(error)
        })?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    // This certificate/key pair is a public, test-only fixture. No production
    // credentials are used. Model an intercepting TLS endpoint and prove it
    // receives no HTTP bytes, even on the alternative (IP hostname) client.
    #[tokio::test]
    async fn untrusted_alternative_receives_no_authorization_header() {
        let cert = CertificateDer::from(include_bytes!("testdata/untrusted.der").to_vec());
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
            include_bytes!("testdata/untrusted-key.der").to_vec(),
        );
        let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let connection = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            let mut received = [0_u8; 4096];
            assert!(
                stream.read(&mut received).is_err(),
                "interceptor received HTTP plaintext"
            );
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .use_preconfigured_tls(config(true).unwrap())
            .build()
            .unwrap();
        let error = client
            .get(format!("https://{address}/auth/refresh"))
            .bearer_auth("test-only-not-a-real-token")
            .send()
            .await
            .unwrap_err();
        assert!(error.is_connect());
        server.join().unwrap();
    }
}
