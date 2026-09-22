use super::{models::PhysicalServer, NativeError, NativeResult};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{pkcs8::DecodePublicKey, Signature, VerifyingKey};
use serde::Serialize;
use std::{net::IpAddr, sync::OnceLock};

// Proton Windows v5.1.8 DefaultConfiguration.ServerValidationPublicKey.
// This signature covers EntryIP and Label, not the X25519 key or other metadata.
const PUBLIC_KEY_DER: &str = "MCowBQYDK2VwAyEANpYpt/FlSRwEuGLMoNAGOjy1BTyEJPJvKe00oln7LZk=";

pub fn validate(server: &PhysicalServer) -> NativeResult<()> {
    static KEY: OnceLock<VerifyingKey> = OnceLock::new();
    let key = KEY.get_or_init(|| {
        VerifyingKey::from_public_key_der(
            &BASE64.decode(PUBLIC_KEY_DER).expect("pinned base64 key"),
        )
        .expect("pinned Ed25519 key")
    });
    validate_with_key(server, key)
}

fn invalid() -> NativeError {
    NativeError::new(
        "server_validation_failed",
        "The VPN server could not be verified. Refresh the server list and try again.",
    )
    .retryable(true)
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct SignedServer<'a> {
    #[serde(rename = "EntryIP")]
    entry_ip: &'a str,
    label: &'a Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct SignedPayload<'a> {
    server: SignedServer<'a>,
}

fn signed_payload(server: &PhysicalServer) -> Vec<u8> {
    serde_json::to_vec(&SignedPayload {
        server: SignedServer {
            entry_ip: &server.entry_ip,
            label: &server.label,
        },
    })
    .expect("serializable server fields")
}

fn validate_with_key(server: &PhysicalServer, key: &VerifyingKey) -> NativeResult<()> {
    if server.entry_ip.parse::<IpAddr>().is_err()
        || server.label.as_ref().is_some_and(|label| !label.is_ascii())
        || server.x25519_public_key.len() != 44
        || BASE64
            .decode(&server.x25519_public_key)
            .map_or(true, |key| key.len() != 32)
    {
        return Err(invalid());
    }
    let signature = server
        .signature
        .as_deref()
        .filter(|s| s.len() == 88)
        .ok_or_else(invalid)?;
    let signature = BASE64.decode(signature).map_err(|_| invalid())?;
    let signature = Signature::from_slice(&signature).map_err(|_| invalid())?;
    key.verify_strict(&signed_payload(server), &signature)
        .map_err(|_| invalid())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub fn signed_endpoint() -> PhysicalServer {
        let mut server = PhysicalServer {
            id: "synthetic-endpoint".into(),
            entry_ip: "192.0.2.1".into(),
            exit_ip: "192.0.2.2".into(),
            domain: "example.test".into(),
            status: 1,
            x25519_public_key: BASE64.encode([1u8; 32]),
            label: Some(String::new()),
            signature: None,
            extra: Default::default(),
        };
        sign(&mut server);
        server
    }

    fn sign(server: &mut PhysicalServer) {
        server.signature = Some(
            BASE64.encode(
                SigningKey::from_bytes(&[7; 32])
                    .sign(&signed_payload(server))
                    .to_bytes(),
            ),
        );
    }

    pub fn validate_test(server: &PhysicalServer) -> NativeResult<()> {
        validate_with_key(server, &SigningKey::from_bytes(&[7; 32]).verifying_key())
    }

    #[test]
    fn signatures_preserve_null_empty_and_escaped_labels() {
        let mut server = signed_endpoint();
        for label in [
            None,
            Some(String::new()),
            Some("42".into()),
            Some("a\"\\b".into()),
        ] {
            server.label = label;
            sign(&mut server);
            validate_test(&server).unwrap();
        }
        server.label = None;
        assert_eq!(
            String::from_utf8(signed_payload(&server)).unwrap(),
            r#"{"Server":{"EntryIP":"192.0.2.1","Label":null}}"#
        );
    }

    #[test]
    fn rejects_tampering_missing_signatures_wrong_keys_and_malformed_endpoints() {
        let valid = signed_endpoint();
        validate_test(&valid).unwrap();
        assert!(
            validate(&valid).is_err(),
            "A test key must never be trusted in production"
        );
        let mut bad = valid.clone();
        bad.entry_ip = "192.0.2.3".into();
        assert!(validate_test(&bad).is_err());
        let mut bad = valid.clone();
        bad.label = None;
        assert!(validate_test(&bad).is_err());
        for signature in [None, Some(String::new()), Some(BASE64.encode([0u8; 64]))] {
            let mut bad = valid.clone();
            bad.signature = signature;
            assert!(validate_test(&bad).is_err());
        }
        for public_key in ["key".to_owned(), BASE64.encode([0u8; 31]), "!".repeat(44)] {
            let mut bad = valid.clone();
            bad.x25519_public_key = public_key;
            assert!(validate_test(&bad).is_err());
        }
        let mut bad = valid;
        bad.entry_ip = "not-an-ip".into();
        sign(&mut bad);
        assert!(validate_test(&bad).is_err());
    }
    #[test]
    #[ignore = "requires PROTON_SIGNED_CATALOG_PATH pointing to an authenticated API catalog response"]
    fn official_catalog_fixture_verifies_with_the_production_key() {
        let path = std::env::var_os("PROTON_SIGNED_CATALOG_PATH")
            .expect("provide a signed public catalog response, never session credentials");
        let catalog =
            super::super::models::ServerCatalog::load(std::path::Path::new(&path)).unwrap();
        let endpoints: Vec<_> = catalog
            .logical_servers
            .iter()
            .flat_map(|logical| &logical.servers)
            .filter(|server| server.status == 1)
            .collect();
        assert!(
            !endpoints.is_empty(),
            "catalog must contain active physical endpoints"
        );
        let verified = endpoints
            .iter()
            .filter(|server| validate(server).is_ok())
            .count();
        assert_eq!(
            verified,
            endpoints.len(),
            "all active official endpoints must verify"
        );
        eprintln!("Verified {verified} official signed endpoints");
    }
}
