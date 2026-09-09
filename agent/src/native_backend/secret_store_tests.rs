use super::*;
use crate::native_backend::models::{
    SessionData, VpnCertificate, VpnLocation, VpnSecrets, VpnSessionData,
};
use serde_json::json;
use std::{cell::RefCell, collections::BTreeMap};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Action {
    Read(String, String),
    Write(String),
    Delete(String),
}

#[derive(Default)]
struct MemoryKeyring {
    entries: RefCell<BTreeMap<(String, String), String>>,
    actions: RefCell<Vec<Action>>,
    fail_next: RefCell<Option<Action>>,
}

impl MemoryKeyring {
    fn insert(&self, service: &str, username: &str, value: &str) {
        self.entries
            .borrow_mut()
            .insert((service.into(), username.into()), value.into());
    }

    fn seed_legacy(&self, session: &SessionData) {
        self.insert(
            LEGACY_SERVICE,
            LEGACY_ACCOUNT_INDEX,
            &serde_json::to_string(&[&session.account_name]).unwrap(),
        );
        self.insert(
            LEGACY_SERVICE,
            &legacy_account_key(&session.account_name),
            &serde_json::to_string(session).unwrap().replace("\\n", "\n"),
        );
    }

    fn record(&self, action: Action) -> keyring::Result<()> {
        self.actions.borrow_mut().push(action.clone());
        if self.fail_next.borrow().as_ref() == Some(&action) {
            self.fail_next.borrow_mut().take();
            return Err(keyring::Error::NoStorageAccess(Box::new(
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, "test keyring locked"),
            )));
        }
        Ok(())
    }

    fn mutations(&self) -> Vec<Action> {
        self.actions
            .borrow()
            .iter()
            .filter(|action| !matches!(action, Action::Read(..)))
            .cloned()
            .collect()
    }

    fn assert_private_writes_are_safe(&self) {
        for ((service, key), value) in self.entries.borrow().iter() {
            if service != SERVICE {
                continue;
            }
            assert!(value.is_ascii());
            assert!(value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_')));
            if key == ACCOUNT_INDEX {
                assert!(decode_account_index(value).is_some());
            } else if key == LEGACY_IMPORT_MARKER {
                assert_eq!(value, LEGACY_IMPORT_COMPLETE);
            } else {
                assert!(decode_session(value).is_some());
            }
        }
    }
}

impl SecretService for MemoryKeyring {
    fn read(&self, service: &str, username: &str) -> keyring::Result<Zeroizing<String>> {
        self.record(Action::Read(service.into(), username.into()))?;
        self.entries
            .borrow()
            .get(&(service.into(), username.into()))
            .cloned()
            .map(Zeroizing::new)
            .ok_or(keyring::Error::NoEntry)
    }

    fn write_private(&self, username: &str, value: &str) -> keyring::Result<()> {
        self.record(Action::Write(username.into()))?;
        self.insert(SERVICE, username, value);
        Ok(())
    }

    fn delete_private(&self, username: &str) -> keyring::Result<()> {
        self.record(Action::Delete(username.into()))?;
        self.entries
            .borrow_mut()
            .remove(&(SERVICE.into(), username.into()))
            .map(|_| ())
            .ok_or(keyring::Error::NoEntry)
    }
}

fn session() -> SessionData {
    SessionData {
        uid: "uid".into(),
        access_token: "access-token".into(),
        refresh_token: "refresh-token".into(),
        scopes: vec!["vpn".into()],
        account_name: "test@example.test".into(),
        credentialless: false,
        environment: "prod".into(),
        vpn: VpnSessionData {
            vpninfo: json!({"VPN": {"MaxTier": 2}}),
            certificate: VpnCertificate {
                certificate: "-----BEGIN CERTIFICATE-----\nRkFLRQ==\n-----END CERTIFICATE-----\n"
                    .into(),
                client_key: "-----BEGIN PUBLIC KEY-----\nRkFLRQ==\n-----END PUBLIC KEY-----\n"
                    .into(),
                client_key_fingerprint: "fingerprint".into(),
                expiration_time: 2,
                refresh_time: 1,
                server_public_key: String::new(),
                server_public_key_mode: "EC".into(),
                extra: serde_json::Map::new(),
            },
            secrets: VpnSecrets {
                ed25519_privatekey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            },
            location: VpnLocation::default(),
        },
        extra: serde_json::Map::new(),
    }
}

#[test]
fn private_and_legacy_account_keys_are_namespaced() {
    assert_eq!(private_account_key("test"), "account-v1-orsxg5a");
    assert_eq!(legacy_account_key("test"), "proton-sso-account-orsxg5a");
}

#[test]
fn account_names_are_bounded_before_becoming_keyring_keys() {
    assert!(valid_account_name("test@example.test"));
    assert!(!valid_account_name("   "));
    assert!(!valid_account_name("bad\0name"));
    assert!(!valid_account_name("bad\nname"));
    assert!(!valid_account_name(&"x".repeat(MAX_ACCOUNT_NAME_BYTES + 1)));
}

#[test]
fn private_session_round_trips_through_ascii_envelope() {
    let encoded = encode_session(&session()).expect("encode session");
    assert!(encoded.starts_with(SESSION_ENVELOPE_PREFIX));
    assert!(encoded
        .strip_prefix(SESSION_ENVELOPE_PREFIX)
        .expect("prefix")
        .chars()
        .all(|character| character.is_ascii_alphanumeric()
            || character == '-'
            || character == '_'));

    let decoded = decode_session(encoded.as_str()).expect("decode session");
    assert_eq!(decoded.account_name, "test@example.test");
    assert_eq!(
        decoded.vpn.certificate.certificate,
        session().vpn.certificate.certificate
    );
}

#[test]
fn private_account_index_round_trips_through_ascii_envelope() {
    let accounts = vec!["test@example.test".to_string(), "second".to_string()];
    let encoded = encode_account_index(&accounts).expect("encode index");
    assert!(encoded.starts_with(INDEX_ENVELOPE_PREFIX));
    assert!(encoded
        .strip_prefix(INDEX_ENVELOPE_PREFIX)
        .expect("prefix")
        .chars()
        .all(|character| character.is_ascii_alphanumeric()
            || character == '-'
            || character == '_'));
    assert_eq!(
        decode_account_index(encoded.as_str()).expect("decode index"),
        accounts
    );
}

#[test]
fn private_decoder_rejects_legacy_raw_json() {
    let raw = serde_json::to_string(&session()).expect("serialize session");
    assert!(decode_session(&raw).is_none());
}

#[test]
fn legacy_proton_sso_json_session_remains_importable() {
    let raw = serde_json::to_string(&session()).expect("serialize session");
    let decoded = decode_legacy_session(&raw).expect("decode legacy session");
    assert_eq!(decoded.account_name, "test@example.test");
    assert!(decoded.vpn.certificate.certificate.contains("\nRkFLRQ==\n"));
}

#[test]
fn legacy_passwordless_gnome_keyring_round_trip_is_recovered() {
    let raw = serde_json::to_string(&session()).expect("serialize session");
    let damaged = raw.replace("\\n", "\n");
    assert!(serde_json::from_str::<SessionData>(&damaged).is_err());

    let decoded = decode_legacy_session(&damaged).expect("repair legacy session");
    assert_eq!(decoded.account_name, "test@example.test");
    assert_eq!(
        decoded.vpn.certificate.certificate,
        session().vpn.certificate.certificate
    );
}

#[test]
fn malformed_sessions_are_rejected() {
    assert!(decode_session("not a session").is_none());
    assert!(decode_legacy_session("not a session").is_none());
}

#[test]
fn migration_refresh_and_signout_leave_shared_credentials_untouched() {
    let store = MemoryKeyring::default();
    let mut expected = session();
    store.seed_legacy(&expected);
    store.insert("unrelated application", "account", "unrelated secret");
    let shared_before = store.entries.borrow().clone();

    let imported = load_default(&store)
        .unwrap()
        .expect("import legacy session");
    assert_eq!(
        imported.vpn.certificate.certificate,
        expected.vpn.certificate.certificate
    );
    store.assert_private_writes_are_safe();

    expected.access_token = "rotated-access-token".into();
    expected.refresh_token = "rotated-refresh-token".into();
    save(&store, &expected).unwrap();
    let restored = load_default(&store)
        .unwrap()
        .expect("restore private session");
    assert_eq!(restored.access_token, expected.access_token);
    assert_eq!(restored.refresh_token, expected.refresh_token);

    delete(&store, &expected.account_name).unwrap();
    store.actions.borrow_mut().clear();
    assert!(load_default(&store).unwrap().is_none());
    assert!(!store
        .actions
        .borrow()
        .iter()
        .any(|action| matches!(action, Action::Read(service, _) if service == LEGACY_SERVICE)));
    for (key, value) in shared_before {
        assert_eq!(store.entries.borrow().get(&key), Some(&value));
    }
    store.assert_private_writes_are_safe();
}

#[test]
fn token_refresh_writes_only_the_session_and_keeps_rc1_metadata() {
    let store = MemoryKeyring::default();
    let mut current = session();
    save(&store, &current).unwrap();
    let index = store.read(SERVICE, ACCOUNT_INDEX).unwrap();
    let marker = store.read(SERVICE, LEGACY_IMPORT_MARKER).unwrap();
    store.actions.borrow_mut().clear();

    current.access_token = "new-access-token".into();
    save(&store, &current).unwrap();
    assert_eq!(
        store.mutations(),
        [Action::Write(private_account_key(&current.account_name))]
    );
    assert_eq!(store.read(SERVICE, ACCOUNT_INDEX).unwrap(), index);
    assert_eq!(store.read(SERVICE, LEGACY_IMPORT_MARKER).unwrap(), marker);
    assert_eq!(
        load_default(&store).unwrap().unwrap().access_token,
        current.access_token
    );
}

#[test]
fn interrupted_migration_can_be_retried_at_each_storage_step() {
    let expected = session();
    for failed_key in [
        private_account_key(&expected.account_name),
        ACCOUNT_INDEX.into(),
        LEGACY_IMPORT_MARKER.into(),
    ] {
        let store = MemoryKeyring::default();
        store.seed_legacy(&expected);
        *store.fail_next.borrow_mut() = Some(Action::Write(failed_key));
        let error = load_default(&store).unwrap_err();
        assert_eq!(error.code, "secret_service_error");
        assert!(error.retryable);

        let restored = load_default(&store).unwrap().expect("retry import");
        assert_eq!(restored.refresh_token, expected.refresh_token);
        delete(&store, &expected.account_name).unwrap();
        assert!(load_default(&store).unwrap().is_none());
        store.assert_private_writes_are_safe();
    }
}

#[test]
fn signout_blocks_legacy_reimport_even_if_index_cleanup_fails() {
    let store = MemoryKeyring::default();
    let current = session();
    store.seed_legacy(&current);
    save(&store, &current).unwrap();
    // Reproduce a previous import interrupted after its index write.
    store
        .entries
        .borrow_mut()
        .remove(&(SERVICE.into(), LEGACY_IMPORT_MARKER.into()));
    *store.fail_next.borrow_mut() = Some(Action::Write(ACCOUNT_INDEX.into()));

    assert!(delete(&store, &current.account_name).is_err());
    assert!(legacy_import_complete(&store).unwrap());
    assert!(load_default(&store).unwrap().is_none());
    delete(&store, &current.account_name).expect("retry index cleanup");
    delete(&store, &current.account_name).expect("signout is idempotent");
    assert!(load_private_accounts(&store).unwrap().is_empty());
}

#[test]
fn signout_marker_failure_preserves_the_session_for_retry() {
    let store = MemoryKeyring::default();
    let current = session();
    save(&store, &current).unwrap();
    store
        .entries
        .borrow_mut()
        .remove(&(SERVICE.into(), LEGACY_IMPORT_MARKER.into()));
    let before = store.entries.borrow().clone();
    *store.fail_next.borrow_mut() = Some(Action::Write(LEGACY_IMPORT_MARKER.into()));

    assert!(delete(&store, &current.account_name).is_err());
    assert_eq!(*store.entries.borrow(), before);
    delete(&store, &current.account_name).expect("retry signout");
    assert!(load_default(&store).unwrap().is_none());
}

#[test]
fn failed_session_delete_keeps_index_and_can_be_retried() {
    let store = MemoryKeyring::default();
    let current = session();
    save(&store, &current).unwrap();
    let index = store.read(SERVICE, ACCOUNT_INDEX).unwrap();
    *store.fail_next.borrow_mut() =
        Some(Action::Delete(private_account_key(&current.account_name)));

    assert!(delete(&store, &current.account_name).is_err());
    assert_eq!(store.read(SERVICE, ACCOUNT_INDEX).unwrap(), index);
    assert!(load_private_default(&store).unwrap().is_some());
    delete(&store, &current.account_name).expect("retry credential deletion");
    assert!(load_default(&store).unwrap().is_none());
}

#[test]
fn locked_private_storage_does_not_trigger_legacy_import_or_mutation() {
    for failed_action in [
        Action::Read(SERVICE.into(), ACCOUNT_INDEX.into()),
        Action::Read(SERVICE.into(), LEGACY_IMPORT_MARKER.into()),
    ] {
        let store = MemoryKeyring::default();
        store.seed_legacy(&session());
        *store.fail_next.borrow_mut() = Some(failed_action);
        assert!(load_default(&store).is_err());
        assert!(store.mutations().is_empty());
        assert!(!store
            .actions
            .borrow()
            .iter()
            .any(|action| matches!(action, Action::Read(service, _) if service == LEGACY_SERVICE)));
    }
}

#[test]
fn invalid_or_oversized_sessions_do_not_replace_existing_credentials() {
    let store = MemoryKeyring::default();
    let current = session();
    save(&store, &current).unwrap();
    let before = store.entries.borrow().clone();
    for invalid in [
        SessionData {
            access_token: String::new(),
            ..current.clone()
        },
        SessionData {
            refresh_token: String::new(),
            ..current.clone()
        },
        SessionData {
            uid: String::new(),
            ..current.clone()
        },
        SessionData {
            account_name: "bad\nname".into(),
            ..current.clone()
        },
        SessionData {
            access_token: "x".repeat(MAX_SESSION_BYTES),
            ..current.clone()
        },
    ] {
        store.actions.borrow_mut().clear();
        assert_eq!(save(&store, &invalid).unwrap_err().code, "session_invalid");
        assert!(store.mutations().is_empty());
        assert_eq!(*store.entries.borrow(), before);
    }
    store.actions.borrow_mut().clear();
    assert!(delete(&store, &"x".repeat(MAX_ACCOUNT_NAME_BYTES + 1)).is_err());
    assert!(store.actions.borrow().is_empty());
}

#[test]
fn oversized_index_is_rejected_before_the_session_write() {
    let store = MemoryKeyring::default();
    // Valid account names can still expand when JSON escapes quotes.
    let accounts: Vec<_> = (0..MAX_ACCOUNTS - 1)
        .map(|number| format!("{number:02}{}", "\"".repeat(254)))
        .collect();
    store.insert(
        SERVICE,
        ACCOUNT_INDEX,
        &encode_account_index(&accounts).unwrap(),
    );
    let mut current = session();
    current.account_name = "\\".repeat(MAX_ACCOUNT_NAME_BYTES);
    assert_eq!(save(&store, &current).unwrap_err().code, "session_invalid");
    assert!(store.mutations().is_empty());
}

#[test]
fn duplicate_missing_and_mismatched_accounts_do_not_hide_a_valid_session() {
    let store = MemoryKeyring::default();
    let current = session();
    let mut accounts = vec!["missing".into(); MAX_ACCOUNTS];
    accounts.extend(["wrong-account".into(), current.account_name.clone()]);
    store.insert(
        SERVICE,
        ACCOUNT_INDEX,
        &encode_account_index(&accounts).unwrap(),
    );
    let encoded = encode_session(&current).unwrap();
    store.insert(SERVICE, &private_account_key("wrong-account"), &encoded);
    store.insert(
        SERVICE,
        &private_account_key(&current.account_name),
        &encoded,
    );

    assert_eq!(
        load_default(&store).unwrap().unwrap().account_name,
        current.account_name
    );
    save(&store, &current).unwrap();
    assert_eq!(
        load_private_accounts(&store).unwrap(),
        [
            current.account_name,
            "missing".into(),
            "wrong-account".into()
        ]
    );
}

#[test]
fn legacy_payload_limits_apply_before_parsing_and_repair() {
    let store = MemoryKeyring::default();
    store.seed_legacy(&session());
    let oversized = format!(
        "{}{}",
        " ".repeat(MAX_INDEX_BYTES),
        "[\"test@example.test\"]"
    );
    store.insert(LEGACY_SERVICE, LEGACY_ACCOUNT_INDEX, &oversized);
    assert!(load_default(&store).unwrap().is_none());
    assert!(store.mutations().is_empty());
    assert!(!store.actions.borrow().iter().any(|action| {
        matches!(action, Action::Read(service, key)
            if service == LEGACY_SERVICE && key != LEGACY_ACCOUNT_INDEX)
    }));
    let oversized = format!(
        "{}{}",
        " ".repeat(MAX_SESSION_BYTES),
        serde_json::to_string(&session()).unwrap()
    );
    assert!(decode_legacy_session(&oversized).is_none());
}

#[test]
fn all_control_characters_and_unicode_survive_private_storage() {
    let store = MemoryKeyring::default();
    let mut expected = session();
    expected.account_name = "josé@example.test".into();
    let controls: String = (0u8..=31).map(char::from).collect();
    expected.extra.insert(
        "future-field".into(),
        json!({
            "controls": controls,
            "text": "Español 日本語 \\n \\t \\ \" ; = [group]"
        }),
    );
    save(&store, &expected).unwrap();
    store.assert_private_writes_are_safe();
    let actual = load_default(&store).unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

#[test]
fn unknown_envelope_versions_and_oversized_payloads_are_rejected() {
    let encoded = encode_session(&session()).unwrap();
    assert!(decode_session(&encoded.replacen("pvom1:", "pvom2:", 1)).is_none());
    assert!(decode_session(&"x".repeat(MAX_SESSION_ENVELOPE_BYTES + 1)).is_none());
    assert!(decode_account_index(&"x".repeat(MAX_INDEX_ENVELOPE_BYTES + 1)).is_none());
    let oversized_session = format!(
        "{SESSION_ENVELOPE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(vec![b' '; MAX_SESSION_BYTES + 1])
    );
    assert!(decode_session(&oversized_session).is_none());
    let oversized_index = format!(
        "{INDEX_ENVELOPE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(vec![b' '; MAX_INDEX_BYTES + 1])
    );
    assert!(decode_account_index(&oversized_index).is_none());
    assert!(decode_account_index("pvom-index2:W10").is_none());
}

#[test]
fn ambiguous_credentials_never_expose_their_debug_details() {
    use keyring::credential::CredentialBuilderApi;
    let credential = keyring::secret_service::SsCredentialBuilder {}
        .build(None, "private-service-label", "private-account-label")
        .unwrap();
    let error = keyring_error("read session", keyring::Error::Ambiguous(vec![credential]));
    let diagnostic = format!("{error:?} {error}");
    assert!(!diagnostic.contains("private-service-label"));
    assert!(!diagnostic.contains("private-account-label"));
    assert!(diagnostic.contains("1 matching credentials"));
    assert!(error.retryable);
}

// This opt-in check performs reads only. It does not call load_default (which
// can import legacy entries), save, delete, or any Proton/network operation.
#[test]
#[ignore = "reads real desktop credentials; requires explicit user consent"]
fn desktop_private_session_is_rc1_compatible_read_only() {
    assert_eq!(
        std::env::var("PROTON_KEYRING_READ_ONLY_TEST").as_deref(),
        Ok("1")
    );
    let store = SecretStore;
    let index = store
        .read(SERVICE, ACCOUNT_INDEX)
        .unwrap_or_else(|_| panic!("cannot read private account index"));
    let accounts = decode_account_index(&index).expect("invalid private account envelope");
    let accounts = normalized_accounts(accounts);
    assert!(!accounts.is_empty(), "no private account to validate");
    for account in accounts {
        let key = private_account_key(&account);
        let raw = store
            .read(SERVICE, &key)
            .unwrap_or_else(|_| panic!("cannot read private session"));
        let session = decode_session(&raw).expect("invalid private session envelope");
        assert!(session.account_name == account, "session/account mismatch");
        assert!(
            session.is_authenticated(),
            "session authentication fields are missing"
        );
        let encoded =
            encode_session(&session).unwrap_or_else(|_| panic!("session cannot be safely encoded"));
        assert!(encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_')));
        let restored = decode_session(&encoded).expect("session cannot be decoded");
        // Compare serialized, zeroizing buffers without ever printing values
        // on failure, including tokens, PEM material or account identifiers.
        let expected = Zeroizing::new(serde_json::to_vec(&session).unwrap());
        let actual = Zeroizing::new(serde_json::to_vec(&restored).unwrap());
        assert!(expected == actual, "session round-trip changed data");
        let after = store
            .read(SERVICE, &key)
            .unwrap_or_else(|_| panic!("cannot reread private session"));
        assert!(
            raw == after,
            "stored session changed during read-only validation"
        );
    }
    let after = store
        .read(SERVICE, ACCOUNT_INDEX)
        .unwrap_or_else(|_| panic!("cannot reread private account index"));
    assert!(
        index == after,
        "account index changed during read-only validation"
    );
}

#[test]
#[ignore = "writes synthetic credentials; run only through tests/keyring-roundtrip.py"]
fn isolated_passwordless_keyring_restart() {
    let root = std::path::PathBuf::from(
        std::env::var_os("PROTON_KEYRING_TEST_ROOT").expect("isolated runner required"),
    );
    assert!(root.is_absolute());
    assert!(root.join("isolated-keyring-test").is_file());
    assert_eq!(
        std::env::var_os("XDG_DATA_HOME").map(std::path::PathBuf::from),
        Some(root.join("data"))
    );
    assert_ne!(
        std::env::var("DBUS_SESSION_BUS_ADDRESS").ok(),
        std::env::var("PROTON_KEYRING_PARENT_BUS").ok()
    );
    let mut expected = session();
    expected.extra.insert(
        "control-characters".into(),
        json!((0u8..=31).map(char::from).collect::<String>() + " Español 日本語 \\n \\t \""),
    );
    // The shared sentinel must itself be safe to persist. Writing old raw JSON
    // with PEM newlines would reproduce the pre-0.9.6 corruption before this
    // test could check the new private format. Damaged legacy imports are
    // covered separately by the in-memory fault tests.
    let mut legacy_expected = session();
    legacy_expected.vpn.certificate.certificate = "synthetic-certificate".into();
    legacy_expected.vpn.certificate.client_key = "synthetic-public-key".into();
    let store = SecretStore;
    let phase = std::env::var("PROTON_KEYRING_TEST_PHASE").unwrap();
    match phase.as_str() {
        "seed" => {
            // Only synthetic data in the runner's private D-Bus session and
            // temporary XDG directories. Include shared/unrelated sentinels.
            Entry::new(LEGACY_SERVICE, LEGACY_ACCOUNT_INDEX)
                .unwrap()
                .set_password(&serde_json::to_string(&[&expected.account_name]).unwrap())
                .unwrap();
            Entry::new(LEGACY_SERVICE, &legacy_account_key(&expected.account_name))
                .unwrap()
                .set_password(&serde_json::to_string(&legacy_expected).unwrap())
                .unwrap();
            Entry::new("unrelated application", "sentinel")
                .unwrap()
                .set_password("unrelated-secret")
                .unwrap();
            store.save(&expected).unwrap();
        }
        "restore" => {
            let actual = store
                .load_default()
                .unwrap()
                .expect("restore after daemon restart");
            assert_eq!(
                serde_json::to_value(actual).unwrap(),
                serde_json::to_value(&expected).unwrap()
            );
        }
        "delete" => store.delete(&expected.account_name).unwrap(),
        "signed-out" => assert!(store.load_default().unwrap().is_none()),
        _ => panic!("unknown isolated test phase"),
    }
    assert_eq!(
        Entry::new("unrelated application", "sentinel")
            .unwrap()
            .get_password()
            .unwrap(),
        "unrelated-secret"
    );
    let legacy = store
        .read(LEGACY_SERVICE, &legacy_account_key(&expected.account_name))
        .unwrap();
    assert_eq!(
        serde_json::to_value(decode_legacy_session(&legacy).expect("legacy sentinel survives"))
            .unwrap(),
        serde_json::to_value(legacy_expected).unwrap()
    );
}
