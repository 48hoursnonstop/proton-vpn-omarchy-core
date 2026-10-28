use super::*;

#[test]
fn guest_profiles_have_fresh_keys_and_leave_dns_and_autostart_unchanged() {
    let endpoint = crate::native_backend::guest_hole::Endpoint {
        name: "Fixture".into(),
        ip: "192.0.2.1".into(),
        public_key: BASE64.encode([9_u8; 32]),
    };
    let first = ProtunProfile::guest(&endpoint).unwrap();
    let second = ProtunProfile::guest(&endpoint).unwrap();
    assert_ne!(first.private_key.as_str(), second.private_key.as_str());
    assert_ne!(first.uuid, second.uuid);
    let settings = first.dbus_settings();
    let ipv4 = &settings["ipv4"];
    assert_eq!(cast::<bool>(&*ipv4["ignore-auto-dns"].0), Some(&true));
    assert!(!ipv4.contains_key("dns-data"));
    assert!(!ipv4.contains_key("dns-search"));
    assert_eq!(cast::<Vec<u32>>(&*ipv4["dns"].0), Some(&vec![]));
    assert!(!ipv4.contains_key("routing-rules"));
    assert!(!ipv4.contains_key("route-table"));
    assert_eq!(
        cast::<bool>(&*settings["connection"]["autoconnect"].0),
        Some(&false)
    );
    assert_eq!(settings["ipv6"]["method"].0.as_str(), Some("disabled"));
    assert!(vpn_data_string(
        &settings.into_iter().map(|(k, v)| (k.into(), v)).collect(),
        GUEST_HOLE_PURPOSE
    )
    .is_some());
}
