use onionlink_core::Session;

#[test]
fn live_http_get_when_enabled() {
    if std::env::var("ONIONLINK_LIVE_TESTS").as_deref() != Ok("1") {
        return;
    }

    let onion = std::env::var("ONIONLINK_LIVE_ONION")
        .expect("ONIONLINK_LIVE_ONION must be set when ONIONLINK_LIVE_TESTS=1");
    let port = std::env::var("ONIONLINK_LIVE_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(80);
    let path = std::env::var("ONIONLINK_LIVE_PATH").unwrap_or_else(|_| "/".to_string());
    let session = Session::new("128.31.0.39:9131", "", 30_000, true).unwrap();
    let response = session
        .http_get(&onion, port, &path, 4 * 1024 * 1024)
        .unwrap();
    assert!(response.len() <= 4 * 1024 * 1024);
}
