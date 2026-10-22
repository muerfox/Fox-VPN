use std::time::Duration;

/// Ask a public HTTPS endpoint for this machine's address.
/// A fresh client is created so the check cannot reuse a socket opened
/// before the tunnel existed. Cleartext HTTP is not used.
pub async fn public_ip() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;
    for url in ["https://api.ipify.org", "https://ifconfig.me/ip"] {
        let Ok(response) = client.get(url).send().await else {
            continue;
        };
        if !response.status().is_success() {
            continue;
        }
        let Ok(text) = response.text().await else {
            continue;
        };
        let text = text.trim();
        if text.len() < 64 && text.parse::<std::net::IpAddr>().is_ok() {
            return Some(text.to_string());
        }
    }
    None
}
