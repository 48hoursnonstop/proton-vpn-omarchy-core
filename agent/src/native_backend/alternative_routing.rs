use super::{NativeError, NativeResult};
use data_encoding::BASE32_NOPAD;
use futures_util::{stream::FuturesUnordered, StreamExt};
use reqwest::header;
use std::{net::SocketAddr, time::Duration};

const API_HOST: &str = "vpn-api.proton.me";
const AR_SUFFIX: &str = ".protonpro.xyz";

#[derive(Clone, Debug)]
pub struct AlternativeRoute {
    pub host: String,
    pub valid_for: Duration,
}

pub async fn resolve() -> NativeResult<AlternativeRoute> {
    let query_host = format!("d{}{}", BASE32_NOPAD.encode(API_HOST.as_bytes()), AR_SUFFIX);
    let query = build_txt_query(&query_host)?;
    let providers = [
        ("dns.google", "8.8.8.8:443"),
        ("dns.google", "8.8.4.4:443"),
        ("dns11.quad9.net", "9.9.9.11:443"),
        ("dns11.quad9.net", "149.112.112.11:443"),
    ];
    let mut pending = FuturesUnordered::new();
    for (host, socket) in providers {
        pending.push(query_provider(host, socket, &query));
    }
    let mut last_error = None;
    while let Some(result) = pending.next().await {
        match result {
            Ok(routes) => {
                if let Some(route) = routes.into_iter().next() {
                    return Ok(route);
                }
                last_error = Some("a provider returned no alternative route".into());
            }
            Err(error) => last_error = Some(error.to_string()),
        }
    }
    Err(NativeError::new(
        "alternative_routing_unavailable",
        "No Proton alternative API route could be resolved",
    )
    .with_source(last_error.unwrap_or_else(|| "no DNS-over-HTTPS provider responded".into()))
    .retryable(true))
}

async fn query_provider(
    provider_host: &str,
    provider_socket: &str,
    query: &[u8],
) -> NativeResult<Vec<AlternativeRoute>> {
    let socket: SocketAddr = provider_socket.parse().map_err(|error| {
        NativeError::new(
            "alternative_routing_invalid_provider",
            "The built-in DNS-over-HTTPS provider address is invalid",
        )
        .with_source(error)
    })?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .resolve(provider_host, socket)
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|error| {
            NativeError::new(
                "alternative_routing_unavailable",
                "Unable to initialize the DNS-over-HTTPS client",
            )
            .with_source(error)
        })?;
    let response = client
        .post(format!("https://{provider_host}/dns-query"))
        .header(header::CONTENT_TYPE, "application/dns-message")
        .header(header::ACCEPT, "application/dns-message")
        .body(query.to_vec())
        .send()
        .await
        .map_err(|error| {
            NativeError::new(
                "alternative_routing_unavailable",
                "A DNS-over-HTTPS provider could not be reached",
            )
            .with_source(error)
            .retryable(true)
        })?;
    if !response.status().is_success() {
        return Err(NativeError::new(
            "alternative_routing_unavailable",
            format!(
                "A DNS-over-HTTPS provider returned HTTP {}",
                response.status().as_u16()
            ),
        )
        .retryable(response.status().is_server_error()));
    }
    let bytes = response.bytes().await.map_err(|error| {
        NativeError::new(
            "alternative_routing_response_invalid",
            "The DNS-over-HTTPS response could not be read",
        )
        .with_source(error)
    })?;
    parse_txt_response(&bytes)
}

fn build_txt_query(host: &str) -> NativeResult<Vec<u8>> {
    if !valid_hostname(host) {
        return Err(NativeError::new(
            "alternative_routing_invalid_host",
            "The generated alternative-routing lookup host is invalid",
        ));
    }
    let mut query = Vec::with_capacity(host.len() + 18);
    query.extend_from_slice(&0x5056_u16.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    for label in host.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&16_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    Ok(query)
}

fn parse_txt_response(message: &[u8]) -> NativeResult<Vec<AlternativeRoute>> {
    if message.len() < 12 {
        return Err(invalid_dns_response("DNS header is truncated"));
    }
    if read_u16(message, 0)? != 0x5056 {
        return Err(invalid_dns_response("DNS transaction ID does not match"));
    }
    let flags = read_u16(message, 2)?;
    if flags & 0x8000 == 0 || flags & 0x000f != 0 {
        return Err(invalid_dns_response(
            "DNS query was not answered successfully",
        ));
    }
    let questions = read_u16(message, 4)? as usize;
    let answers = read_u16(message, 6)? as usize;
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_dns_name(message, offset)?;
        offset = offset
            .checked_add(4)
            .filter(|offset| *offset <= message.len())
            .ok_or_else(|| invalid_dns_response("DNS question is truncated"))?;
    }

    let mut routes = Vec::new();
    for _ in 0..answers {
        offset = skip_dns_name(message, offset)?;
        let record_type = read_u16(message, offset)?;
        let class = read_u16(message, offset + 2)?;
        let ttl = read_u32(message, offset + 4)?;
        let data_len = read_u16(message, offset + 8)? as usize;
        offset += 10;
        let end = offset
            .checked_add(data_len)
            .filter(|end| *end <= message.len())
            .ok_or_else(|| invalid_dns_response("DNS record is truncated"))?;
        if record_type == 16 && class == 1 {
            let mut text = Vec::new();
            let mut cursor = offset;
            while cursor < end {
                let part_len = message[cursor] as usize;
                cursor += 1;
                let part_end = cursor
                    .checked_add(part_len)
                    .filter(|part_end| *part_end <= end)
                    .ok_or_else(|| invalid_dns_response("DNS TXT record is truncated"))?;
                text.extend_from_slice(&message[cursor..part_end]);
                cursor = part_end;
            }
            if let Ok(host) = String::from_utf8(text) {
                let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
                if valid_hostname(&host) {
                    routes.push(AlternativeRoute {
                        host,
                        valid_for: Duration::from_secs(u64::from(ttl.max(60))),
                    });
                }
            }
        }
        offset = end;
    }
    Ok(routes)
}

fn skip_dns_name(message: &[u8], mut offset: usize) -> NativeResult<usize> {
    loop {
        let length = *message
            .get(offset)
            .ok_or_else(|| invalid_dns_response("DNS name is truncated"))?;
        offset += 1;
        if length == 0 {
            return Ok(offset);
        }
        if length & 0xc0 == 0xc0 {
            message
                .get(offset)
                .ok_or_else(|| invalid_dns_response("DNS compression pointer is truncated"))?;
            return Ok(offset + 1);
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(invalid_dns_response("DNS label length is invalid"));
        }
        offset = offset
            .checked_add(length as usize)
            .filter(|offset| *offset <= message.len())
            .ok_or_else(|| invalid_dns_response("DNS label is truncated"))?;
    }
}

fn read_u16(message: &[u8], offset: usize) -> NativeResult<u16> {
    let bytes: [u8; 2] = message
        .get(offset..offset + 2)
        .ok_or_else(|| invalid_dns_response("DNS integer is truncated"))?
        .try_into()
        .map_err(|_| invalid_dns_response("DNS integer is invalid"))?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(message: &[u8], offset: usize) -> NativeResult<u32> {
    let bytes: [u8; 4] = message
        .get(offset..offset + 4)
        .ok_or_else(|| invalid_dns_response("DNS integer is truncated"))?
        .try_into()
        .map_err(|_| invalid_dns_response("DNS integer is invalid"))?;
    Ok(u32::from_be_bytes(bytes))
}

fn valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn invalid_dns_response(detail: &str) -> NativeError {
    NativeError::new(
        "alternative_routing_response_invalid",
        "The alternative-routing DNS response is invalid",
    )
    .with_source(detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_the_proton_lookup_name() {
        let host = format!("d{}{}", BASE32_NOPAD.encode(API_HOST.as_bytes()), AR_SUFFIX);
        assert_eq!(host, "dOZYG4LLBOBUS44DSN52G63RONVSQ.protonpro.xyz");
        assert!(build_txt_query(&host).is_ok());
    }

    #[test]
    fn parses_a_compressed_txt_answer() {
        let mut response = build_txt_query("example.test").unwrap();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&16_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&120_u32.to_be_bytes());
        let value = b"route.protonvpn.net";
        response.extend_from_slice(&((value.len() + 1) as u16).to_be_bytes());
        response.push(value.len() as u8);
        response.extend_from_slice(value);
        let routes = parse_txt_response(&response).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].host, "route.protonvpn.net");
        assert_eq!(routes[0].valid_for, Duration::from_secs(120));
    }

    #[test]
    fn rejects_non_host_txt_values() {
        assert!(!valid_hostname("https://example.test"));
        assert!(!valid_hostname("example.test/path"));
        assert!(!valid_hostname("-example.test"));
        assert!(valid_hostname("route-1.example.test"));
    }

    #[tokio::test]
    #[ignore = "contacts public DNS-over-HTTPS providers"]
    async fn resolves_a_live_proton_alternative_route() {
        let route = resolve().await.unwrap();
        assert!(valid_hostname(&route.host));
        assert!(route.valid_for >= Duration::from_secs(60));
    }
}
