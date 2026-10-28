use super::*;
use std::{
    ffi::CString,
    net::{Ipv4Addr, SocketAddr},
    os::fd::AsRawFd,
};

pub(super) async fn resolve_api(interface: &str) -> NativeResult<Vec<SocketAddr>> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(dns_error)?;
    let interface = CString::new(interface).map_err(dns_error)?;
    // SAFETY: the fd belongs to socket and the NUL-terminated interface buffer
    // remains valid for the duration of setsockopt.
    let bound = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            interface.as_ptr().cast(),
            interface.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if bound != 0 {
        return Err(dns_error(std::io::Error::last_os_error()));
    }
    socket.set_nonblocking(true).map_err(dns_error)?;
    let socket = tokio::net::UdpSocket::from_std(socket).map_err(dns_error)?;
    socket.connect("10.2.0.1:53").await.map_err(dns_error)?;
    let id = rand::random::<u16>();
    let query = query(id);
    let response = tokio::time::timeout(Duration::from_secs(4), async {
        socket.send(&query).await?;
        let mut buffer = [0_u8; 4096];
        let length = socket.recv(&mut buffer).await?;
        Ok::<_, std::io::Error>(buffer[..length].to_vec())
    })
    .await
    .map_err(dns_error)?
    .map_err(dns_error)?;
    parse(&response, id)
}

fn query(id: u16) -> Vec<u8> {
    let mut query = Vec::from(id.to_be_bytes());
    query.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in "vpn-api.proton.me".split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    query
}

fn parse(data: &[u8], id: u16) -> NativeResult<Vec<SocketAddr>> {
    let invalid = || {
        NativeError::new("guest_hole_dns_failed", "The recovery DNS reply is invalid")
            .retryable(true)
    };
    if data.len() < 12
        || data[..2] != id.to_be_bytes()
        || data[2] & 0x82 != 0x80
        || data[3] & 15 != 0
        || data[4..6] != [0, 1]
    {
        return Err(invalid());
    }
    let answers = u16::from_be_bytes([data[6], data[7]]);
    if answers > 64 {
        return Err(invalid());
    }
    let mut offset = 12;
    skip_name(data, &mut offset)?;
    offset = offset
        .checked_add(4)
        .filter(|end| *end <= data.len())
        .ok_or_else(invalid)?;
    let mut addresses = Vec::new();
    for _ in 0..answers {
        skip_name(data, &mut offset)?;
        let header = data.get(offset..offset + 10).ok_or_else(invalid)?;
        let length = u16::from_be_bytes([header[8], header[9]]) as usize;
        offset += 10;
        let bytes = data.get(offset..offset + length).ok_or_else(invalid)?;
        if header[..4] == [0, 1, 0, 1] && length == 4 {
            let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            if !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
            {
                addresses.push(SocketAddr::new(ip.into(), 443));
            }
        }
        offset += length;
    }
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(invalid());
    }
    Ok(addresses)
}

fn skip_name(data: &[u8], offset: &mut usize) -> NativeResult<()> {
    for _ in 0..128 {
        let byte = *data
            .get(*offset)
            .ok_or_else(|| dns_error("truncated name"))?;
        *offset += 1;
        match byte {
            0 => return Ok(()),
            0xc0..=0xff => {
                let low = *data
                    .get(*offset)
                    .ok_or_else(|| dns_error("truncated pointer"))?;
                let pointer = (((byte & 63) as usize) << 8) | low as usize;
                if pointer >= data.len() {
                    return Err(dns_error("invalid pointer"));
                }
                *offset += 1;
                return Ok(());
            }
            1..=63 => {
                *offset += byte as usize;
                if *offset > data.len() {
                    return Err(dns_error("truncated label"));
                }
            }
            _ => return Err(dns_error("invalid label")),
        }
    }
    Err(dns_error("name exceeds limit"))
}

fn dns_error(error: impl std::fmt::Display) -> NativeError {
    NativeError::new(
        "guest_hole_dns_failed",
        "The recovery tunnel could not resolve the Proton API",
    )
    .with_source(error)
    .retryable(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_bounded_a_answers_and_rejects_malformed_or_unrelated_replies() {
        let mut response = query(42);
        response[2] = 0x81;
        response[3] = 0x80;
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7]);
        assert_eq!(
            parse(&response, 42).unwrap(),
            vec!["203.0.113.7:443".parse().unwrap()]
        );
        assert!(parse(&response, 43).is_err());
        for length in 0..response.len() {
            assert!(parse(&response[..length], 42).is_err());
        }
        response[2] |= 2;
        assert!(parse(&response, 42).is_err());
    }
}
