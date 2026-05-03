use std::net::{Ipv4Addr, ToSocketAddrs};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::error::{ensure, err, Error, Result};

pub type Bytes = Vec<u8>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

pub fn split_ws(s: &str) -> Vec<&str> {
    s.split_whitespace().collect()
}

pub fn lower(s: impl AsRef<str>) -> String {
    s.as_ref().to_ascii_lowercase()
}

pub fn put_u16(b: &mut Bytes, v: u16) {
    b.extend_from_slice(&v.to_be_bytes());
}

pub fn put_u32(b: &mut Bytes, v: u32) {
    b.extend_from_slice(&v.to_be_bytes());
}

pub fn put_u64(b: &mut Bytes, v: u64) {
    b.extend_from_slice(&v.to_be_bytes());
}

pub fn read_u16(b: &[u8], off: usize) -> Result<u16> {
    ensure(off + 2 <= b.len(), "short u16")?;
    Ok(u16::from_be_bytes([b[off], b[off + 1]]))
}

pub fn read_u32(b: &[u8], off: usize) -> Result<u32> {
    ensure(off + 4 <= b.len(), "short u32")?;
    Ok(u32::from_be_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
    ]))
}

pub fn from_string(s: impl AsRef<str>) -> Bytes {
    s.as_ref().as_bytes().to_vec()
}

pub fn to_string_lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

pub fn hex(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(b.len() * 2);
    for &c in b {
        out.push(HEX[(c >> 4) as usize] as char);
        out.push(HEX[(c & 0x0f) as usize] as char);
    }
    out
}

pub fn parse_hostport(s: &str, default_port: u16) -> Result<HostPort> {
    ensure(!s.is_empty(), "empty host")?;
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| Error::new("bad IPv6 host:port"))?;
        let host = rest[..close].to_string();
        let after = &rest[close + 1..];
        let port = if after.is_empty() {
            default_port
        } else {
            ensure(after.starts_with(':'), "bad IPv6 port separator")?;
            after[1..].parse::<u16>()?
        };
        (host, port)
    } else if let Some(colon) = s.rfind(':') {
        if s[..colon].contains(':') {
            (s.to_string(), default_port)
        } else {
            (s[..colon].to_string(), s[colon + 1..].parse::<u16>()?)
        }
    } else {
        (s.to_string(), default_port)
    };
    ensure(!host.is_empty(), "missing host")?;
    ensure(port != 0, "missing port")?;
    Ok(HostPort { host, port })
}

pub fn base64_decode(s: &str) -> Result<Bytes> {
    let mut cleaned: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let padding = (4 - cleaned.len() % 4) % 4;
    for _ in 0..padding {
        cleaned.push('=');
    }
    Ok(STANDARD.decode(cleaned)?)
}

pub fn base64_encode_unpadded(b: &[u8]) -> String {
    let mut out = STANDARD.encode(b);
    while out.ends_with('=') {
        out.pop();
    }
    out
}

pub fn base32_decode_onion(s: &str) -> Result<Bytes> {
    let mut s = lower(s);
    if s.len() > 6 && s.ends_with(".onion") {
        s.truncate(s.len() - 6);
    }
    ensure(
        s.len() == 56,
        "v3 onion address must have 56 base32 characters",
    )?;
    let mut bits = 0;
    let mut acc = 0u32;
    let mut out = Bytes::new();
    for ch in s.bytes() {
        let v = match ch {
            b'a'..=b'z' => ch - b'a',
            b'2'..=b'7' => ch - b'2' + 26,
            _ => return err("invalid base32 character in onion address"),
        } as u32;
        acc = (acc << 5) | v;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    ensure(out.len() == 35, "invalid v3 onion address length")?;
    Ok(out)
}

pub fn duration_from_timeout_ms(timeout_ms: i32) -> Result<Duration> {
    ensure(timeout_ms >= 0, "timeout must be non-negative")?;
    Ok(Duration::from_millis(timeout_ms as u64))
}

pub fn resolve_socket_addrs(host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>> {
    let addrs: Vec<_> = (host, port).to_socket_addrs()?.collect();
    ensure(
        !addrs.is_empty(),
        format!("getaddrinfo failed for {host}: no address found"),
    )?;
    Ok(addrs)
}

pub fn ipv4_to_link_bytes(ip: &str, port: u16) -> Result<Bytes> {
    let addr: Ipv4Addr = ip
        .parse()
        .map_err(|_| Error::new("relay has non-IPv4 address"))?;
    let mut out = addr.octets().to_vec();
    put_u16(&mut out, port);
    Ok(out)
}
