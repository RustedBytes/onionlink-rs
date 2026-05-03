use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use log::info;
use rand::RngCore;
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, ClientConfig, ClientConnection, ServerName, StreamOwned};

use crate::error::{ensure, Error, Result};
use crate::util::{
    duration_from_timeout_ms, put_u16, put_u32, read_u16, read_u32, resolve_socket_addrs, Bytes,
};

pub const K_CELL_BODY_LEN: usize = 509;
pub const K_RELAY_HEADER_LEN: usize = 11;
pub const K_RELAY_PAYLOAD_LEN: usize = K_CELL_BODY_LEN - K_RELAY_HEADER_LEN;

pub const CMD_RELAY: u8 = 3;
pub const CMD_DESTROY: u8 = 4;
pub const CMD_CREATE_FAST: u8 = 5;
pub const CMD_CREATED_FAST: u8 = 6;
pub const CMD_VERSIONS: u8 = 7;
pub const CMD_NETINFO: u8 = 8;
pub const CMD_RELAY_EARLY: u8 = 9;
#[allow(dead_code)]
pub const CMD_CREATE2: u8 = 10;
#[allow(dead_code)]
pub const CMD_CREATED2: u8 = 11;

pub const RELAY_BEGIN: u8 = 1;
pub const RELAY_DATA: u8 = 2;
pub const RELAY_END: u8 = 3;
pub const RELAY_CONNECTED: u8 = 4;
pub const RELAY_SENDME: u8 = 5;
pub const RELAY_BEGIN_DIR: u8 = 13;
pub const RELAY_EXTEND2: u8 = 14;
pub const RELAY_EXTENDED2: u8 = 15;
pub const RELAY_ESTABLISH_RENDEZVOUS: u8 = 33;
pub const RELAY_INTRODUCE1: u8 = 34;
pub const RELAY_RENDEZVOUS2: u8 = 37;
pub const RELAY_RENDEZVOUS_ESTABLISHED: u8 = 39;
pub const RELAY_INTRODUCE_ACK: u8 = 40;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cell {
    pub circ_id: u32,
    pub cmd: u8,
    pub body: Bytes,
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

pub fn connect_tcp(host: &str, port: u16, timeout_ms: i32) -> Result<TcpStream> {
    let timeout = duration_from_timeout_ms(timeout_ms)?;
    let addrs = resolve_socket_addrs(host, port)
        .map_err(|e| Error::new(format!("getaddrinfo failed for {host}: {e}")))?;
    let mut last_error = String::from("no address found");
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => {
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                return Ok(stream);
            }
            Err(e) => last_error = e.to_string(),
        }
    }
    Err(Error::new(format!(
        "tcp connect failed to {host}:{port}: {last_error}"
    )))
}

pub fn write_all_fd(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    stream.write_all(data)?;
    Ok(())
}

pub fn read_all_fd(stream: &mut TcpStream, limit: usize) -> Result<Bytes> {
    let mut out = Bytes::new();
    let mut buf = [0u8; 8192];
    while out.len() < limit {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

pub struct TorChannel {
    tls: StreamOwned<ClientConnection, TcpStream>,
    link_version: i32,
}

impl TorChannel {
    pub fn new(host: String, port: u16, timeout_ms: i32) -> Result<Self> {
        info!("opening Tor TLS channel to {host}:{port}");
        let tls = Self::init_tls(&host, port, timeout_ms)?;
        let mut ch = Self {
            tls,
            link_version: 4,
        };
        ch.negotiate()?;
        Ok(ch)
    }

    pub fn write_cell(&mut self, circ_id: u32, cmd: u8, body: &[u8]) -> Result<()> {
        let mut out = Bytes::new();
        if cmd == CMD_VERSIONS {
            put_u16(&mut out, 0);
            out.push(cmd);
            put_u16(&mut out, body.len() as u16);
            out.extend_from_slice(body);
        } else if cmd >= 128 {
            put_u32(&mut out, circ_id);
            out.push(cmd);
            put_u16(&mut out, body.len() as u16);
            out.extend_from_slice(body);
        } else {
            ensure(body.len() <= K_CELL_BODY_LEN, "fixed cell body too large")?;
            put_u32(&mut out, circ_id);
            out.push(cmd);
            out.extend_from_slice(body);
            out.resize(4 + 1 + K_CELL_BODY_LEN, 0);
        }
        self.tls.write_all(&out)?;
        self.tls.flush()?;
        Ok(())
    }

    pub fn read_cell(&mut self) -> Result<Cell> {
        self.read_cell_with_circ_len(4)
    }

    pub fn new_circ_id(&self) -> u32 {
        let mut id = rand::rngs::OsRng.next_u32() | 0x8000_0000;
        if id == 0 {
            id = 0x8000_0001;
        }
        id
    }

    fn init_tls(
        host: &str,
        port: u16,
        timeout_ms: i32,
    ) -> Result<StreamOwned<ClientConnection, TcpStream>> {
        let stream = connect_tcp(host, port, timeout_ms)?;
        let verifier = Arc::new(NoCertificateVerification);
        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let server_name = ServerName::try_from("ignored.invalid")
            .map_err(|_| Error::new("bad TLS server name"))?;
        let conn = ClientConnection::new(Arc::new(config), server_name)?;
        Ok(StreamOwned::new(conn, stream))
    }

    fn negotiate(&mut self) -> Result<()> {
        let mut versions = Bytes::new();
        put_u16(&mut versions, 4);
        put_u16(&mut versions, 5);
        let mut out = Bytes::new();
        put_u16(&mut out, 0);
        out.push(CMD_VERSIONS);
        put_u16(&mut out, versions.len() as u16);
        out.extend_from_slice(&versions);
        self.tls.write_all(&out)?;
        self.tls.flush()?;

        let v = self.read_cell_with_circ_len(2)?;
        ensure(v.cmd == CMD_VERSIONS, "first Tor cell was not VERSIONS")?;
        let mut best = 0;
        let mut i = 0;
        while i + 1 < v.body.len() {
            let peer = ((v.body[i] as i32) << 8) | v.body[i + 1] as i32;
            if (peer == 4 || peer == 5) && peer > best {
                best = peer;
            }
            i += 2;
        }
        ensure(best >= 4, "relay does not support link protocol 4+")?;
        self.link_version = best;
        info!("negotiated Tor link protocol v{best}");
        let mut got_netinfo = false;
        for _ in 0..16 {
            let c = self.read_cell()?;
            if c.cmd == CMD_NETINFO {
                got_netinfo = true;
                break;
            }
        }
        ensure(got_netinfo, "relay did not send NETINFO")?;
        self.send_netinfo()
    }

    fn send_netinfo(&mut self) -> Result<()> {
        let mut body = vec![0; K_CELL_BODY_LEN];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        body[0..4].copy_from_slice(&now.to_be_bytes());
        body[4] = 4;
        body[5] = 4;
        body[10] = 0;
        self.write_cell(0, CMD_NETINFO, &body)
    }

    fn read_cell_with_circ_len(&mut self, circ_len: usize) -> Result<Cell> {
        let mut header = vec![0; circ_len + 1];
        self.tls.read_exact(&mut header)?;
        let circ_id = if circ_len == 2 {
            read_u16(&header, 0)? as u32
        } else {
            read_u32(&header, 0)?
        };
        let cmd = header[circ_len];
        let variable = cmd == CMD_VERSIONS || cmd >= 128;
        let body = if variable {
            let mut lenb = [0u8; 2];
            self.tls.read_exact(&mut lenb)?;
            let len = read_u16(&lenb, 0)? as usize;
            let mut body = vec![0; len];
            self.tls.read_exact(&mut body)?;
            body
        } else {
            let mut body = vec![0; K_CELL_BODY_LEN];
            self.tls.read_exact(&mut body)?;
            body
        };
        Ok(Cell { circ_id, cmd, body })
    }
}
