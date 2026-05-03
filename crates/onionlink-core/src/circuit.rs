use log::info;

use crate::crypto::{
    ct_equal, hkdf_sha256_expand, hmac_sha256, kdf_tor, random_bytes, x25519_public_from_private,
    x25519_shared, DigestKind, RelayCrypto,
};
use crate::directory::{decode_http_body, same_relay};
use crate::directory::{relay_link_specifiers, serialize_link_specifiers, Relay};
use crate::error::{ensure, err, Result};
use crate::tor::{
    TorChannel, CMD_CREATED_FAST, CMD_CREATE_FAST, CMD_DESTROY, CMD_RELAY, CMD_RELAY_EARLY,
    K_CELL_BODY_LEN, K_RELAY_HEADER_LEN, K_RELAY_PAYLOAD_LEN, RELAY_BEGIN_DIR, RELAY_CONNECTED,
    RELAY_DATA, RELAY_END, RELAY_EXTEND2, RELAY_EXTENDED2, RELAY_SENDME,
};
use crate::util::{from_string, put_u16, read_u16, Bytes};

#[derive(Clone, Debug, Default)]
pub struct NtorState {
    pub x: Bytes,
    pub x_pub: Bytes,
    pub b: Bytes,
    pub id: Bytes,
    pub bx: Bytes,
}

pub fn build_ntor_onionskin(relay: &Relay, st: &mut NtorState) -> Result<Bytes> {
    ensure(
        relay.rsa_id.len() == 20,
        "relay missing RSA identity for ntor",
    )?;
    ensure(relay.ntor_key.len() == 32, "relay missing ntor key")?;
    st.x = random_bytes(32);
    st.x_pub = x25519_public_from_private(&st.x)?;
    st.b = relay.ntor_key.clone();
    st.id = relay.rsa_id.clone();
    st.bx = x25519_shared(&st.x, &st.b)?;
    let mut hdata = st.id.clone();
    hdata.extend_from_slice(&st.b);
    hdata.extend_from_slice(&st.x_pub);
    Ok(hdata)
}

pub fn finish_ntor(st: &NtorState, hdata: &[u8]) -> Result<RelayCrypto> {
    ensure(hdata.len() >= 64, "short ntor CREATED2 data")?;
    let y = &hdata[..32];
    let auth = &hdata[32..64];
    let yx = x25519_shared(&st.x, y)?;
    let proto = from_string("ntor-curve25519-sha256-1");
    let mut secret = yx;
    secret.extend_from_slice(&st.bx);
    secret.extend_from_slice(&st.id);
    secret.extend_from_slice(&st.b);
    secret.extend_from_slice(&st.x_pub);
    secret.extend_from_slice(y);
    secret.extend_from_slice(&proto);
    let t_key = from_string("ntor-curve25519-sha256-1:key_extract");
    let t_verify = from_string("ntor-curve25519-sha256-1:verify");
    let t_mac = from_string("ntor-curve25519-sha256-1:mac");
    let key_seed = hmac_sha256(&t_key, &secret)?;
    let verify = hmac_sha256(&t_verify, &secret)?;
    let mut auth_input = verify;
    auth_input.extend_from_slice(&st.id);
    auth_input.extend_from_slice(&st.b);
    auth_input.extend_from_slice(y);
    auth_input.extend_from_slice(&st.x_pub);
    auth_input.extend_from_slice(&proto);
    auth_input.extend_from_slice(b"Server");
    let expected = hmac_sha256(&t_mac, &auth_input)?;
    ensure(ct_equal(auth, &expected), "ntor auth mismatch")?;
    let k = hkdf_sha256_expand(&key_seed, b"ntor-curve25519-sha256-1:key_expand", 92)?;
    Ok(RelayCrypto::new(
        &k[0..20],
        &k[20..40],
        &k[40..56],
        &k[56..72],
        DigestKind::Sha1,
    ))
}

#[derive(Clone, Debug, Default)]
pub struct RelayMessage {
    pub cmd: u8,
    pub stream_id: u16,
    pub data: Bytes,
}

pub struct Circuit {
    ch: TorChannel,
    id: u32,
    hops: Vec<RelayCrypto>,
}

impl Circuit {
    pub fn create_fast(mut ch: TorChannel) -> Result<Self> {
        let id = ch.new_circ_id();
        info!("creating fast circuit {id}");
        let x = random_bytes(20);
        let mut body = x.clone();
        body.resize(K_CELL_BODY_LEN, 0);
        ch.write_cell(id, CMD_CREATE_FAST, &body)?;
        loop {
            let c = ch.read_cell()?;
            if c.circ_id != id {
                continue;
            }
            if c.cmd == CMD_DESTROY {
                return err("CREATE_FAST was destroyed");
            }
            ensure(
                c.cmd == CMD_CREATED_FAST,
                "unexpected cell while waiting for CREATED_FAST",
            )?;
            let y = &c.body[..20];
            let kh = &c.body[20..40];
            let mut k0 = x;
            k0.extend_from_slice(y);
            let k = kdf_tor(&k0, 92);
            ensure(ct_equal(kh, &k[..20]), "CREATE_FAST key hash mismatch")?;
            let rc = RelayCrypto::new(
                &k[20..40],
                &k[40..60],
                &k[60..76],
                &k[76..92],
                DigestKind::Sha1,
            );
            return Ok(Self {
                ch,
                id,
                hops: vec![rc],
            });
        }
    }

    pub fn send_relay(&mut self, cmd: u8, stream_id: u16, data: &[u8]) -> Result<()> {
        let hop_index = self.hops.len() - 1;
        self.send_relay_cell(CMD_RELAY, hop_index, cmd, stream_id, data)
    }

    pub fn recv_relay(&mut self) -> Result<RelayMessage> {
        loop {
            let c = self.ch.read_cell()?;
            if c.circ_id != self.id {
                continue;
            }
            if c.cmd == CMD_DESTROY {
                return err("circuit destroyed");
            }
            if c.cmd != CMD_RELAY {
                continue;
            }
            let mut body = c.body;
            for hop in &mut self.hops {
                body = hop.decrypt_body_only(&body)?;
                if hop.recognize_decrypted(&body) {
                    return parse_relay_body(&body);
                }
            }
        }
    }

    pub fn send_raw_body(&mut self, body: &[u8]) -> Result<()> {
        ensure(
            body.len() == K_CELL_BODY_LEN,
            "raw relay body must be one cell body",
        )?;
        let mut encrypted = body.to_vec();
        for hop in self.hops.iter_mut().rev() {
            encrypted = hop.encrypt_body_only(&encrypted)?;
        }
        self.ch.write_cell(self.id, CMD_RELAY, &encrypted)
    }

    pub fn recv_raw_body(&mut self) -> Result<Bytes> {
        loop {
            let c = self.ch.read_cell()?;
            if c.circ_id != self.id {
                continue;
            }
            if c.cmd == CMD_DESTROY {
                return err("rendezvous circuit destroyed");
            }
            if c.cmd == CMD_RELAY {
                let mut body = c.body;
                for hop in &mut self.hops {
                    body = hop.decrypt_body_only(&body)?;
                }
                return Ok(body);
            }
        }
    }

    pub fn extend_ntor(&mut self, relay: &Relay) -> Result<()> {
        info!(
            "extending circuit to relay {} at {}:{}",
            relay.nickname, relay.ip, relay.or_port
        );
        let mut st = NtorState::default();
        let hdata = build_ntor_onionskin(relay, &mut st)?;
        let lspec = serialize_link_specifiers(&relay_link_specifiers(relay)?)?;
        let mut data = lspec;
        put_u16(&mut data, 2);
        put_u16(&mut data, hdata.len() as u16);
        data.extend_from_slice(&hdata);
        let hop_index = self.hops.len() - 1;
        self.send_relay_cell(CMD_RELAY_EARLY, hop_index, RELAY_EXTEND2, 0, &data)?;
        loop {
            let m = self.recv_relay()?;
            if m.cmd == RELAY_EXTENDED2 {
                ensure(m.data.len() >= 2, "short EXTENDED2 body")?;
                let hlen = read_u16(&m.data, 0)? as usize;
                ensure(m.data.len() >= 2 + hlen, "truncated EXTENDED2 handshake")?;
                let created = &m.data[2..2 + hlen];
                self.hops.push(finish_ntor(&st, created)?);
                return Ok(());
            }
        }
    }

    fn send_relay_cell(
        &mut self,
        cell_cmd: u8,
        hop_index: usize,
        relay_cmd: u8,
        stream_id: u16,
        data: &[u8],
    ) -> Result<()> {
        ensure(hop_index < self.hops.len(), "bad hop index")?;
        let mut body = self.hops[hop_index].encrypt_relay(relay_cmd, stream_id, data)?;
        for i in (0..hop_index).rev() {
            body = self.hops[i].encrypt_body_only(&body)?;
        }
        self.ch.write_cell(self.id, cell_cmd, &body)
    }
}

pub fn parse_relay_body(body: &[u8]) -> Result<RelayMessage> {
    ensure(body.len() == K_CELL_BODY_LEN, "bad relay body")?;
    let len = read_u16(body, 9)? as usize;
    ensure(len <= K_RELAY_PAYLOAD_LEN, "relay length too large")?;
    Ok(RelayMessage {
        cmd: body[0],
        stream_id: read_u16(body, 3)?,
        data: body[K_RELAY_HEADER_LEN..K_RELAY_HEADER_LEN + len].to_vec(),
    })
}

pub fn begin_dir_get_via(
    guard: &Relay,
    target: &Relay,
    path: &str,
    timeout_ms: i32,
) -> Result<Bytes> {
    info!(
        "opening BEGIN_DIR request to {} via guard {}",
        target.nickname, guard.nickname
    );
    let ch = TorChannel::new(guard.ip.clone(), guard.or_port, timeout_ms)?;
    let mut circ = Circuit::create_fast(ch)?;
    circ.extend_ntor(target)?;
    circ.send_relay(RELAY_BEGIN_DIR, 1, &[])?;
    loop {
        let m = circ.recv_relay()?;
        if m.cmd == RELAY_CONNECTED && m.stream_id == 1 {
            break;
        }
        if m.cmd == RELAY_END && m.stream_id == 1 {
            return err(format!("BEGIN_DIR rejected by {}", target.nickname));
        }
    }
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {}\r\nUser-Agent: onionlink/0\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        target.ip
    );
    let rb = from_string(req);
    for chunk in rb.chunks(K_RELAY_PAYLOAD_LEN) {
        circ.send_relay(RELAY_DATA, 1, chunk)?;
    }
    let mut response = Bytes::new();
    let mut circ_window = 1000;
    let mut stream_window = 500;
    loop {
        let m = circ.recv_relay()?;
        if m.cmd == RELAY_DATA && m.stream_id == 1 {
            response.extend_from_slice(&m.data);
            circ_window -= 1;
            if circ_window <= 900 {
                circ.send_relay(RELAY_SENDME, 0, &[0, 0, 0])?;
                circ_window += 100;
            }
            stream_window -= 1;
            if stream_window <= 450 {
                circ.send_relay(RELAY_SENDME, 1, &[])?;
                stream_window += 50;
            }
        } else if m.cmd == RELAY_END && m.stream_id == 1 {
            break;
        }
        if response.len() > 8 * 1024 * 1024 {
            return err("BEGIN_DIR response too large");
        }
    }
    decode_http_body(&response)
}

pub fn connect_guard_circuit(guard: &Relay, timeout_ms: i32) -> Result<Circuit> {
    Circuit::create_fast(TorChannel::new(
        guard.ip.clone(),
        guard.or_port,
        timeout_ms,
    )?)
}

pub fn extend_unless_same(circ: &mut Circuit, guard: &Relay, target: &Relay) -> Result<()> {
    if !same_relay(guard, target) {
        circ.extend_ntor(target)?;
    }
    Ok(())
}
