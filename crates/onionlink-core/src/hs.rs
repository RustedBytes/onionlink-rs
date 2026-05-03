use log::{debug, info, warn};
use rand::seq::SliceRandom;

use crate::circuit::{
    begin_dir_get_via, connect_guard_circuit, extend_unless_same, Circuit, RelayMessage,
};
use crate::crypto::{
    aes_ctr_crypt, ct_equal, random_bytes, relay_body_len, sha3_256, shake256, tor_mac,
    x25519_public_from_private, x25519_shared, DigestKind, RelayCrypto,
};
use crate::directory::{
    candidate_rendezvous_relays, link_spec_ipv4, parse_link_specifiers, relay_link_specifiers,
    relay_usable_rendezvous, same_relay, select_hsdirs, serialize_link_specifiers, HsPeriodKeys,
    LinkSpecifier, Relay,
};
use crate::error::{ensure, err, Result};
use crate::tor::{
    K_RELAY_HEADER_LEN, K_RELAY_PAYLOAD_LEN, RELAY_BEGIN, RELAY_CONNECTED, RELAY_DATA, RELAY_END,
    RELAY_ESTABLISH_RENDEZVOUS, RELAY_INTRODUCE1, RELAY_INTRODUCE_ACK, RELAY_RENDEZVOUS2,
    RELAY_RENDEZVOUS_ESTABLISHED, RELAY_SENDME,
};
use crate::util::{
    base64_decode, base64_encode_unpadded, from_string, put_u16, put_u64, read_u16, split_ws,
    to_string_lossy, Bytes,
};
use crate::{Consensus, Options};

const K_HS_PROTO: &str = "tor-hs-ntor-curve25519-sha3-256-1";

pub fn extract_pem_message(text: &str, begin_label: &str, end_label: &str) -> Result<String> {
    let b = text
        .find(begin_label)
        .ok_or_else(|| crate::Error::new("PEM begin marker not found"))?;
    let after_begin = text[b..]
        .find('\n')
        .map(|idx| b + idx)
        .ok_or_else(|| crate::Error::new("bad PEM begin line"))?;
    let e = text[after_begin..]
        .find(end_label)
        .map(|idx| after_begin + idx)
        .ok_or_else(|| crate::Error::new("PEM end marker not found"))?;
    Ok(text[after_begin + 1..e].to_string())
}

pub fn parse_ed25519_cert_subject(pem: &str) -> Result<Bytes> {
    let cert = base64_decode(&extract_pem_message(
        pem,
        "-----BEGIN ED25519 CERT-----",
        "-----END ED25519 CERT-----",
    )?)?;
    ensure(
        cert.len() >= 1 + 1 + 4 + 1 + 32 + 1 + 64,
        "short ed25519 cert",
    )?;
    ensure(cert[0] == 1, "unsupported ed25519 cert version")?;
    Ok(cert[7..39].to_vec())
}

pub fn decrypt_descriptor_layer(
    ciphertext: &[u8],
    secret_data: &[u8],
    subcredential: &[u8],
    revision: u64,
    constant: &str,
) -> Result<Bytes> {
    ensure(
        ciphertext.len() >= 16 + 32,
        "descriptor ciphertext too short",
    )?;
    let salt = &ciphertext[..16];
    let enc = &ciphertext[16..ciphertext.len() - 32];
    let mac = &ciphertext[ciphertext.len() - 32..];
    let mut secret_input = secret_data.to_vec();
    secret_input.extend_from_slice(subcredential);
    put_u64(&mut secret_input, revision);
    let mut kdf_in = secret_input;
    kdf_in.extend_from_slice(salt);
    kdf_in.extend_from_slice(constant.as_bytes());
    let keys = shake256(&kdf_in, 32 + 16 + 32);
    let secret_key = &keys[..32];
    let secret_iv = &keys[32..48];
    let mac_key = &keys[48..];
    let mut mac_in = Bytes::new();
    put_u64(&mut mac_in, mac_key.len() as u64);
    mac_in.extend_from_slice(mac_key);
    put_u64(&mut mac_in, salt.len() as u64);
    mac_in.extend_from_slice(salt);
    mac_in.extend_from_slice(enc);
    ensure(
        ct_equal(mac, &sha3_256(&mac_in)),
        "descriptor layer MAC mismatch",
    )?;
    let mut plain = aes_ctr_crypt(secret_key, enc, Some(secret_iv))?;
    while plain.last() == Some(&0) {
        plain.pop();
    }
    Ok(plain)
}

#[derive(Clone, Debug, Default)]
pub struct IntroductionPoint {
    pub links: Vec<LinkSpecifier>,
    pub ntor_key: Bytes,
    pub auth_key: Bytes,
    pub enc_key: Bytes,
}

#[derive(Clone, Debug, Default)]
pub struct HiddenServiceDescriptor {
    pub intros: Vec<IntroductionPoint>,
}

#[derive(Clone, Debug)]
pub struct DescriptorFetchResult {
    pub descriptor: HiddenServiceDescriptor,
    pub guard: Relay,
}

pub fn intro_relay_from_descriptor(intro: &IntroductionPoint) -> Result<Relay> {
    let hp = link_spec_ipv4(&intro.links)
        .ok_or_else(|| crate::Error::new("intro point lacks IPv4 link specifier"))?;
    let mut relay = Relay {
        nickname: "intro".to_string(),
        ip: hp.host,
        or_port: hp.port,
        ntor_key: intro.ntor_key.clone(),
        ..Relay::default()
    };
    for ls in &intro.links {
        if ls.spec_type == 2 && ls.data.len() == 20 {
            relay.rsa_id = ls.data.clone();
        } else if ls.spec_type == 3 && ls.data.len() == 32 {
            relay.ed_id = ls.data.clone();
        }
    }
    ensure(
        relay.rsa_id.len() == 20,
        "intro point lacks RSA identity link specifier",
    )?;
    ensure(
        relay.ed_id.len() == 32,
        "intro point lacks Ed25519 identity link specifier",
    )?;
    ensure(
        relay.ntor_key.len() == 32,
        "intro point lacks ntor onion key",
    )?;
    Ok(relay)
}

pub fn parse_inner_descriptor(plain: &str) -> Result<HiddenServiceDescriptor> {
    let lines: Vec<String> = plain
        .lines()
        .map(|line| line.strip_suffix('\r').unwrap_or(line).to_string())
        .collect();
    let mut desc = HiddenServiceDescriptor::default();
    let mut cur: Option<usize> = None;
    let mut i = 0usize;
    while i < lines.len() {
        let line = &lines[i];
        let parts = split_ws(line);
        if parts.is_empty() {
            i += 1;
            continue;
        }
        if parts[0] == "introduction-point" && parts.len() >= 2 {
            desc.intros.push(IntroductionPoint {
                links: parse_link_specifiers(&base64_decode(parts[1])?)?,
                ..IntroductionPoint::default()
            });
            cur = Some(desc.intros.len() - 1);
        } else if parts[0] == "onion-key" && parts.len() >= 3 && parts[1] == "ntor" {
            if let Some(idx) = cur {
                desc.intros[idx].ntor_key = base64_decode(parts[2])?;
            }
        } else if parts[0] == "enc-key" && parts.len() >= 3 && parts[1] == "ntor" {
            if let Some(idx) = cur {
                desc.intros[idx].enc_key = base64_decode(parts[2])?;
            }
        } else if parts[0] == "auth-key" {
            if let Some(idx) = cur {
                let mut pem = format!("{line}\n");
                let mut in_cert = false;
                i += 1;
                while i < lines.len() {
                    let cert_line = &lines[i];
                    pem.push_str(cert_line);
                    pem.push('\n');
                    if cert_line == "-----BEGIN ED25519 CERT-----" {
                        in_cert = true;
                    }
                    if cert_line == "-----END ED25519 CERT-----" {
                        break;
                    }
                    i += 1;
                }
                ensure(in_cert, "auth-key missing cert")?;
                desc.intros[idx].auth_key = parse_ed25519_cert_subject(&pem)?;
            }
        }
        i += 1;
    }
    desc.intros.retain(|intro| {
        intro.auth_key.len() == 32
            && intro.ntor_key.len() == 32
            && intro.enc_key.len() == 32
            && link_spec_ipv4(&intro.links).is_some()
    });
    ensure(
        !desc.intros.is_empty(),
        "descriptor has no usable introduction points",
    )?;
    Ok(desc)
}

pub fn decrypt_hs_descriptor(outer: &str, keys: &HsPeriodKeys) -> Result<HiddenServiceDescriptor> {
    let mut revision = 0u64;
    let mut super_pem = String::new();
    let mut in_super = false;
    for raw_line in outer.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let parts = split_ws(line);
        if parts.len() >= 2 && parts[0] == "revision-counter" {
            revision = parts[1].parse()?;
        }
        if line == "-----BEGIN MESSAGE-----" {
            in_super = true;
            super_pem.push_str(line);
            super_pem.push('\n');
            continue;
        }
        if in_super {
            super_pem.push_str(line);
            super_pem.push('\n');
            if line == "-----END MESSAGE-----" {
                in_super = false;
            }
        }
    }
    ensure(
        revision != 0 || outer.contains("revision-counter 0"),
        "descriptor missing revision-counter",
    )?;
    ensure(
        !super_pem.is_empty(),
        "descriptor missing superencrypted blob",
    )?;
    let super_cipher = base64_decode(&extract_pem_message(
        &super_pem,
        "-----BEGIN MESSAGE-----",
        "-----END MESSAGE-----",
    )?)?;
    let first_plain = decrypt_descriptor_layer(
        &super_cipher,
        &keys.blinded,
        &keys.subcredential,
        revision,
        "hsdir-superencrypted-data",
    )?;
    let first = to_string_lossy(&first_plain);
    let inner_pem =
        extract_pem_message(&first, "-----BEGIN MESSAGE-----", "-----END MESSAGE-----")?;
    let inner_cipher = base64_decode(&inner_pem)?;
    let second_plain = decrypt_descriptor_layer(
        &inner_cipher,
        &keys.blinded,
        &keys.subcredential,
        revision,
        "hsdir-encrypted-data",
    )?;
    parse_inner_descriptor(&to_string_lossy(&second_plain))
}

#[derive(Clone, Debug, Default)]
pub struct HsNtorState {
    pub x: Bytes,
    pub x_pub: Bytes,
    pub b: Bytes,
    pub auth_key: Bytes,
    pub bx: Bytes,
    pub ntor_key_seed: Bytes,
}

#[derive(Clone, Debug, Default)]
pub struct HsIntroPayload {
    pub body: Bytes,
    pub state: HsNtorState,
}

pub fn build_introduce1(
    intro: &IntroductionPoint,
    rp: &Relay,
    rend_cookie: &[u8],
    keys: &HsPeriodKeys,
) -> Result<HsIntroPayload> {
    ensure(rend_cookie.len() == 20, "bad rendezvous cookie")?;
    ensure(rp.ntor_key.len() == 32, "rendezvous relay missing ntor key")?;
    let mut header = vec![0; 20];
    header.push(2);
    put_u16(&mut header, 32);
    header.extend_from_slice(&intro.auth_key);
    header.push(0);

    let mut plain = rend_cookie.to_vec();
    plain.push(0);
    plain.push(1);
    put_u16(&mut plain, 32);
    plain.extend_from_slice(&rp.ntor_key);
    let rp_lspec = serialize_link_specifiers(&relay_link_specifiers(rp)?)?;
    plain.extend_from_slice(&rp_lspec);
    if plain.len() < 246 {
        plain.resize(246, 0);
    }

    let mut st = HsNtorState::default();
    st.x = random_bytes(32);
    st.x_pub = x25519_public_from_private(&st.x)?;
    st.b = intro.enc_key.clone();
    st.auth_key = intro.auth_key.clone();
    st.bx = x25519_shared(&st.x, &st.b)?;

    let proto = from_string(K_HS_PROTO);
    let mut intro_secret = st.bx.clone();
    intro_secret.extend_from_slice(&intro.auth_key);
    intro_secret.extend_from_slice(&st.x_pub);
    intro_secret.extend_from_slice(&st.b);
    intro_secret.extend_from_slice(&proto);
    let mut info = from_string(format!("{K_HS_PROTO}:hs_key_expand"));
    info.extend_from_slice(&keys.subcredential);
    let mut kdf_in = intro_secret;
    kdf_in.extend_from_slice(format!("{K_HS_PROTO}:hs_key_extract").as_bytes());
    kdf_in.extend_from_slice(&info);
    let hs_keys = shake256(&kdf_in, 64);
    let enc_key = &hs_keys[..32];
    let mac_key = &hs_keys[32..];
    let encrypted = aes_ctr_crypt(enc_key, &plain, None)?;

    let mut mac_msg = header.clone();
    mac_msg.extend_from_slice(&st.x_pub);
    mac_msg.extend_from_slice(&encrypted);
    let mac = tor_mac(mac_key, &mac_msg);

    let mut body = header;
    body.extend_from_slice(&st.x_pub);
    body.extend_from_slice(&encrypted);
    body.extend_from_slice(&mac);
    Ok(HsIntroPayload { body, state: st })
}

pub fn finish_hs_ntor(st: &mut HsNtorState, handshake_info: &[u8]) -> Result<RelayCrypto> {
    ensure(
        handshake_info.len() >= 64,
        "RENDEZVOUS2 handshake too short",
    )?;
    let y = &handshake_info[..32];
    let auth = &handshake_info[32..64];
    let yx = x25519_shared(&st.x, y)?;
    let proto = from_string(K_HS_PROTO);
    let mut secret = yx;
    secret.extend_from_slice(&st.bx);
    secret.extend_from_slice(&st.auth_key);
    secret.extend_from_slice(&st.b);
    secret.extend_from_slice(&st.x_pub);
    secret.extend_from_slice(y);
    secret.extend_from_slice(&proto);
    let ntor_key_seed = tor_mac(&secret, format!("{K_HS_PROTO}:hs_key_extract").as_bytes());
    let verify = tor_mac(&secret, format!("{K_HS_PROTO}:hs_verify").as_bytes());
    let mut auth_input = verify;
    auth_input.extend_from_slice(&st.auth_key);
    auth_input.extend_from_slice(&st.b);
    auth_input.extend_from_slice(y);
    auth_input.extend_from_slice(&st.x_pub);
    auth_input.extend_from_slice(&proto);
    auth_input.extend_from_slice(b"Server");
    let expected = tor_mac(&auth_input, format!("{K_HS_PROTO}:hs_mac").as_bytes());
    ensure(
        ct_equal(auth, &expected),
        "RENDEZVOUS2 hs-ntor auth mismatch",
    )?;
    st.ntor_key_seed = ntor_key_seed.clone();
    let mut kdf_in = ntor_key_seed;
    kdf_in.extend_from_slice(format!("{K_HS_PROTO}:hs_key_expand").as_bytes());
    let k = shake256(&kdf_in, 128);
    Ok(RelayCrypto::new(
        &k[..32],
        &k[32..64],
        &k[64..96],
        &k[96..128],
        DigestKind::Sha3,
    ))
}

pub struct RendezvousStream {
    circ: Circuit,
    hs: RelayCrypto,
}

impl RendezvousStream {
    pub fn new(circ: Circuit, hs_crypto: RelayCrypto) -> Self {
        Self {
            circ,
            hs: hs_crypto,
        }
    }

    pub fn begin(&mut self, stream_id: u16, port: u16) -> Result<()> {
        let mut target = from_string(format!(":{port}"));
        target.push(0);
        self.send_hs(RELAY_BEGIN, stream_id, &target)?;
        loop {
            let m = self.recv_hs()?;
            if m.stream_id != stream_id {
                continue;
            }
            if m.cmd == RELAY_CONNECTED {
                return Ok(());
            }
            if m.cmd == RELAY_END {
                return err("onion service stream ended before CONNECTED");
            }
        }
    }

    pub fn send_data(&mut self, stream_id: u16, data: &[u8]) -> Result<()> {
        for chunk in data.chunks(K_RELAY_PAYLOAD_LEN) {
            self.send_hs(RELAY_DATA, stream_id, chunk)?;
        }
        Ok(())
    }

    pub fn read_until_end(&mut self, stream_id: u16, limit: usize) -> Result<Bytes> {
        let mut out = Bytes::new();
        let mut circ_window = 1000;
        let mut stream_window = 500;
        loop {
            let m = self.recv_hs()?;
            if m.stream_id != stream_id {
                continue;
            }
            if m.cmd == RELAY_DATA {
                out.extend_from_slice(&m.data);
                circ_window -= 1;
                if circ_window <= 900 {
                    self.send_hs(RELAY_SENDME, 0, &[0, 0, 0])?;
                    circ_window += 100;
                }
                stream_window -= 1;
                if stream_window <= 450 {
                    self.send_hs(RELAY_SENDME, stream_id, &[])?;
                    stream_window += 50;
                }
                if out.len() > limit {
                    return err("stream response too large");
                }
            } else if m.cmd == RELAY_END {
                break;
            }
        }
        Ok(out)
    }

    pub fn end(&mut self, stream_id: u16) -> Result<()> {
        self.send_hs(RELAY_END, stream_id, &[6])
    }

    fn send_hs(&mut self, cmd: u8, stream_id: u16, data: &[u8]) -> Result<()> {
        let body = self.hs.encrypt_relay(cmd, stream_id, data)?;
        self.circ.send_raw_body(&body)
    }

    fn recv_hs(&mut self) -> Result<RelayMessage> {
        loop {
            let rp_plain = self.circ.recv_raw_body()?;
            if let Some(body) = self.hs.decrypt_recognized(&rp_plain)? {
                let len = relay_body_len(&body)?;
                ensure(
                    K_RELAY_HEADER_LEN + len <= body.len(),
                    "relay length too large",
                )?;
                return Ok(RelayMessage {
                    cmd: body[0],
                    stream_id: read_u16(&body, 3)?,
                    data: body[K_RELAY_HEADER_LEN..K_RELAY_HEADER_LEN + len].to_vec(),
                });
            }
        }
    }
}

pub fn fetch_hidden_service_descriptor(
    consensus: &Consensus,
    keys: &HsPeriodKeys,
    timeout_ms: i32,
    _verbose: bool,
) -> Result<DescriptorFetchResult> {
    let mut srvs = Vec::new();
    if !consensus.shared_rand_current.is_empty() {
        srvs.push(consensus.shared_rand_current.clone());
    }
    if !consensus.shared_rand_previous.is_empty() {
        srvs.push(consensus.shared_rand_previous.clone());
    }
    ensure(!srvs.is_empty(), "consensus has no shared-rand values")?;
    let blinded_b64 = base64_encode_unpadded(&keys.blinded);
    let path = format!("/tor/hs/3/{blinded_b64}");
    let mut last_error = String::new();
    let guards = candidate_rendezvous_relays(consensus)?;
    for srv in srvs {
        let mut hsdirs = select_hsdirs(
            consensus,
            &keys.blinded,
            &srv,
            keys.period_num,
            keys.period_len,
        )?;
        hsdirs.shuffle(&mut rand::thread_rng());
        let mut guard_pos = 0usize;
        for hsdir in hsdirs {
            let result: Result<DescriptorFetchResult> = (|| {
                info!("fetching descriptor from HSDir {}", hsdir.nickname);
                let mut guard = None;
                for tries in 0..guards.len() {
                    let candidate = &guards[(guard_pos + tries) % guards.len()];
                    if candidate.ed_id != hsdir.ed_id {
                        guard = Some(candidate.clone());
                        guard_pos = (guard_pos + tries + 1) % guards.len();
                        break;
                    }
                }
                let guard = guard
                    .ok_or_else(|| crate::Error::new("no guard available for HSDir request"))?;
                let body = begin_dir_get_via(&guard, &hsdir, &path, timeout_ms)?;
                Ok(DescriptorFetchResult {
                    descriptor: decrypt_hs_descriptor(&to_string_lossy(&body), keys)?,
                    guard,
                })
            })();
            match result {
                Ok(desc) => return Ok(desc),
                Err(e) => {
                    last_error = e.to_string();
                    debug!(
                        "descriptor fetch from HSDir {} failed: {}",
                        hsdir.nickname, last_error
                    );
                }
            }
        }
    }
    err(format!(
        "failed to fetch/decrypt hidden service descriptor: {last_error}"
    ))
}

pub fn connect_onion_service(
    opt: &Options,
    consensus: &Consensus,
    desc: &HiddenServiceDescriptor,
    keys: &HsPeriodKeys,
    rp: &Relay,
    guard: &Relay,
) -> Result<RendezvousStream> {
    let rend_cookie = random_bytes(20);
    info!(
        "connecting to rendezvous point {} at {}:{} via guard {}",
        rp.nickname, rp.ip, rp.or_port, guard.nickname
    );
    let mut rp_circ = connect_guard_circuit(guard, opt.timeout_ms)?;
    extend_unless_same(&mut rp_circ, guard, rp)?;
    rp_circ.send_relay(RELAY_ESTABLISH_RENDEZVOUS, 0, &rend_cookie)?;
    loop {
        let m = rp_circ.recv_relay()?;
        if m.cmd == RELAY_RENDEZVOUS_ESTABLISHED {
            break;
        }
    }

    let mut intros = desc.intros.clone();
    intros.shuffle(&mut rand::thread_rng());
    let mut last_error = String::new();
    let mut ntor_state = HsNtorState::default();
    let mut introduced = false;
    for intro in intros {
        let attempt: Result<HsNtorState> = (|| {
            let intro_relay = intro_relay_from_descriptor(&intro)?;
            info!(
                "sending INTRODUCE1 via intro point {}:{}",
                intro_relay.ip, intro_relay.or_port
            );
            let payload = build_introduce1(&intro, rp, &rend_cookie, keys)?;
            let mut ip_circ = connect_guard_circuit(guard, opt.timeout_ms)?;
            extend_unless_same(&mut ip_circ, guard, &intro_relay)?;
            ip_circ.send_relay(RELAY_INTRODUCE1, 0, &payload.body)?;
            loop {
                let ack = ip_circ.recv_relay()?;
                if ack.cmd == RELAY_INTRODUCE_ACK {
                    ensure(ack.data.len() >= 2, "short INTRODUCE_ACK")?;
                    let status = read_u16(&ack.data, 0)?;
                    ensure(status == 0, format!("INTRODUCE_ACK status {status}"))?;
                    return Ok(payload.state);
                }
            }
        })();
        match attempt {
            Ok(state) => {
                ntor_state = state;
                introduced = true;
                break;
            }
            Err(e) => last_error = e.to_string(),
        }
    }
    ensure(
        introduced,
        format!("all introduction points failed: {last_error}"),
    )?;
    info!("waiting for RENDEZVOUS2");
    let hs_crypto = loop {
        let m = rp_circ.recv_relay()?;
        if m.cmd == RELAY_RENDEZVOUS2 {
            break finish_hs_ntor(&mut ntor_state, &m.data)?;
        }
    };
    let _ = consensus;
    Ok(RendezvousStream::new(rp_circ, hs_crypto))
}

pub fn connect_onion_service_with_retries(
    opt: &Options,
    consensus: &Consensus,
    desc: &HiddenServiceDescriptor,
    keys: &HsPeriodKeys,
    preferred_guards: &[Relay],
) -> Result<RendezvousStream> {
    let candidates = candidate_rendezvous_relays(consensus)?;
    let mut guards = Vec::<Relay>::new();
    for g in preferred_guards {
        if relay_usable_rendezvous(g) && !guards.iter().any(|existing| same_relay(existing, g)) {
            guards.push(g.clone());
        }
    }
    for g in &candidates {
        if !guards.iter().any(|existing| same_relay(existing, g)) {
            guards.push(g.clone());
        }
    }
    ensure(!guards.is_empty(), "no usable guard relays for rendezvous")?;
    let mut last_error = String::new();
    let rp_attempts = 12usize.min(candidates.len());
    let guard_attempts = 3usize.min(guards.len());
    for i in 0..rp_attempts {
        for j in 0..guard_attempts {
            let rp = &candidates[i];
            let guard = &guards[(i + j) % guards.len()];
            if same_relay(rp, guard) && guards.len() > 1 {
                continue;
            }
            match connect_onion_service(opt, consensus, desc, keys, rp, guard) {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    last_error = e.to_string();
                    warn!("rendezvous attempt failed: {last_error}");
                }
            }
        }
    }
    err(format!("all rendezvous attempts failed: {last_error}"))
}
