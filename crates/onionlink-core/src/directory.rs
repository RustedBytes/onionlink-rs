use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use chrono::NaiveDateTime;
use log::{info, warn};

use crate::crypto::{ed25519_point_is_valid, ed25519_scalarmult_noclamp, sha256, sha3_256};
use crate::error::{ensure, err, Error, Result};
use crate::tor::{connect_tcp, read_all_fd, write_all_fd};
use crate::util::{
    base32_decode_onion, base64_decode, base64_encode_unpadded, from_string, hex,
    ipv4_to_link_bytes, lower, parse_hostport, put_u64, split_ws, to_string_lossy, Bytes, HostPort,
};

const K_BLIND_STRING: &str = "Derive temporary signing key";
const K_BLIND_BASE_POINT: &str =
    "(1511222134953540077250115140958853151145401269304185720604611328394984776\
2202, \
46316835694926478169428394003475163141307993866256225615783033603165251855\
960)";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Relay {
    pub nickname: String,
    pub ip: String,
    pub or_port: u16,
    pub dir_port: u16,
    pub rsa_id: Bytes,
    pub ed_id: Bytes,
    pub flags: BTreeSet<String>,
    pub proto: String,
    pub md_digest: String,
    pub ntor_key: Bytes,
}

impl Relay {
    pub fn has_flag(&self, flag: &str) -> bool {
        self.flags.contains(flag)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Consensus {
    pub valid_after: i64,
    pub fresh_until: i64,
    pub params: BTreeMap<String, i32>,
    pub shared_rand_current: Bytes,
    pub shared_rand_previous: Bytes,
    pub relays: Vec<Relay>,
}

impl Consensus {
    pub fn param(&self, name: &str, default: i32) -> i32 {
        self.params.get(name).copied().unwrap_or(default)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionAddress {
    pub pubkey: Bytes,
}

pub fn parse_onion_address(addr: &str) -> Result<OnionAddress> {
    let raw = base32_decode_onion(addr)?;
    let pubkey = raw[..32].to_vec();
    let checksum = &raw[32..34];
    let version = raw[34];
    ensure(version == 3, "only v3 onion addresses are supported")?;
    let mut check_input = from_string(".onion checksum");
    check_input.extend_from_slice(&pubkey);
    check_input.push(version);
    let expected = sha3_256(&check_input);
    ensure(
        checksum[0] == expected[0] && checksum[1] == expected[1],
        "bad onion checksum",
    )?;
    ensure(
        ed25519_point_is_valid(&pubkey),
        "onion ed25519 key is invalid",
    )?;
    Ok(OnionAddress { pubkey })
}

pub fn parse_time_utc(date: &str, time: &str) -> Result<i64> {
    let both = format!("{date} {time}");
    let dt = NaiveDateTime::parse_from_str(&both, "%Y-%m-%d %H:%M:%S")?;
    Ok(dt.and_utc().timestamp())
}

pub fn parse_consensus(doc: &str) -> Result<Consensus> {
    let mut c = Consensus::default();
    let mut cur: Option<usize> = None;
    for raw_line in doc.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        let parts = split_ws(line);
        if parts.is_empty() {
            continue;
        }
        match parts[0] {
            "valid-after" if parts.len() >= 3 => {
                c.valid_after = parse_time_utc(parts[1], parts[2])?;
            }
            "fresh-until" if parts.len() >= 3 => {
                c.fresh_until = parse_time_utc(parts[1], parts[2])?;
            }
            "params" => {
                for part in &parts[1..] {
                    if let Some(eq) = part.find('=') {
                        c.params
                            .insert(part[..eq].to_string(), part[eq + 1..].parse()?);
                    }
                }
            }
            "shared-rand-current-value" if parts.len() >= 3 => {
                c.shared_rand_current = base64_decode(parts[2])?;
            }
            "shared-rand-previous-value" if parts.len() >= 3 => {
                c.shared_rand_previous = base64_decode(parts[2])?;
            }
            "r" if parts.len() >= 8 => {
                let mut r = Relay {
                    nickname: parts[1].to_string(),
                    rsa_id: base64_decode(parts[2])?,
                    ..Relay::default()
                };
                if parts.len() >= 9 {
                    r.ip = parts[6].to_string();
                    r.or_port = parts[7].parse()?;
                    r.dir_port = parts[8].parse()?;
                } else {
                    r.ip = parts[5].to_string();
                    r.or_port = parts[6].parse()?;
                    r.dir_port = parts[7].parse()?;
                }
                c.relays.push(r);
                cur = Some(c.relays.len() - 1);
            }
            "s" => {
                if let Some(i) = cur {
                    for part in &parts[1..] {
                        c.relays[i].flags.insert((*part).to_string());
                    }
                }
            }
            "pr" => {
                if let Some(i) = cur {
                    c.relays[i].proto = if line.len() > 3 {
                        line[3..].to_string()
                    } else {
                        String::new()
                    };
                }
            }
            "id" if parts.len() >= 3 && parts[1] == "ed25519" && parts[2] != "none" => {
                if let Some(i) = cur {
                    c.relays[i].ed_id = base64_decode(parts[2])?;
                }
            }
            "m" if parts.len() >= 2 => {
                if let Some(i) = cur {
                    let mut digest = parts[1].to_string();
                    for part in &parts[1..] {
                        if let Some(eq) = part.find("sha256=") {
                            digest = part[eq + 7..].to_string();
                        }
                    }
                    c.relays[i].md_digest = digest;
                }
            }
            _ => {}
        }
    }
    ensure(c.valid_after != 0, "consensus missing valid-after")?;
    ensure(!c.relays.is_empty(), "consensus has no relays")?;
    Ok(c)
}

pub fn read_file_bytes(path: &str) -> Result<Bytes> {
    std::fs::read(path).map_err(|_| Error::new(format!("failed to open {path}")))
}

pub fn read_file_string(path: &str) -> Result<String> {
    Ok(to_string_lossy(&read_file_bytes(path)?))
}

pub fn parse_microdescriptor_into(mut relay: Relay, doc: &str) -> Result<Relay> {
    for raw_line in doc.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let parts = split_ws(line);
        if parts.is_empty() {
            continue;
        }
        if parts[0] == "ntor-onion-key" && parts.len() >= 2 {
            relay.ntor_key = base64_decode(parts[1])?;
        } else if parts[0] == "id"
            && parts.len() >= 3
            && parts[1] == "ed25519"
            && relay.ed_id.is_empty()
        {
            relay.ed_id = base64_decode(parts[2])?;
        }
    }
    ensure(
        relay.ntor_key.len() == 32,
        format!(
            "microdescriptor missing ntor-onion-key for {}",
            relay.nickname
        ),
    )?;
    Ok(relay)
}

pub fn split_microdescriptors(raw: &str) -> Vec<String> {
    let Some(mut start) = raw.find("onion-key\n") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    while start < raw.len() {
        if let Some(next_rel) = raw[start + 1..].find("\nonion-key\n") {
            let next = start + 1 + next_rel;
            out.push(raw[start..next + 1].to_string());
            start = next + 1;
        } else {
            out.push(raw[start..].to_string());
            break;
        }
    }
    out
}

#[derive(Clone, Debug, Default)]
pub struct MicrodescriptorFields {
    pub ed_id: Bytes,
    pub ntor_key: Bytes,
}

pub fn parse_microdescriptor_fields(doc: &str) -> Result<MicrodescriptorFields> {
    let mut fields = MicrodescriptorFields::default();
    for raw_line in doc.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let parts = split_ws(line);
        if parts.is_empty() {
            continue;
        }
        if parts[0] == "ntor-onion-key" && parts.len() >= 2 {
            fields.ntor_key = base64_decode(parts[1])?;
        } else if parts[0] == "id" && parts.len() >= 3 && parts[1] == "ed25519" {
            fields.ed_id = base64_decode(parts[2])?;
        }
    }
    Ok(fields)
}

pub fn index_microdescriptors(raw: &str) -> Result<BTreeMap<String, MicrodescriptorFields>> {
    let mut out = BTreeMap::new();
    for doc in split_microdescriptors(raw) {
        out.insert(
            base64_encode_unpadded(&sha256(doc.as_bytes())),
            parse_microdescriptor_fields(&doc)?,
        );
    }
    Ok(out)
}

pub fn relay_usable_dir(r: &Relay) -> bool {
    r.or_port != 0 && r.has_flag("Running") && r.has_flag("Valid")
}

pub fn relay_usable_hsdir(r: &Relay) -> bool {
    relay_usable_dir(r)
        && r.has_flag("HSDir")
        && !r.has_flag("NoEdConsensus")
        && r.ed_id.len() == 32
}

pub fn relay_usable_rendezvous(r: &Relay) -> bool {
    relay_usable_dir(r)
        && !r.has_flag("MiddleOnly")
        && !r.has_flag("NoEdConsensus")
        && r.rsa_id.len() == 20
        && r.ed_id.len() == 32
        && r.ntor_key.len() == 32
}

pub fn candidate_rendezvous_relays(c: &Consensus) -> Result<Vec<Relay>> {
    let mut out: Vec<Relay> = c
        .relays
        .iter()
        .filter(|r| relay_usable_rendezvous(r))
        .cloned()
        .collect();
    ensure(!out.is_empty(), "no usable rendezvous relays in consensus")?;
    use rand::seq::SliceRandom;
    out.shuffle(&mut rand::thread_rng());
    Ok(out)
}

pub fn current_period_num(c: &Consensus, period_len_min: i32) -> u64 {
    let mut voting_interval = 60;
    if c.fresh_until > c.valid_after {
        voting_interval = ((c.fresh_until - c.valid_after) / 60) as i32;
        if voting_interval <= 0 {
            voting_interval = 60;
        }
    }
    let minutes = (c.valid_after / 60).max(0) as u64;
    let offset = (12 * voting_interval) as u64;
    if minutes < offset {
        return 0;
    }
    (minutes - offset) / period_len_min as u64
}

pub fn blind_onion_key(pubkey: &[u8], period_num: u64, period_len: u64) -> Result<Bytes> {
    ensure(pubkey.len() == 32, "bad onion pubkey")?;
    let mut nonce = from_string("key-blind");
    put_u64(&mut nonce, period_num);
    put_u64(&mut nonce, period_len);
    let mut input = from_string(K_BLIND_STRING);
    input.push(0);
    input.extend_from_slice(pubkey);
    input.extend_from_slice(K_BLIND_BASE_POINT.as_bytes());
    input.extend_from_slice(&nonce);
    let mut h = sha3_256(&input);
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;
    ed25519_scalarmult_noclamp(&h, pubkey)
}

pub fn onion_subcredential(pubkey: &[u8], blinded: &[u8]) -> Bytes {
    let mut cred_in = from_string("credential");
    cred_in.extend_from_slice(pubkey);
    let cred = sha3_256(&cred_in);
    let mut sub_in = from_string("subcredential");
    sub_in.extend_from_slice(&cred);
    sub_in.extend_from_slice(blinded);
    sha3_256(&sub_in)
}

#[derive(Clone, Debug, Default)]
pub struct HsPeriodKeys {
    pub period_num: u64,
    pub period_len: i32,
    pub blinded: Bytes,
    pub subcredential: Bytes,
}

pub fn derive_hs_period_keys(c: &Consensus, addr: &OnionAddress) -> Result<HsPeriodKeys> {
    let period_len = c.param("hsdir-interval", 1440);
    let period_num = current_period_num(c, period_len);
    let blinded = blind_onion_key(&addr.pubkey, period_num, period_len as u64)?;
    let subcredential = onion_subcredential(&addr.pubkey, &blinded);
    Ok(HsPeriodKeys {
        period_num,
        period_len,
        blinded,
        subcredential,
    })
}

pub fn select_hsdirs(
    c: &Consensus,
    blinded: &[u8],
    srv: &[u8],
    period_num: u64,
    period_len: i32,
) -> Result<Vec<Relay>> {
    ensure(
        srv.len() == 32,
        "shared random value missing from consensus",
    )?;
    #[derive(Clone)]
    struct Indexed {
        idx: Bytes,
        relay: Relay,
    }
    let mut ring = Vec::<Indexed>::new();
    for r in &c.relays {
        if !relay_usable_hsdir(r) {
            continue;
        }
        let mut input = from_string("node-idx");
        input.extend_from_slice(&r.ed_id);
        input.extend_from_slice(srv);
        put_u64(&mut input, period_num);
        put_u64(&mut input, period_len as u64);
        ring.push(Indexed {
            idx: sha3_256(&input),
            relay: r.clone(),
        });
    }
    ensure(!ring.is_empty(), "no usable HSDir relays in consensus")?;
    ring.sort_by(|a, b| a.idx.cmp(&b.idx));

    let replicas = c.param("hsdir_n_replicas", 2).clamp(1, 16);
    let spread = c.param("hsdir_spread_fetch", 3).clamp(1, 128);
    let mut out = Vec::new();
    let mut used = BTreeSet::new();
    for rep in 1..=replicas {
        let mut sin = from_string("store-at-idx");
        sin.extend_from_slice(blinded);
        put_u64(&mut sin, rep as u64);
        put_u64(&mut sin, period_len as u64);
        put_u64(&mut sin, period_num);
        let service_idx = sha3_256(&sin);
        let start = ring
            .binary_search_by(|indexed| indexed.idx.cmp(&service_idx))
            .unwrap_or_else(|pos| pos);
        let mut n = 0usize;
        let mut seen = 0usize;
        while seen < ring.len() && n < spread as usize {
            let relay = &ring[(start + seen) % ring.len()].relay;
            let key = hex(&relay.ed_id);
            if used.insert(key) {
                out.push(relay.clone());
                n += 1;
            }
            seen += 1;
        }
    }
    Ok(out)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkSpecifier {
    pub spec_type: u8,
    pub data: Bytes,
}

pub fn parse_link_specifiers(encoded: &[u8]) -> Result<Vec<LinkSpecifier>> {
    ensure(!encoded.is_empty(), "empty link specifier block")?;
    let mut pos = 0usize;
    let n = encoded[pos];
    pos += 1;
    let mut specs = Vec::new();
    for _ in 0..n {
        ensure(pos + 2 <= encoded.len(), "truncated link specifier")?;
        let spec_type = encoded[pos];
        let len = encoded[pos + 1] as usize;
        pos += 2;
        ensure(pos + len <= encoded.len(), "truncated link specifier body")?;
        specs.push(LinkSpecifier {
            spec_type,
            data: encoded[pos..pos + len].to_vec(),
        });
        pos += len;
    }
    Ok(specs)
}

pub fn serialize_link_specifiers(specs: &[LinkSpecifier]) -> Result<Bytes> {
    ensure(specs.len() <= 255, "too many link specifiers")?;
    let mut out = Bytes::new();
    out.push(specs.len() as u8);
    for spec in specs {
        ensure(spec.data.len() <= 255, "link specifier too large")?;
        out.push(spec.spec_type);
        out.push(spec.data.len() as u8);
        out.extend_from_slice(&spec.data);
    }
    Ok(out)
}

pub fn link_spec_ipv4(specs: &[LinkSpecifier]) -> Option<HostPort> {
    for spec in specs {
        if spec.spec_type == 0 && spec.data.len() == 6 {
            let host = format!(
                "{}.{}.{}.{}",
                spec.data[0], spec.data[1], spec.data[2], spec.data[3]
            );
            let port = ((spec.data[4] as u16) << 8) | spec.data[5] as u16;
            return Some(HostPort { host, port });
        }
    }
    None
}

pub fn relay_link_specifiers(r: &Relay) -> Result<Vec<LinkSpecifier>> {
    Ok(vec![
        LinkSpecifier {
            spec_type: 0,
            data: ipv4_to_link_bytes(&r.ip, r.or_port)?,
        },
        LinkSpecifier {
            spec_type: 2,
            data: r.rsa_id.clone(),
        },
        LinkSpecifier {
            spec_type: 3,
            data: r.ed_id.clone(),
        },
    ])
}

pub fn same_relay(a: &Relay, b: &Relay) -> bool {
    if !a.ed_id.is_empty() && !b.ed_id.is_empty() && a.ed_id == b.ed_id {
        return true;
    }
    if !a.rsa_id.is_empty() && !b.rsa_id.is_empty() && a.rsa_id == b.rsa_id {
        return true;
    }
    !a.ip.is_empty() && a.or_port != 0 && a.ip == b.ip && a.or_port == b.or_port
}

pub fn decode_http_body(response: &[u8]) -> Result<Bytes> {
    let s = to_string_lossy(response);
    let Some(pos) = s.find("\r\n\r\n") else {
        return err("malformed HTTP response");
    };
    let head = &s[..pos];
    let body = &response[pos + 4..];
    ensure(
        head.contains(" 200 "),
        format!(
            "HTTP request failed: {}",
            head.split("\r\n").next().unwrap_or(head)
        ),
    )?;
    if lower(head).contains("transfer-encoding: chunked") {
        let mut decoded = Bytes::new();
        let mut p = 0usize;
        while p < body.len() {
            let mut line_end = p;
            while line_end + 1 < body.len()
                && !(body[line_end] == b'\r' && body[line_end + 1] == b'\n')
            {
                line_end += 1;
            }
            ensure(line_end + 1 < body.len(), "bad chunked response")?;
            let len_s = std::str::from_utf8(&body[p..line_end])?
                .split(';')
                .next()
                .unwrap_or("")
                .trim();
            let chunk_len = usize::from_str_radix(len_s, 16)?;
            p = line_end + 2;
            if chunk_len == 0 {
                break;
            }
            ensure(p + chunk_len <= body.len(), "truncated chunk")?;
            decoded.extend_from_slice(&body[p..p + chunk_len]);
            p += chunk_len + 2;
        }
        Ok(decoded)
    } else {
        Ok(body.to_vec())
    }
}

pub fn http_get_direct(hp: &HostPort, path: &str, timeout_ms: i32) -> Result<Bytes> {
    let mut stream = connect_tcp(&hp.host, hp.port, timeout_ms)?;
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {}\r\nUser-Agent: onionlink/0\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        hp.host
    );
    write_all_fd(&mut stream, req.as_bytes())?;
    stream.flush()?;
    let resp = read_all_fd(&mut stream, 8 * 1024 * 1024)?;
    decode_http_body(&resp)
}

pub fn fetch_microdescriptor_doc(
    bootstrap: &HostPort,
    r: &Relay,
    timeout_ms: i32,
) -> Result<String> {
    ensure(
        !r.md_digest.is_empty(),
        "relay missing microdescriptor digest",
    )?;
    let body = http_get_direct(
        bootstrap,
        &format!("/tor/micro/d/{}", r.md_digest),
        timeout_ms,
    )?;
    Ok(to_string_lossy(&body))
}

pub fn hydrate_microdescriptors(
    consensus: &mut Consensus,
    bootstrap: &HostPort,
    timeout_ms: i32,
    _verbose: bool,
) -> Result<()> {
    let mut digests = Vec::new();
    let mut seen = BTreeSet::new();
    for r in &consensus.relays {
        if !relay_usable_dir(r) || r.md_digest.is_empty() || r.has_flag("NoEdConsensus") {
            continue;
        }
        if r.has_flag("HSDir") && seen.insert(r.md_digest.clone()) {
            digests.push(r.md_digest.clone());
        }
    }
    ensure(
        !digests.is_empty(),
        "consensus has no microdescriptor digests to fetch",
    )?;

    let mut sources = vec![bootstrap.clone()];
    for r in &consensus.relays {
        if relay_usable_dir(r) && r.dir_port != 0 && r.has_flag("V2Dir") {
            sources.push(HostPort {
                host: r.ip.clone(),
                port: r.dir_port,
            });
        }
    }
    {
        use rand::seq::SliceRandom;
        sources[1..].shuffle(&mut rand::thread_rng());
    }

    #[derive(Clone)]
    struct Batch {
        first: usize,
        last: usize,
        path: String,
    }

    let mut batches = Vec::new();
    for (i, chunk) in digests.chunks(90).enumerate() {
        let first = i * 90 + 1;
        let last = first + chunk.len() - 1;
        batches.push(Batch {
            first,
            last,
            path: format!("/tor/micro/d/{}", chunk.join("-")),
        });
    }

    let fields = Arc::new(Mutex::new(BTreeMap::<String, MicrodescriptorFields>::new()));
    let next_batch = Arc::new(AtomicUsize::new(0));
    let batches = Arc::new(batches);
    let sources = Arc::new(sources);
    let worker_count = 8usize.min(batches.len().max(1));
    let microdesc_timeout_ms = timeout_ms.min(3000);
    info!(
        "fetching {} HSDir microdescriptor batches from {} directory sources",
        batches.len(),
        sources.len()
    );

    let mut workers = Vec::new();
    for worker_id in 0..worker_count {
        let fields = fields.clone();
        let next_batch = next_batch.clone();
        let batches = batches.clone();
        let sources = sources.clone();
        let digests_len = digests.len();
        workers.push(thread::spawn(move || loop {
            let idx = next_batch.fetch_add(1, Ordering::SeqCst);
            if idx >= batches.len() {
                return;
            }
            let batch = &batches[idx];
            info!(
                "fetching HSDir microdescriptors {}-{} of {}",
                batch.first, batch.last, digests_len
            );
            let attempts = 5usize.min(sources.len());
            let mut ok = false;
            let mut last_error = String::new();
            for attempt in 0..attempts {
                let src_idx = (idx * 7 + worker_id * 13 + attempt) % sources.len();
                let src = &sources[src_idx];
                match http_get_direct(src, &batch.path, microdesc_timeout_ms)
                    .and_then(|body| index_microdescriptors(&to_string_lossy(&body)))
                {
                    Ok(parsed) => {
                        fields.lock().expect("fields lock").extend(parsed);
                        ok = true;
                        break;
                    }
                    Err(e) => last_error = e.to_string(),
                }
            }
            if !ok {
                warn!(
                    "microdescriptor batch {}-{} failed after {} sources: {}",
                    batch.first, batch.last, attempts, last_error
                );
            }
        }));
    }
    for worker in workers {
        worker
            .join()
            .map_err(|_| Error::new("microdescriptor worker panicked"))?;
    }

    let fields = fields.lock().expect("fields lock");
    let mut hydrated = 0usize;
    for r in &mut consensus.relays {
        let Some(found) = fields.get(&r.md_digest) else {
            continue;
        };
        if r.ed_id.is_empty() {
            r.ed_id = found.ed_id.clone();
        }
        if r.ntor_key.is_empty() {
            r.ntor_key = found.ntor_key.clone();
        }
        if r.ed_id.len() == 32 || r.ntor_key.len() == 32 {
            hydrated += 1;
        }
    }
    info!("hydrated {hydrated} relays from microdescriptors");
    Ok(())
}

pub fn default_bootstrap() -> HostPort {
    parse_hostport("128.31.0.39:9131", 0).expect("valid default bootstrap")
}
