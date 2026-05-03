mod circuit;
mod crypto;
mod directory;
mod error;
mod hs;
mod tor;
mod util;

use std::sync::Mutex;

use log::info;

pub use circuit::{
    build_ntor_onionskin, finish_ntor, parse_relay_body, Circuit, NtorState, RelayMessage,
};
pub use crypto::{
    aes_ctr_crypt, ct_equal, hmac_sha256, kdf_tor, random_bytes, sha1, sha256, sha3_256, shake256,
    tor_mac, x25519_public_from_private, x25519_shared, DigestKind, RelayCrypto,
};
pub use directory::{
    blind_onion_key, candidate_rendezvous_relays, current_period_num, decode_http_body,
    default_bootstrap, derive_hs_period_keys, fetch_microdescriptor_doc, hydrate_microdescriptors,
    index_microdescriptors, link_spec_ipv4, onion_subcredential, parse_consensus,
    parse_link_specifiers, parse_microdescriptor_fields, parse_microdescriptor_into,
    parse_onion_address, relay_link_specifiers, relay_usable_dir, relay_usable_hsdir,
    relay_usable_rendezvous, same_relay, select_hsdirs, serialize_link_specifiers,
    split_microdescriptors, Consensus, HsPeriodKeys, LinkSpecifier, MicrodescriptorFields,
    OnionAddress, Relay,
};
pub use error::{ensure, err, Error, Result};
pub use hs::{
    build_introduce1, connect_onion_service, connect_onion_service_with_retries,
    decrypt_descriptor_layer, decrypt_hs_descriptor, fetch_hidden_service_descriptor,
    finish_hs_ntor, parse_ed25519_cert_subject, parse_inner_descriptor, DescriptorFetchResult,
    HiddenServiceDescriptor, HsIntroPayload, HsNtorState, IntroductionPoint, RendezvousStream,
};
pub use tor::{Cell, TorChannel};
pub use util::{
    base32_decode_onion, base64_decode, base64_encode_unpadded, from_string, hex, lower,
    parse_hostport, put_u16, put_u32, put_u64, read_u16, read_u32, split_ws, to_string_lossy,
    Bytes, HostPort,
};

use directory::{http_get_direct, read_file_string};
use hs::connect_onion_service_with_retries as connect_with_retries;

#[derive(Clone, Debug)]
pub struct Options {
    pub onion: String,
    pub port: u16,
    pub bootstrap: HostPort,
    pub consensus_file: String,
    pub verbose: bool,
    pub stdin_mode: bool,
    pub send_text: String,
    pub http_get: String,
    pub timeout_ms: i32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            onion: String::new(),
            port: 0,
            bootstrap: default_bootstrap(),
            consensus_file: String::new(),
            verbose: false,
            stdin_mode: false,
            send_text: String::new(),
            http_get: String::new(),
            timeout_ms: 30000,
        }
    }
}

impl Options {
    pub fn for_session(
        bootstrap: &str,
        consensus_file: &str,
        timeout_ms: i32,
        verbose: bool,
    ) -> Result<Self> {
        Ok(Self {
            bootstrap: parse_hostport(bootstrap, 0)?,
            consensus_file: consensus_file.to_string(),
            timeout_ms,
            verbose,
            ..Self::default()
        })
    }
}

pub fn load_consensus(opt: &Options) -> Result<Consensus> {
    if !opt.consensus_file.is_empty() {
        info!(
            "loading microdescriptor consensus from {}",
            opt.consensus_file
        );
        let consensus = parse_consensus(&read_file_string(&opt.consensus_file)?)?;
        info!("loaded consensus with {} relays", consensus.relays.len());
        return Ok(consensus);
    }
    info!(
        "fetching microdescriptor consensus from {}:{}",
        opt.bootstrap.host, opt.bootstrap.port
    );
    let doc = http_get_direct(
        &opt.bootstrap,
        "/tor/status-vote/current/consensus-microdesc",
        opt.timeout_ms,
    )?;
    let consensus = parse_consensus(&to_string_lossy(&doc))?;
    info!("loaded consensus with {} relays", consensus.relays.len());
    Ok(consensus)
}

pub fn request_bytes(
    opt: &Options,
    consensus: &Consensus,
    onion: &str,
    port: u16,
    outbound: &[u8],
    response_limit: usize,
) -> Result<Bytes> {
    let mut opt = opt.clone();
    opt.onion = onion.to_string();
    opt.port = port;
    let onion_addr = parse_onion_address(&opt.onion)?;
    let keys = derive_hs_period_keys(consensus, &onion_addr)?;
    let desc = fetch_hidden_service_descriptor(consensus, &keys, opt.timeout_ms, opt.verbose)?;
    let mut stream = connect_with_retries(&opt, consensus, &desc.descriptor, &keys, &[desc.guard])?;
    const STREAM_ID: u16 = 1;
    stream.begin(STREAM_ID, opt.port)?;
    if !outbound.is_empty() {
        stream.send_data(STREAM_ID, outbound)?;
    }
    stream.read_until_end(STREAM_ID, response_limit)
}

pub fn build_simple_http_get(onion: &str, path: &str) -> Bytes {
    let mut normalized_path = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };
    if !normalized_path.starts_with('/') {
        normalized_path.insert(0, '/');
    }
    from_string(format!(
        "GET {normalized_path} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        lower(onion)
    ))
}

pub struct Session {
    opt: Options,
    consensus: Mutex<Consensus>,
}

impl Session {
    pub fn new(
        bootstrap: &str,
        consensus_file: &str,
        timeout_ms: i32,
        verbose: bool,
    ) -> Result<Self> {
        let opt = Options::for_session(bootstrap, consensus_file, timeout_ms, verbose)?;
        info!("initializing onionlink session");
        let mut consensus = load_consensus(&opt)?;
        hydrate_microdescriptors(&mut consensus, &opt.bootstrap, opt.timeout_ms, opt.verbose)?;
        Ok(Self {
            opt,
            consensus: Mutex::new(consensus),
        })
    }

    pub fn request(
        &self,
        onion: &str,
        port: u16,
        payload: &[u8],
        response_limit: usize,
    ) -> Result<Bytes> {
        let consensus = self
            .consensus
            .lock()
            .map_err(|_| Error::new("consensus lock poisoned"))?
            .clone();
        request_bytes(&self.opt, &consensus, onion, port, payload, response_limit)
    }

    pub fn http_get(
        &self,
        onion: &str,
        port: u16,
        path: &str,
        response_limit: usize,
    ) -> Result<Bytes> {
        let payload = build_simple_http_get(onion, path);
        self.request(onion, port, &payload, response_limit)
    }
}
