use aes::{Aes128, Aes256};
use ctr::cipher::{KeyIvInit, StreamCipher};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest as ShaDigest, Sha3_256, Shake256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{ensure, Error, Result};
use crate::tor::{K_CELL_BODY_LEN, K_RELAY_HEADER_LEN, K_RELAY_PAYLOAD_LEN};
use crate::util::{put_u64, read_u16, Bytes};

pub fn random_bytes(n: usize) -> Bytes {
    let mut b = vec![0; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

pub fn ct_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn sha1(in_bytes: &[u8]) -> Bytes {
    let mut h = Sha1::new();
    sha1::Digest::update(&mut h, in_bytes);
    h.finalize().to_vec()
}

pub fn sha256(in_bytes: &[u8]) -> Bytes {
    let mut h = Sha256::new();
    sha2::Digest::update(&mut h, in_bytes);
    h.finalize().to_vec()
}

pub fn sha3_256(in_bytes: &[u8]) -> Bytes {
    let mut h = Sha3_256::new();
    ShaDigest::update(&mut h, in_bytes);
    h.finalize().to_vec()
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<Bytes> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::new("hmac failed"))?;
    Mac::update(&mut mac, msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn shake256(in_bytes: &[u8], out_len: usize) -> Bytes {
    let mut h = Shake256::default();
    h.update(in_bytes);
    let mut reader = h.finalize_xof();
    let mut out = vec![0; out_len];
    reader.read(&mut out);
    out
}

pub fn tor_mac(key: &[u8], msg: &[u8]) -> Bytes {
    let mut input = Bytes::new();
    put_u64(&mut input, key.len() as u64);
    input.extend_from_slice(key);
    input.extend_from_slice(msg);
    sha3_256(&input)
}

type Aes128Ctr = ctr::Ctr128BE<Aes128>;
type Aes256Ctr = ctr::Ctr128BE<Aes256>;

enum AesCtr {
    Aes128(Box<Aes128Ctr>),
    Aes256(Box<Aes256Ctr>),
}

impl AesCtr {
    fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        ensure(iv.len() == 16, "bad aes ctr iv")?;
        match key.len() {
            16 => Ok(Self::Aes128(Box::new(
                Aes128Ctr::new_from_slices(key, iv).map_err(|_| Error::new("aes setkey failed"))?,
            ))),
            32 => Ok(Self::Aes256(Box::new(
                Aes256Ctr::new_from_slices(key, iv).map_err(|_| Error::new("aes setkey failed"))?,
            ))),
            _ => Err(Error::new("aes setkey failed")),
        }
    }

    fn apply(&mut self, input: &[u8]) -> Bytes {
        let mut out = input.to_vec();
        match self {
            Self::Aes128(c) => c.apply_keystream(&mut out),
            Self::Aes256(c) => c.apply_keystream(&mut out),
        }
        out
    }
}

pub fn aes_ctr_crypt(key: &[u8], input: &[u8], iv: Option<&[u8]>) -> Result<Bytes> {
    let zero = [0u8; 16];
    let mut c = AesCtr::new(key, iv.unwrap_or(&zero))?;
    Ok(c.apply(input))
}

pub struct AesCtrStream {
    ctr: AesCtr,
}

impl AesCtrStream {
    pub fn new(key: &[u8]) -> Self {
        let iv = [0u8; 16];
        Self {
            ctr: AesCtr::new(key, &iv).expect("valid relay AES key length"),
        }
    }

    pub fn apply(&mut self, input: &[u8]) -> Result<Bytes> {
        Ok(self.ctr.apply(input))
    }
}

#[derive(Clone)]
pub enum DigestState {
    Sha1(Sha1),
    Sha3(Box<Sha3_256>),
}

impl DigestState {
    pub fn sha1_with_seed(seed: &[u8]) -> Self {
        let mut h = Sha1::new();
        sha1::Digest::update(&mut h, seed);
        Self::Sha1(h)
    }

    pub fn sha3_with_seed(seed: &[u8]) -> Self {
        let mut h = Sha3_256::new();
        ShaDigest::update(&mut h, seed);
        Self::Sha3(Box::new(h))
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(h) => sha1::Digest::update(h, bytes),
            Self::Sha3(h) => ShaDigest::update(h.as_mut(), bytes),
        }
    }

    fn current(&self) -> Bytes {
        match self {
            Self::Sha1(h) => h.clone().finalize().to_vec(),
            Self::Sha3(h) => h.as_ref().clone().finalize().to_vec(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestKind {
    Sha1,
    Sha3,
}

pub struct RelayCrypto {
    f: AesCtrStream,
    b: AesCtrStream,
    sf: DigestState,
    sb: DigestState,
}

impl RelayCrypto {
    pub fn new(df: &[u8], db: &[u8], kf: &[u8], kb: &[u8], kind: DigestKind) -> Self {
        let sf = match kind {
            DigestKind::Sha1 => DigestState::sha1_with_seed(df),
            DigestKind::Sha3 => DigestState::sha3_with_seed(df),
        };
        let sb = match kind {
            DigestKind::Sha1 => DigestState::sha1_with_seed(db),
            DigestKind::Sha3 => DigestState::sha3_with_seed(db),
        };
        Self {
            f: AesCtrStream::new(kf),
            b: AesCtrStream::new(kb),
            sf,
            sb,
        }
    }

    pub fn encrypt_relay(&mut self, relay_cmd: u8, stream_id: u16, data: &[u8]) -> Result<Bytes> {
        ensure(data.len() <= K_RELAY_PAYLOAD_LEN, "relay payload too large")?;
        let mut body = vec![0; K_CELL_BODY_LEN];
        body[0] = relay_cmd;
        body[3] = (stream_id >> 8) as u8;
        body[4] = stream_id as u8;
        body[9] = (data.len() >> 8) as u8;
        body[10] = data.len() as u8;
        body[K_RELAY_HEADER_LEN..K_RELAY_HEADER_LEN + data.len()].copy_from_slice(data);
        self.sf.update(&body);
        let d = self.sf.current();
        body[5..9].copy_from_slice(&d[..4]);
        self.encrypt_body_only(&body)
    }

    pub fn decrypt_recognized(&mut self, encrypted: &[u8]) -> Result<Option<Bytes>> {
        let body = self.decrypt_body_only(encrypted)?;
        if self.recognize_decrypted(&body) {
            Ok(Some(body))
        } else {
            Ok(None)
        }
    }

    pub fn recognize_decrypted(&mut self, body: &[u8]) -> bool {
        if body.len() != K_CELL_BODY_LEN || body[1] != 0 || body[2] != 0 {
            return false;
        }
        let mut tmp = body.to_vec();
        tmp[5..9].fill(0);
        let checkpoint = self.sb.clone();
        self.sb.update(&tmp);
        let d = self.sb.current();
        if d[..4] == body[5..9] {
            true
        } else {
            self.sb = checkpoint;
            false
        }
    }

    pub fn encrypt_body_only(&mut self, body: &[u8]) -> Result<Bytes> {
        self.f.apply(body)
    }

    pub fn decrypt_body_only(&mut self, body: &[u8]) -> Result<Bytes> {
        self.b.apply(body)
    }
}

pub fn kdf_tor(k0: &[u8], len: usize) -> Bytes {
    let mut out = Bytes::new();
    let mut i = 0u8;
    while out.len() < len {
        let mut input = k0.to_vec();
        input.push(i);
        out.extend_from_slice(&sha1(&input));
        i = i.wrapping_add(1);
    }
    out.truncate(len);
    out
}

pub fn hkdf_sha256_expand(key_seed: &[u8], info: &[u8], len: usize) -> Result<Bytes> {
    let mut out = Bytes::new();
    let mut prev = Bytes::new();
    let mut i = 1u8;
    while out.len() < len {
        let mut msg = prev;
        msg.extend_from_slice(info);
        msg.push(i);
        prev = hmac_sha256(key_seed, &msg)?;
        out.extend_from_slice(&prev);
        i = i.wrapping_add(1);
    }
    out.truncate(len);
    Ok(out)
}

pub fn x25519_public_from_private(privkey: &[u8]) -> Result<Bytes> {
    ensure(privkey.len() == 32, "bad x25519 private key")?;
    let mut raw = [0u8; 32];
    raw.copy_from_slice(privkey);
    let secret = StaticSecret::from(raw);
    let public = PublicKey::from(&secret);
    Ok(public.as_bytes().to_vec())
}

pub fn x25519_shared(privkey: &[u8], pubkey: &[u8]) -> Result<Bytes> {
    ensure(
        privkey.len() == 32 && pubkey.len() == 32,
        "bad x25519 inputs",
    )?;
    let mut priv_raw = [0u8; 32];
    let mut pub_raw = [0u8; 32];
    priv_raw.copy_from_slice(privkey);
    pub_raw.copy_from_slice(pubkey);
    let secret = StaticSecret::from(priv_raw);
    let public = PublicKey::from(pub_raw);
    Ok(secret.diffie_hellman(&public).as_bytes().to_vec())
}

pub fn ed25519_point_is_valid(pubkey: &[u8]) -> bool {
    if pubkey.len() != 32 {
        return false;
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(pubkey);
    CompressedEdwardsY(raw).decompress().is_some()
}

pub fn ed25519_scalarmult_noclamp(scalar_bytes: &[u8], pubkey: &[u8]) -> Result<Bytes> {
    ensure(
        scalar_bytes.len() == 32 && pubkey.len() == 32,
        "bad ed25519 inputs",
    )?;
    let mut s = [0u8; 32];
    let mut p = [0u8; 32];
    s.copy_from_slice(scalar_bytes);
    p.copy_from_slice(pubkey);
    let point = CompressedEdwardsY(p)
        .decompress()
        .ok_or_else(|| Error::new("ed25519 key blinding failed"))?;
    let scalar = Scalar::from_bytes_mod_order(s);
    Ok((scalar * point).compress().to_bytes().to_vec())
}

pub fn relay_body_len(body: &[u8]) -> Result<usize> {
    read_u16(body, 9).map(|v| v as usize)
}
