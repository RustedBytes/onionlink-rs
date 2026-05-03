use serde_json::Value;

use onionlink_core::*;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../../tests/golden/deterministic.json")).unwrap()
}

fn s<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    let mut cur = v;
    for key in path {
        cur = &cur[*key];
    }
    cur.as_str().unwrap()
}

fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn utilities_match_golden_bytes() {
    let f = fixture();
    let mut out = Vec::new();
    put_u16(&mut out, 0x1234);
    assert_eq!(hex(&out), s(&f, &["endian", "u16"]));
    out.clear();
    put_u32(&mut out, 0x1234_5678);
    assert_eq!(hex(&out), s(&f, &["endian", "u32"]));
    out.clear();
    put_u64(&mut out, 0x0123_4567_89AB_CDEF);
    assert_eq!(hex(&out), s(&f, &["endian", "u64"]));
    assert_eq!(read_u16(&decode_hex("1234"), 0).unwrap(), 0x1234);
    assert_eq!(read_u32(&decode_hex("12345678"), 0).unwrap(), 0x1234_5678);

    let plain = decode_hex(s(&f, &["base64", "plain_hex"]));
    assert_eq!(
        base64_encode_unpadded(&plain),
        s(&f, &["base64", "encoded_unpadded"])
    );
    assert_eq!(
        hex(&base64_decode(s(&f, &["base64", "encoded_unpadded"])).unwrap()),
        s(&f, &["base64", "plain_hex"])
    );

    let raw_onion = base32_decode_onion(s(&f, &["onion", "address"])).unwrap();
    assert_eq!(hex(&raw_onion), s(&f, &["onion", "raw_hex"]));
    assert_eq!(
        hex(&parse_onion_address(s(&f, &["onion", "address"]))
            .unwrap()
            .pubkey),
        s(&f, &["onion", "pubkey_hex"])
    );
}

#[test]
fn crypto_and_relay_bytes_match_golden() {
    let f = fixture();
    assert_eq!(hex(&sha1(b"abc")), s(&f, &["crypto", "sha1_abc"]));
    assert_eq!(hex(&sha256(b"abc")), s(&f, &["crypto", "sha256_abc"]));
    assert_eq!(hex(&sha3_256(b"abc")), s(&f, &["crypto", "sha3_abc"]));
    assert_eq!(
        hex(&shake256(b"abc", 32)),
        s(&f, &["crypto", "shake256_abc_32"])
    );
    assert_eq!(
        hex(&hmac_sha256(b"key", b"msg").unwrap()),
        s(&f, &["crypto", "hmac_sha256_key_msg"])
    );
    assert_eq!(
        hex(&tor_mac(b"k", b"msg")),
        s(&f, &["crypto", "tor_mac_k_msg"])
    );

    let aes_key: Vec<u8> = (0..16).collect();
    let aes_input = decode_hex("00112233445566778899AABBCCDDEEFF");
    assert_eq!(
        hex(&aes_ctr_crypt(&aes_key, &aes_input, None).unwrap()),
        s(&f, &["crypto", "aes128_ctr"])
    );

    let k0: Vec<u8> = (0..20).collect();
    assert_eq!(hex(&kdf_tor(&k0, 64)), s(&f, &["crypto", "kdf_tor_64"]));

    let specs = vec![
        LinkSpecifier {
            spec_type: 0,
            data: vec![127, 0, 0, 1, 0x23, 0x29],
        },
        LinkSpecifier {
            spec_type: 2,
            data: (0..20).collect(),
        },
        LinkSpecifier {
            spec_type: 3,
            data: (32..64).collect(),
        },
    ];
    let serialized = serialize_link_specifiers(&specs).unwrap();
    assert_eq!(
        hex(&serialized),
        s(&f, &["link_specifiers", "serialized_hex"])
    );
    assert_eq!(parse_link_specifiers(&serialized).unwrap(), specs);

    let df = vec![0; 20];
    let db = vec![0; 20];
    let kf: Vec<u8> = (0..16).collect();
    let kb: Vec<u8> = (16..32).collect();
    let mut relay = RelayCrypto::new(&df, &db, &kf, &kb, DigestKind::Sha1);
    assert_eq!(
        hex(&relay.encrypt_relay(2, 1, b"hi").unwrap()),
        s(&f, &["relay_crypto", "encrypted_relay_data_hi_hex"])
    );
}

#[test]
fn descriptor_and_directory_parsing_match_golden() {
    let f = fixture();
    let cipher = decode_hex(s(&f, &["descriptor_layer", "cipher_hex"]));
    let secret: Vec<u8> = (0..32).collect();
    let subcredential: Vec<u8> = (32..64).collect();
    assert_eq!(
        hex(
            &decrypt_descriptor_layer(&cipher, &secret, &subcredential, 7, "hsdir-encrypted-data")
                .unwrap()
        ),
        s(&f, &["descriptor_layer", "plain_trimmed_hex"])
    );

    let consensus = parse_consensus(s(&f, &["consensus", "document"])).unwrap();
    assert_eq!(consensus.relays.len(), 1);
    assert_eq!(
        consensus.relays[0].nickname,
        s(&f, &["consensus", "relay_nickname"])
    );
    assert!(relay_usable_hsdir(&consensus.relays[0]));
    let selected = select_hsdirs(
        &consensus,
        &[7; 32],
        &consensus.shared_rand_current,
        current_period_num(&consensus, 1440),
        1440,
    )
    .unwrap();
    assert_eq!(selected[0].nickname, "Test");
}
