use sha3::{Digest, Keccak256};

pub fn parse_chain_id_str(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

pub fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return None;
    }
    hex::decode(s).ok()
}

pub fn parse_address(s: &str) -> Option<[u8; 20]> {
    let bytes = parse_hex_bytes(s)?;
    if bytes.len() != 20 {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Some(out)
}

pub fn parse_bytes32(s: &str) -> Option<[u8; 32]> {
    let bytes = parse_hex_bytes(s)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

pub fn parse_abi_address(s: &str) -> Option<[u8; 20]> {
    let bytes = parse_hex_bytes(s)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes[12..]);
    Some(out)
}

pub fn address_to_hex(addr: [u8; 20]) -> String {
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    out.push_str(&hex::encode(addr));
    out
}

pub fn to_hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(2 + data.len() * 2);
    out.push_str("0x");
    out.push_str(&hex::encode(data));
    out
}

pub fn encode_create_account(owner: [u8; 20], passkey: &[u8], salt: [u8; 32]) -> Vec<u8> {
    // 함수 셀렉터: createAccount(address,bytes,bytes32)
    let mut hasher = Keccak256::new();
    hasher.update(b"createAccount(address,bytes,bytes32)");
    let selector = &hasher.finalize()[..4];

    let mut out = Vec::with_capacity(4 + 32 * 3 + 32 + passkey.len() + 32);
    out.extend_from_slice(selector);

    // 헤드 (3 * 32 bytes)
    // 1) owner 주소
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(&owner);
    // 2) bytes 데이터 오프셋 (0x60)
    out.extend_from_slice(&u256_be(0x60));
    // 3) bytes32 salt
    out.extend_from_slice(&salt);

    // 테일: bytes 길이 + 데이터 + 패딩
    out.extend_from_slice(&u256_be(passkey.len() as u64));
    out.extend_from_slice(passkey);
    let pad = (32 - (passkey.len() % 32)) % 32;
    if pad != 0 {
        out.extend_from_slice(&vec![0u8; pad]);
    }
    out
}

pub fn encode_get_address(owner: [u8; 20], passkey: &[u8], salt: [u8; 32]) -> Vec<u8> {
    // 함수 셀렉터: getAddress(address,bytes,bytes32)
    let mut hasher = Keccak256::new();
    hasher.update(b"getAddress(address,bytes,bytes32)");
    let selector = &hasher.finalize()[..4];

    let mut out = Vec::with_capacity(4 + 32 * 3 + 32 + passkey.len() + 32);
    out.extend_from_slice(selector);

    // 헤드 (3 * 32 bytes)
    // 1) owner 주소
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(&owner);
    // 2) bytes 데이터 오프셋 (0x60)
    out.extend_from_slice(&u256_be(0x60));
    // 3) bytes32 salt
    out.extend_from_slice(&salt);

    // 테일: bytes 길이 + 데이터 + 패딩
    out.extend_from_slice(&u256_be(passkey.len() as u64));
    out.extend_from_slice(passkey);
    let pad = (32 - (passkey.len() % 32)) % 32;
    if pad != 0 {
        out.extend_from_slice(&vec![0u8; pad]);
    }
    out
}

fn u256_be(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}
