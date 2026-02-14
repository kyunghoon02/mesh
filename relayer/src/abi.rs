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
    // 함수 시그니처: createAccount(address,bytes,bytes32)
    let mut hasher = Keccak256::new();
    hasher.update(b"createAccount(address,bytes,bytes32)");
    let selector = &hasher.finalize()[..4];

    let mut out = Vec::with_capacity(4 + 32 * 3 + 32 + passkey.len() + 32);
    out.extend_from_slice(selector);

    // 헤드(3 * 32 바이트)
    // 1) owner 주소
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(&owner);
    // 2) bytes 데이터 오프셋(0x60)
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
    // 함수 시그니처: getAddress(address,bytes,bytes32)
    let mut hasher = Keccak256::new();
    hasher.update(b"getAddress(address,bytes,bytes32)");
    let selector = &hasher.finalize()[..4];

    let mut out = Vec::with_capacity(4 + 32 * 3 + 32 + passkey.len() + 32);
    out.extend_from_slice(selector);

    // 헤드(3 * 32 바이트)
    // 1) owner 주소
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(&owner);
    // 2) bytes 데이터 오프셋(0x60)
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

/// setPasskey(bytes) calldata 인코딩
pub fn encode_set_passkey(pubkey: &[u8]) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    hasher.update(b"setPasskey(bytes)");
    let selector = &hasher.finalize()[..4];

    let mut out = Vec::with_capacity(4 + 32 + 32 + pubkey.len() + 32);
    out.extend_from_slice(selector);

    // bytes 타입은 0x20 오프셋에서 시작
    out.extend_from_slice(&u256_be(0x20));
    out.extend_from_slice(&u256_be(pubkey.len() as u64));
    out.extend_from_slice(pubkey);
    let pad = (32 - (pubkey.len() % 32)) % 32;
    if pad != 0 {
        out.extend_from_slice(&vec![0u8; pad]);
    }

    out
}

/// recoverOwner(address,bytes,bytes,bytes) calldata 인코딩
pub fn encode_recover_owner(
    new_owner: [u8; 20],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    hasher.update(b"recoverOwner(address,bytes,bytes,bytes)");
    let selector = &hasher.finalize()[..4];

    let auth_len = authenticator_data.len();
    let client_len = client_data_json.len();
    let sig_len = signature.len();

    let auth_tail = 32 + auth_len + (32 - (auth_len % 32)) % 32;
    let client_tail = 32 + client_len + (32 - (client_len % 32)) % 32;
    let sig_tail = 32 + sig_len + (32 - (sig_len % 32)) % 32;

    let offset_auth = 0x80u64;
    let offset_client = offset_auth + auth_tail as u64;
    let offset_sig = offset_client + client_tail as u64;

    let mut out = Vec::with_capacity(4 + 32 * 4 + auth_tail + client_tail + sig_tail);
    out.extend_from_slice(selector);

    // newOwner (address, 20 바이트)
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(&new_owner);
    // 동적 슬롯 오프셋
    out.extend_from_slice(&u256_be(offset_auth));
    out.extend_from_slice(&u256_be(offset_client));
    out.extend_from_slice(&u256_be(offset_sig));

    // authenticatorData 인코딩
    out.extend_from_slice(&u256_be(auth_len as u64));
    out.extend_from_slice(authenticator_data);
    let pad = (32 - (auth_len % 32)) % 32;
    if pad != 0 {
        out.extend_from_slice(&vec![0u8; pad]);
    }

    // clientDataJSON 인코딩
    out.extend_from_slice(&u256_be(client_len as u64));
    out.extend_from_slice(client_data_json);
    let pad = (32 - (client_len % 32)) % 32;
    if pad != 0 {
        out.extend_from_slice(&vec![0u8; pad]);
    }

    // signature 인코딩
    out.extend_from_slice(&u256_be(sig_len as u64));
    out.extend_from_slice(signature);
    let pad = (32 - (sig_len % 32)) % 32;
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
