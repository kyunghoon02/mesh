use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use esp_hal::rng::Rng;
use k256::SecretKey;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{RecoveryId, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

const AEAD_KEY_BYTES: [u8; 32] = [0u8; 32];

pub struct KeyManager {
    pub secret_key: SecretKey,
}

impl KeyManager {
    /// TRNG로 secp256k1 개인키를 생성한다.
    pub fn generate_new(rng: &mut Rng) -> Self {
        loop {
            let mut seed = [0u8; 32];
            rng.read(&mut seed);

            if let Ok(secret_key) = SecretKey::from_slice(&seed) {
                return Self { secret_key };
            }
        }
    }

    /// 개인키에서 이더리움 주소를 계산한다.
    pub fn get_eth_address(&self) -> [u8; 20] {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let public_key = self.secret_key.public_key();
        let encoded_point = public_key.to_encoded_point(false);
        let public_bytes = &encoded_point.as_bytes()[1..];

        let mut hasher = Keccak256::new();
        hasher.update(public_bytes);
        let hash = hasher.finalize();

        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..32]);
        address
    }

    /// 메시지 해시를 서명하고, 이더리움 형식 v 값을 붙여 반환한다.
    pub fn sign_hash(&self, hash32: &[u8; 32]) -> Option<[u8; 65]> {
        let signing_key = SigningKey::from(&self.secret_key);
        let signature = signing_key.sign_prehash(hash32).ok()?;

        // 검증으로 가장자리 케이스까지 복구 ID를 정확히 찾아 매핑한다.
        let verifying_key = VerifyingKey::from(&signing_key);
        let mut recovery_id = None;
        for id in 0u8..=1 {
            if let Ok(rid) = RecoveryId::from_byte(id) {
                if let Ok(recovered) = VerifyingKey::recover_from_prehash(hash32, &signature, rid) {
                    if recovered == verifying_key {
                        recovery_id = Some(rid);
                        break;
                    }
                }
            }
        }
        let recovery_id = recovery_id?;

        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&signature.to_bytes());
        // 이더리움 v 값은 27/28 규격을 사용한다.
        out[64] = recovery_id.to_byte() + 27;
        Some(out)
    }
}

/// SecurePacket 페이로드를 ChaCha20-Poly1305로 복호화한다.
/// auth_tag가 0으로 채워진 패킷은 유효하지 않은 요청으로 간주한다.
pub fn decrypt_payload(
    boot_id: u32,
    counter: u64,
    ciphertext: &[u8; 192],
    ciphertext_len: usize,
    auth_tag: &[u8; 16],
) -> Option<([u8; 192], usize)> {
    if ciphertext_len > 192 {
        return None;
    }

    let mut buf = [0u8; 192];
    buf[..ciphertext_len].copy_from_slice(&ciphertext[..ciphertext_len]);

    if auth_tag.iter().all(|b| *b == 0) {
        return None;
    }

    let key = Key::from_slice(&AEAD_KEY_BYTES);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = build_nonce(boot_id, counter);

    if cipher
        .decrypt_in_place_detached(&nonce, b"", &mut buf[..ciphertext_len], auth_tag.into())
        .is_ok()
    {
        Some((buf, ciphertext_len))
    } else {
        None
    }
}

/// 서명해시를 암호화해 ESP-NOW 송신용 payload를 구성한다.
pub fn encrypt_hash(boot_id: u32, counter: u64, hash32: &[u8; 32]) -> ([u8; 32], [u8; 16]) {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(hash32);

    let key = Key::from_slice(&AEAD_KEY_BYTES);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = build_nonce(boot_id, counter);

    let tag = cipher
        .encrypt_in_place_detached(&nonce, b"", &mut buf)
        .expect("aead");
    (buf, tag.into())
}

/// 범용 SecurePacket 페이로드를 암호화한다.
pub fn encrypt_payload(
    boot_id: u32,
    counter: u64,
    plaintext: &[u8],
) -> Option<([u8; 192], [u8; 16])> {
    if plaintext.len() > 192 {
        return None;
    }

    let mut buf = [0u8; 192];
    buf[..plaintext.len()].copy_from_slice(plaintext);

    let key = Key::from_slice(&AEAD_KEY_BYTES);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = build_nonce(boot_id, counter);
    let tag = cipher
        .encrypt_in_place_detached(&nonce, b"", &mut buf[..plaintext.len()])
        .ok()?;

    Some((buf, tag.into()))
}

fn build_nonce(boot_id: u32, counter: u64) -> Nonce {
    let mut out = [0u8; 12];
    // 빌드 시 사용하는 boot_id + counter 조합을 12byte nonce로 사용
    out[..4].copy_from_slice(&boot_id.to_be_bytes());
    out[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::from_slice(&out).to_owned()
}
