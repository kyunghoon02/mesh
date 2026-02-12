use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use esp_hal::rng::Rng;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{RecoveryId, SigningKey, VerifyingKey};
use k256::SecretKey;
use sha3::{Digest, Keccak256};

const AEAD_KEY_BYTES: [u8; 32] = [0u8; 32];

pub struct KeyManager {
    pub secret_key: SecretKey,
}

impl KeyManager {
    pub fn generate_new(rng: &mut Rng) -> Self {
        // 유효한 Secp256k1 키가 생성될 때까지 재시도
        loop {
            let mut seed = [0u8; 32];
            rng.read(&mut seed);

            if let Ok(secret_key) = SecretKey::from_slice(&seed) {
                return Self { secret_key };
            }
        }
    }

    pub fn get_eth_address(&self) -> [u8; 20] {
        // 공개키(비압축) -> Keccak256 -> 마지막 20바이트
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

    pub fn sign_hash(&self, hash32: &[u8; 32]) -> Option<[u8; 65]> {
        let signing_key = SigningKey::from(&self.secret_key);
        let signature = signing_key.sign_prehash(hash32).ok()?;

        // recovery id 계산: 복구된 공개키가 실제 공개키와 일치하는지 확인
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
        // Ethereum 표준 v = 27/28
        out[64] = recovery_id.to_byte() + 27;
        Some(out)
    }
}

pub fn decrypt_payload(
    boot_id: u32,
    counter: u64,
    ciphertext: &[u8; 192],
    ciphertext_len: usize,
    auth_tag: &[u8; 16],
) -> Option<([u8; 192], usize)> {
    if ciphertext_len == 0 || ciphertext_len > 192 {
        return None;
    }

    // auth_tag가 전부 0이면 평문으로 처리 (하위 호환)
    let mut buf = [0u8; 192];
    buf[..ciphertext_len].copy_from_slice(&ciphertext[..ciphertext_len]);
    if auth_tag.iter().all(|b| *b == 0) {
        return Some((buf, ciphertext_len));
    }

    let key = Key::from_slice(&AEAD_KEY_BYTES);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = build_nonce(boot_id, counter);

    if cipher
        .decrypt_in_place_detached(
            &nonce,
            b"",
            &mut buf[..ciphertext_len],
            auth_tag.into(),
        )
        .is_ok()
    {
        Some((buf, ciphertext_len))
    } else {
        None
    }
}

pub fn encrypt_hash(boot_id: u32, counter: u64, hash32: &[u8; 32]) -> ([u8; 32], [u8; 16]) {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(hash32);

    let key = Key::from_slice(&AEAD_KEY_BYTES);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = build_nonce(boot_id, counter);

    let tag = cipher.encrypt_in_place_detached(&nonce, b"", &mut buf).expect("aead");
    (buf, tag.into())
}

fn build_nonce(boot_id: u32, counter: u64) -> Nonce {
    let mut out = [0u8; 12];
    out[..4].copy_from_slice(&boot_id.to_be_bytes());
    out[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::from_slice(&out).to_owned()
}
