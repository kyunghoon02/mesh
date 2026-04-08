use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use esp_hal::rng::Rng;
use k256::SecretKey;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{RecoveryId, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

pub struct KeyManager {
    pub secret_key: SecretKey,
}

impl KeyManager {
    pub fn generate_new(rng: &mut Rng) -> Self {
        loop {
            let mut seed = [0u8; 32];
            rng.read(&mut seed);

            if let Ok(secret_key) = SecretKey::from_slice(&seed) {
                return Self { secret_key };
            }
        }
    }

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

    pub fn sign_hash(&self, hash32: &[u8; 32]) -> Option<[u8; 65]> {
        let signing_key = SigningKey::from(&self.secret_key);
        let signature = signing_key.sign_prehash(hash32).ok()?;

        let verifying_key = VerifyingKey::from(&signing_key);
        let mut recovery_id = None;
        for id in 0u8..=1 {
            if let Some(rid) = RecoveryId::from_byte(id) {
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
        out[64] = recovery_id.to_byte() + 27;
        Some(out)
    }

    pub fn derive_aead_key(secret_key: &SecretKey) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(secret_key.to_bytes());
        let hash = hasher.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        key
    }

    pub fn derive_aead_key_from_address(address: &[u8; 20]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(address);
        let hash = hasher.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        key
    }
}

pub fn decrypt_payload(
    boot_id: u32,
    counter: u64,
    ciphertext: &[u8; 192],
    ciphertext_len: usize,
    aead_key: &[u8; 32],
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

    let key = Key::from_slice(aead_key);
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

pub fn encrypt_hash(
    boot_id: u32,
    counter: u64,
    hash32: &[u8; 32],
    aead_key: &[u8; 32],
) -> ([u8; 32], [u8; 16]) {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(hash32);

    let key = Key::from_slice(aead_key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = build_nonce(boot_id, counter);

    let tag = cipher
        .encrypt_in_place_detached(&nonce, b"", &mut buf)
        .expect("aead");
    (buf, tag.into())
}

pub fn encrypt_payload(
    boot_id: u32,
    counter: u64,
    plaintext: &[u8],
    aead_key: &[u8; 32],
) -> Option<([u8; 192], [u8; 16])> {
    if plaintext.len() > 192 {
        return None;
    }

    let mut buf = [0u8; 192];
    buf[..plaintext.len()].copy_from_slice(plaintext);

    let key = Key::from_slice(aead_key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = build_nonce(boot_id, counter);
    let tag = cipher
        .encrypt_in_place_detached(&nonce, b"", &mut buf[..plaintext.len()])
        .ok()?;

    Some((buf, tag.into()))
}

fn build_nonce(boot_id: u32, counter: u64) -> Nonce {
    let mut out = [0u8; 12];
    out[..4].copy_from_slice(&boot_id.to_be_bytes());
    out[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::clone_from_slice(&out)
}
