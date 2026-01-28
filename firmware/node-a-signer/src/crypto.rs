use esp_hal::rng::Rng;
use k256::SecretKey;
use sha3::{Digest, Keccak256};

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
}
