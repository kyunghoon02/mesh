#![no_std]

use heapless::String;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

/// Endianness policy: postcard uses Little Endian.
/// All nodes (Relayer, Node A, Node B) are expected to be LE.

#[derive(Serialize_repr, Deserialize_repr, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Handshake = 0,
    SignRequest = 1,
    SignResponse = 2,
    ErrorMessage = 3,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecurePacket {
    pub version: u8,
    pub boot_id: u32,          // Session ID (reset on reboot)
    pub counter: u64,          // Anti-replay counter
    pub payload_type: PacketType,
    pub ciphertext_len: u8,    // 0..=192
    pub ciphertext: [u8; 192], // ESP-NOW 250-byte limit (with padding)
    pub auth_tag: [u8; 16],    // AEAD authentication tag
}

impl SecurePacket {
    pub fn new(p_type: PacketType, data: &[u8], tag: [u8; 16]) -> Option<Self> {
        if data.len() > 192 {
            return None;
        }

        let mut buf = [0u8; 192];
        buf[..data.len()].copy_from_slice(data);

        Some(Self {
            version: 1,
            boot_id: 0,
            counter: 0,
            payload_type: p_type,
            ciphertext_len: data.len() as u8,
            ciphertext: buf,
            auth_tag: tag,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionIntent {
    pub chain_id: u64,
    pub target_address: [u8; 20],
    pub eth_value: u128, // Wei
    pub risk_level: u8,  // 0: Safe, 1: Warning, 2: Danger
    pub summary: String<64>,
}
