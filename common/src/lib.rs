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

/// Serial Command Set for Node B Gateway
/// Node B only responds to these specific commands for security
#[derive(Serialize_repr, Deserialize_repr, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SerialCommand {
    /// Enter pairing mode (only allowed in first 5 min after boot)
    EnterPairing = 0x01,
    /// Get peer info (MAC address) during pairing
    GetPeerInfo = 0x02,
    /// Confirm pairing with Node A
    ConfirmPairing = 0x03,
    /// Send transaction intent for signing (only in READY state)
    SignRequest = 0x10,
    /// Get current pairing status
    GetStatus = 0x20,
}

/// Serial Frame for Node B communication
/// Frame format over UART: [len_lo, len_hi, SerialFrame...]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerialFrame {
    pub command: SerialCommand,
    pub sequence_id: u32, // Anti-replay counter for Serial layer
    pub payload: [u8; 240], // Max payload size (fits SecurePacket)
    pub payload_len: u16,
}

impl SerialFrame {
    pub fn new(cmd: SerialCommand, seq: u32, data: &[u8]) -> Option<Self> {
        if data.len() > 240 {
            return None;
        }
        let mut buf = [0u8; 240];
        buf[..data.len()].copy_from_slice(data);
        Some(Self {
            command: cmd,
            sequence_id: seq,
            payload: buf,
            payload_len: data.len() as u16,
        })
    }

    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload[..self.payload_len as usize]
    }
}

/// Response frame from Node B to Relayer
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerialResponse {
    pub sequence_id: u32, // Matches request sequence_id
    pub success: bool,
    pub error_code: u8, // 0 = success, others = error codes
    pub payload: [u8; 240],
    pub payload_len: u16,
}

impl SerialResponse {
    pub fn success(seq: u32, data: &[u8]) -> Option<Self> {
        if data.len() > 240 {
            return None;
        }
        let mut buf = [0u8; 240];
        buf[..data.len()].copy_from_slice(data);
        Some(Self {
            sequence_id: seq,
            success: true,
            error_code: 0,
            payload: buf,
            payload_len: data.len() as u16,
        })
    }

    pub fn error(seq: u32, code: u8) -> Self {
        Self {
            sequence_id: seq,
            success: false,
            error_code: code,
            payload: [0u8; 240],
            payload_len: 0,
        }
    }

    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload[..self.payload_len as usize]
    }
}

/// Error codes for SerialResponse
pub mod error_codes {
    pub const SUCCESS: u8 = 0;
    pub const INVALID_STATE: u8 = 1;
    pub const NOT_PAIRED: u8 = 2;
    pub const PAIRING_TIMEOUT: u8 = 3;
    pub const ESPNOW_ERROR: u8 = 4;
    pub const TIMEOUT: u8 = 5;
    pub const INVALID_COMMAND: u8 = 6;
}
