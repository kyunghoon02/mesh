#![no_std]

use heapless::String;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use serde_repr::{Deserialize_repr, Serialize_repr};

/// 바이트 정렬 정책: postcard는 기본적으로 Little Endian을 사용합니다.
/// Relayer, Node A, Node B 모두 Little Endian 환경을 기준으로 동작합니다.
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
    pub boot_id: u32, // 부팅 단위 세션 ID(재부팅 시 재설정)
    pub counter: u64, // 재전송 방지용 카운터
    pub payload_type: PacketType,
    pub ciphertext_len: u8, // 0~192
    #[serde(with = "BigArray")]
    pub ciphertext: [u8; 192], // ESP-NOW 250바이트 제한을 고려한 패딩 포함 버퍼
    pub auth_tag: [u8; 16], // AEAD 인증 태그
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
    pub eth_value: u128,      // Wei
    pub risk_level: u8,       // 0: 안전, 1: 경고, 2: 위험
    pub summary: String<64>,
}

/// 서명 요청(SignRequest) 페이로드 타입
/// 트랜잭션 의도(intent)를 바이트로 패킹하기 위한 구조체
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignRequestPayload {
    pub hash: [u8; 32],
    pub intent: TransactionIntent,
}

/// Node B 게이트웨이에서 처리할 시리얼 명령셋
/// 보안상 허용된 명령만 노드 사이에서 응답한다.
#[derive(Serialize_repr, Deserialize_repr, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SerialCommand {
    /// 페어링 모드 진입(부팅 후 5분 이내만 허용)
    EnterPairing = 0x01,
    /// 페어링 중 상대 노드의 MAC 정보 조회
    GetPeerInfo = 0x02,
    /// Node A와 페어링 확정
    ConfirmPairing = 0x03,
    /// READY 상태에서 서명 의도 전송
    SignRequest = 0x10,
    /// 현재 페어링 상태 조회
    GetStatus = 0x20,
}

/// Node B와의 시리얼 프레임
/// UART 포맷: [len_lo, len_hi, SerialFrame...]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerialFrame {
    pub command: SerialCommand,
    pub sequence_id: u32, // 시리얼 레이어 재전송 방지 카운터
    #[serde(with = "BigArray")]
    pub payload: [u8; 240], // 최대 payload 크기( SecurePacket 전송용 )
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

/// Node B -> Relayer 응답 프레임
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerialResponse {
    pub sequence_id: u32,   // 요청 sequence_id와 매칭
    pub success: bool,
    pub error_code: u8,     // 0: 성공, 그 외: 오류 코드
    #[serde(with = "BigArray")]
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

/// SerialResponse 에러 코드 정의
pub mod error_codes {
    pub const SUCCESS: u8 = 0;
    pub const INVALID_STATE: u8 = 1;
    pub const NOT_PAIRED: u8 = 2;
    pub const PAIRING_TIMEOUT: u8 = 3;
    pub const ESPNOW_ERROR: u8 = 4;
    pub const TIMEOUT: u8 = 5;
    pub const INVALID_COMMAND: u8 = 6;
}
