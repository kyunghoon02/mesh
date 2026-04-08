use common::SecurePacket;
use esp_wifi::esp_now::{Error as EspNowInnerError, EspNow, EspNowError, EspNowWifiInterface, PeerInfo};
use postcard::{from_bytes, to_slice};

pub const BROADCAST_MAC: [u8; 6] = [0xFF; 6];
const ESPNOW_CHANNEL: u8 = 1;

#[derive(Debug)]
pub enum SendPacketError {
    Serialize,
    Send(EspNowError),
    Wait(EspNowError),
}

pub struct CommManager<'a> {
    esp_now: EspNow<'a>,
    peer_address: [u8; 6],
}

impl<'a> CommManager<'a> {
    pub fn new(esp_now: EspNow<'a>, node_a_mac: [u8; 6]) -> Self {
        let _ = Self::ensure_peer_registered(&esp_now, node_a_mac);

        Self {
            esp_now,
            peer_address: node_a_mac,
        }
    }

    pub fn receive_packet(&mut self) -> Option<SecurePacket> {
        if let Some(data) = self.esp_now.receive() {
            let raw_data = data.data();

            if raw_data.is_empty() {
                return None;
            }

            from_bytes::<SecurePacket>(raw_data).ok()
        } else {
            None
        }
    }

    pub fn send_packet(&mut self, packet: &SecurePacket) -> Result<(), SendPacketError> {
        self.send_packet_to(self.peer_address, packet)
    }

    pub fn send_packet_to(
        &mut self,
        destination: [u8; 6],
        packet: &SecurePacket,
    ) -> Result<(), SendPacketError> {
        let mut buf = [0u8; 250];
        let serialized = to_slice(packet, &mut buf).map_err(|_| SendPacketError::Serialize)?;

        let _ = Self::ensure_peer_registered(&self.esp_now, destination);

        let token = self
            .esp_now
            .send(&destination, serialized)
            .map_err(SendPacketError::Send)?;

        if destination == BROADCAST_MAC {
            return Ok(());
        }

        token.wait().map_err(SendPacketError::Wait)
    }

    fn ensure_peer_registered(esp_now: &EspNow<'a>, peer_address: [u8; 6]) -> Result<(), ()> {
        esp_now
            .add_peer(PeerInfo {
                interface: EspNowWifiInterface::Sta,
                peer_address,
                lmk: None,
                channel: Some(ESPNOW_CHANNEL),
                encrypt: false,
            })
            .map_err(|_| ())
    }
}

pub fn send_error_label(err: SendPacketError) -> &'static [u8] {
    match err {
        SendPacketError::Serialize => b"PAIRING_SEND_ERR_SERIALIZE",
        SendPacketError::Send(EspNowError::SendFailed) => b"PAIRING_SEND_ERR_SEND_FAILED",
        SendPacketError::Wait(EspNowError::SendFailed) => b"PAIRING_SEND_ERR_WAIT_FAILED",
        SendPacketError::Send(EspNowError::Error(inner)) => match inner {
            EspNowInnerError::NotInitialized => b"PAIRING_SEND_ERR_NOT_INITIALIZED",
            EspNowInnerError::InvalidArgument => b"PAIRING_SEND_ERR_INVALID_ARGUMENT",
            EspNowInnerError::OutOfMemory => b"PAIRING_SEND_ERR_OUT_OF_MEMORY",
            EspNowInnerError::PeerListFull => b"PAIRING_SEND_ERR_PEER_LIST_FULL",
            EspNowInnerError::NotFound => b"PAIRING_SEND_ERR_NOT_FOUND",
            EspNowInnerError::InternalError => b"PAIRING_SEND_ERR_INTERNAL_ERROR",
            EspNowInnerError::PeerExists => b"PAIRING_SEND_ERR_PEER_EXISTS",
            EspNowInnerError::InterfaceError => b"PAIRING_SEND_ERR_INTERFACE_ERROR",
            EspNowInnerError::Other(_) => b"PAIRING_SEND_ERR_OTHER",
        },
        SendPacketError::Wait(EspNowError::Error(inner)) => match inner {
            EspNowInnerError::NotInitialized => b"PAIRING_WAIT_ERR_NOT_INITIALIZED",
            EspNowInnerError::InvalidArgument => b"PAIRING_WAIT_ERR_INVALID_ARGUMENT",
            EspNowInnerError::OutOfMemory => b"PAIRING_WAIT_ERR_OUT_OF_MEMORY",
            EspNowInnerError::PeerListFull => b"PAIRING_WAIT_ERR_PEER_LIST_FULL",
            EspNowInnerError::NotFound => b"PAIRING_WAIT_ERR_NOT_FOUND",
            EspNowInnerError::InternalError => b"PAIRING_WAIT_ERR_INTERNAL_ERROR",
            EspNowInnerError::PeerExists => b"PAIRING_WAIT_ERR_PEER_EXISTS",
            EspNowInnerError::InterfaceError => b"PAIRING_WAIT_ERR_INTERFACE_ERROR",
            EspNowInnerError::Other(_) => b"PAIRING_WAIT_ERR_OTHER",
        },
        SendPacketError::Send(EspNowError::DuplicateInstance)
        | SendPacketError::Wait(EspNowError::DuplicateInstance) => b"PAIRING_ERR_DUPLICATE_INSTANCE",
        SendPacketError::Send(EspNowError::Initialization(_))
        | SendPacketError::Wait(EspNowError::Initialization(_)) => b"PAIRING_ERR_WIFI_INIT",
    }
}
