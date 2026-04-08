use common::SecurePacket;
use esp_wifi::esp_now::{EspNow, EspNowWifiInterface, PeerInfo};
use postcard::{from_bytes, to_slice};

const ESPNOW_CHANNEL: u8 = 1;
pub const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

#[derive(Clone)]
pub struct PacketEnvelope {
    pub packet: SecurePacket,
    pub src_addr: [u8; 6],
    pub trusted: bool,
}

pub struct CommManager<'a> {
    esp_now: EspNow<'a>,
    peer_address: [u8; 6],
}

impl<'a> CommManager<'a> {
    pub fn new(esp_now: EspNow<'a>, node_b_mac: [u8; 6]) -> Self {
        let _ = Self::ensure_peer_registered(&esp_now, node_b_mac);

        Self {
            esp_now,
            peer_address: node_b_mac,
        }
    }

    pub fn peer_address(&self) -> [u8; 6] {
        self.peer_address
    }

    pub fn update_peer_address(&mut self, peer_address: [u8; 6]) {
        let _ = Self::ensure_peer_registered(&self.esp_now, peer_address);
        self.peer_address = peer_address;
    }

    pub fn send_packet(&mut self, packet: &SecurePacket) -> Result<(), ()> {
        self.send_packet_to(self.peer_address, packet)
    }

    pub fn send_packet_to(
        &mut self,
        destination: [u8; 6],
        packet: &SecurePacket,
    ) -> Result<(), ()> {
        let mut buf = [0u8; 250];
        let serialized = to_slice(packet, &mut buf).map_err(|_| ())?;

        let _ = Self::ensure_peer_registered(&self.esp_now, destination);

        let token = self.esp_now.send(&destination, serialized).map_err(|_| ())?;

        if destination != BROADCAST_MAC {
            let _ = token.wait();
        }

        Ok(())
    }

    pub fn receive_packet_with_src(&self) -> Option<PacketEnvelope> {
        if let Some(data) = self.esp_now.receive() {
            let raw_data = data.data();
            if raw_data.is_empty() {
                return None;
            }

            let src_addr = data.info.src_address;
            let packet = match from_bytes::<SecurePacket>(raw_data) {
                Ok(packet) => packet,
                Err(_) => return None,
            };

            Some(PacketEnvelope {
                packet,
                src_addr,
                trusted: src_addr == self.peer_address,
            })
        } else {
            None
        }
    }

    pub fn receive_packet(&self) -> Option<SecurePacket> {
        self.receive_packet_with_src()
            .filter(|env| env.trusted)
            .map(|env| env.packet)
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
