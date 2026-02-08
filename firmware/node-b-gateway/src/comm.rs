use esp_wifi::esp_now::{EspNow, PeerInfo};
use postcard::{from_bytes, to_slice};

use common::SecurePacket;

pub struct CommManager<'a> {
    esp_now: EspNow<'a>,
    peer_address: [u8; 6],
}

impl<'a> CommManager<'a> {
    pub fn new(mut esp_now: EspNow<'a>, node_a_mac: [u8; 6]) -> Self {
        let _ = esp_now.add_peer(PeerInfo {
            peer_address: node_a_mac,
            lmk: None,
            channel: None,
            encrypt: false,
        });

        Self {
            esp_now,
            peer_address: node_a_mac,
        }
    }

    pub fn receive_packet(&mut self) -> Option<SecurePacket> {
        if let Some(data) = self.esp_now.receive() {
            let actual = &data.data[..data.len as usize];
            return from_bytes::<SecurePacket>(actual).ok();
        }
        None
    }

    pub fn send_packet(&mut self, packet: &SecurePacket) -> Result<(), ()> {
        let mut buf = [0u8; 250];
        let serialized = to_slice(packet, &mut buf).map_err(|_| ())?;
        self.esp_now.send(&self.peer_address, serialized).map_err(|_| ())?;
        Ok(())
    }
}
