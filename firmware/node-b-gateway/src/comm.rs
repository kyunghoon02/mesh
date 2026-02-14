use common::SecurePacket;
use esp_wifi::esp_now::{EspNow, EspNowWifiInterface, PeerInfo};
use postcard::{from_bytes, to_slice};

pub struct CommManager<'a> {
    esp_now: EspNow<'a>,
    peer_address: [u8; 6],
}

impl<'a> CommManager<'a> {
    pub fn new(mut esp_now: EspNow<'a>, node_a_mac: [u8; 6]) -> Self {
        match esp_now.add_peer(PeerInfo {
            interface: EspNowWifiInterface::Sta,
            peer_address: node_a_mac,
            lmk: None,
            channel: None,
            encrypt: false,
        }) {
            Ok(_) => {
                esp_println::println!("[espnow][event=peer_added] node_a_mac={:?}", node_a_mac);
            }
            Err(_) => {
                esp_println::println!("[espnow][event=peer_add_failed] node_a_mac={:?}", node_a_mac);
            }
        }

        Self {
            esp_now,
            peer_address: node_a_mac,
        }
    }

    pub fn receive_packet(&mut self) -> Option<SecurePacket> {
        if let Some(data) = self.esp_now.receive() {
            let src = data.info.src_addr;
            let len = data.len as usize;

            if len == 0 {
                esp_println::println!("[espnow][event=rx_empty]");
                return None;
            }

            if len > data.data.len() {
                esp_println::println!(
                    "[espnow][event=rx_invalid_length] len={} buffer_len={}",
                    len,
                    data.data.len()
                );
                return None;
            }

            if src != self.peer_address {
                esp_println::println!(
                    "[espnow][event=rx_unmatched_peer] src={:?} allow={:?}",
                    src,
                    self.peer_address
                );
                return None;
            }

            let raw_data = &data.data[..len];
            match from_bytes::<SecurePacket>(raw_data) {
                Ok(packet) => Some(packet),
                Err(_) => {
                    esp_println::println!(
                        "[espnow][event=rx_deserialize_fail] len={} src={:?}",
                        len,
                        src
                    );
                    None
                }
            }
        } else {
            None
        }
    }

    pub fn send_packet(&mut self, packet: &SecurePacket) -> Result<(), ()> {
        let mut buf = [0u8; 250];
        let serialized = match to_slice(packet, &mut buf) {
            Ok(v) => v,
            Err(_) => {
                esp_println::println!("[espnow][event=tx_serialize_failed]");
                return Err(());
            }
        };

        let token = match self.esp_now.send(&self.peer_address, serialized) {
            Ok(t) => t,
            Err(_) => {
                esp_println::println!(
                    "[espnow][event=tx_send_failed] to={:?}",
                    self.peer_address
                );
                return Err(());
            }
        };

        if let Err(_) = token.wait() {
            esp_println::println!("[espnow][event=tx_wait_timeout] to={:?}", self.peer_address);
            return Err(());
        }

        Ok(())
    }
}
