use common::SecurePacket;
use esp_wifi::esp_now::{EspNow, EspNowWifiInterface, PeerInfo};
use postcard::{from_bytes, to_slice};

#[derive(Clone, Copy)]
pub struct PacketEnvelope {
    pub packet: SecurePacket,
    pub src_addr: [u8; 6],
    pub trusted: bool,
}

pub struct CommManager<'a> {
    esp_now: EspNow<'a>,
    // 통신 상대인 Node B의 MAC
    peer_address: [u8; 6],
}

impl<'a> CommManager<'a> {
    pub fn new(mut esp_now: EspNow<'a>, node_b_mac: [u8; 6]) -> Self {
        // ESP-NOW peer 정보를 등록
        let _ = esp_now.add_peer(PeerInfo {
            interface: EspNowWifiInterface::Sta,
            peer_address: node_b_mac,
            lmk: None,
            channel: None,
            encrypt: false,
        });

        Self {
            esp_now,
            peer_address: node_b_mac,
        }
    }

    pub fn peer_address(&self) -> [u8; 6] {
        self.peer_address
    }

    pub fn update_peer_address(&mut self, peer_address: [u8; 6]) {
        // 페어링 갱신 시 상대 MAC을 교체해 패킷 송수신 대상을 즉시 변경한다.
        self.peer_address = peer_address;
    }

    pub fn send_packet(&mut self, packet: &SecurePacket) -> Result<(), ()> {
        // ESP-NOW 패킷은 최대 250바이트.
        let mut buf = [0u8; 250];
        let serialized = to_slice(packet, &mut buf).map_err(|_| ())?;

        self.esp_now
            .send(&self.peer_address, serialized)
            .map_err(|_| ())?
            .wait()
            .map_err(|_| ())?;

        Ok(())
    }

    pub fn receive_packet_with_src(&self) -> Option<PacketEnvelope> {
        if let Some(data) = self.esp_now.receive() {
            let len = data.len as usize;

            if len == 0 || len > data.data.len() {
                return None;
            }

            let src_addr = data.info.src_addr;
            let raw_data = &data.data[..len];
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
}
