use common::SecurePacket;
use esp_wifi::esp_now::{EspNow, EspNowWifiInterface, PeerInfo};
use postcard::{from_bytes, to_slice};

pub struct CommManager<'a> {
    esp_now: EspNow<'a>,
    // 통신 상대인 Node B의 MAC
    peer_address: [u8; 6],
}

impl<'a> CommManager<'a> {
    pub fn new(mut esp_now: EspNow<'a>, node_b_mac: [u8; 6]) -> Self {
        // ESP-NOW peer 정보를 등록한다.
        let _ = esp_now.add_peer(PeerInfo {
            interface: EspNowWifiInterface::Sta,
            peer_address: node_b_mac,
            lmk: None,
            channel: None,
            // 기본 동작: 암호화를 사용하지 않는다.
            encrypt: false,
        });

        Self {
            esp_now,
            peer_address: node_b_mac,
        }
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

    pub fn receive_packet(&self) -> Option<SecurePacket> {
        if let Some(data) = self.esp_now.receive() {
            // 등록된 Node B에서 온 패킷만 처리한다.
            if data.info.src_addr != self.peer_address {
                esp_println::println!(
                    "알 수 없는 기기(MAC: {:?}) 패킷 감지 - 차단됨",
                    data.info.src_addr
                );
                return None;
            }

            // 실제 수신된 길이만 역직렬화 (패딩은 제외).
            let raw_data = &data.data[..data.len as usize];
            match from_bytes::<SecurePacket>(raw_data) {
                Ok(packet) => Some(packet),
                Err(_) => {
                    esp_println::println!("패킷 역직렬화 실패");
                    None
                }
            }
        } else {
            None
        }
    }
}
