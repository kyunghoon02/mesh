use common::SecurePacket;
use esp_wifi::esp_now::{EspNow, EspNowWifiInterface, PeerInfo};
use postcard::{from_bytes, to_slice};

pub struct CommManager<'a> {
    esp_now: EspNow<'a>,
    peer_address: [u8; 6],
}

impl<'a> CommManager<'a> {
    pub fn new(mut esp_now: EspNow<'a>, node_a_mac: [u8; 6]) -> Self {
        // Node A의 ESP-NOW peer 정보를 등록한다.
        match esp_now.add_peer(PeerInfo {
            interface: EspNowWifiInterface::Sta,
            peer_address: node_a_mac,
            lmk: None,
            channel: None,
            encrypt: false,
        }) {
            Ok(_) => {
                esp_println::println!("Peer 등록 완료: {:?}", node_a_mac);
            }
            Err(_) => {
                esp_println::println!(
                    "Peer 등록 실패/이미 등록된 상태일 수 있음: {:?}",
                    node_a_mac
                );
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

            if src != self.peer_address {
                esp_println::println!(
                    "알 수 없는 노드 패킷 차단: recv={:?}, allow={:?}",
                    src,
                    self.peer_address
                );
                return None;
            }

            if len == 0 {
                esp_println::println!("ESP-NOW 패킷 길이 0 수신");
                return None;
            }

            if len > data.data.len() {
                // 수신 길이가 내부 버퍼 길이보다 큰 경우는 드물지만 방어적으로 로그 남김
                esp_println::println!(
                    "ESP-NOW 길이 이상치: len={} data_len={}",
                    len,
                    data.data.len()
                );
                return None;
            }

            // data 필드에서 실제 수신 길이만 역직렬화 (패딩은 제외).
            let raw_data = &data.data[..len];
            match from_bytes::<SecurePacket>(raw_data) {
                Ok(packet) => Some(packet),
                Err(_) => {
                    esp_println::println!("ESP-NOW 패킷 역직렬화 실패: len={} src={:?}", len, src);
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
                esp_println::println!("ESP-NOW 패킷 직렬화 실패");
                return Err(());
            }
        };

        let token = match self.esp_now.send(&self.peer_address, serialized) {
            Ok(t) => t,
            Err(_) => {
                esp_println::println!("ESP-NOW send 호출 실패: to={:?}", self.peer_address);
                return Err(());
            }
        };

        if let Err(_) = token.wait() {
            esp_println::println!("ESP-NOW send 대기 실패: to={:?}", self.peer_address);
            return Err(());
        }

        Ok(())
    }
}
