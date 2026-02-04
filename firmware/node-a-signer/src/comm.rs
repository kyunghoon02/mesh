use esp_wifi::esp_now::{EspNow, PeerInfo};
use common::SecurePacket;
use postcard::{to_slice, from_bytes};

pub struct CommManager<'a> {
    esp_now: EspNow<'a>,
    // Node B MAC 주소
    peer_address: [u8; 6],
}

impl<'a> CommManager<'a> {
    pub fn new(esp_now: EspNow<'a>, node_b_mac: [u8; 6]) -> Self {
        // Node B를 peer로 등록
        let _ = esp_now.add_peer(PeerInfo {
            peer_address: node_b_mac,
            lmk: None,
            channel: None,
            // 암호화는 SecurePacket 레이어에서 처리
            encrypt: false,
        });

        Self {
            esp_now,
            peer_address: node_b_mac,
        }
    }

    pub fn send_packet(&self, packet: &SecurePacket) -> Result<(), ()> {
        // ESP-NOW 페이로드 최대 250바이트
        let mut buf = [0u8; 250];
        let serialized = to_slice(packet, &mut buf).map_err(|_| ())?;

        self.esp_now
            .send(&self.peer_address, serialized)
            .map_err(|_| ())?;

        Ok(())
    }

    pub fn receive_packet(&self) -> Option<SecurePacket> {
        if let Some(data) = self.esp_now.receive() {
            // 상호 화이트리스팅: 보낸 사람(src_addr)이 내가 신뢰하는 노드 B인지 확인
            if data.info.src_addr != self.peer_address {
                esp_println::println!(
                    "알 수 없는 기기(MAC: {:?})로부터 패킷 감지 - 차단됨",
                    data.info.src_addr
                );
                return None;
            }

            // 실제 수신된 길이만 역직렬화 (패딩 쓰레기 방지)
            let actual_data = &data.data[..data.len as usize];
            let packet: Result<SecurePacket, _> = from_bytes(actual_data);
            return match packet {
                Ok(p) => Some(p),
                Err(_) => {
                    esp_println::println!("패킷 역직렬화 실패");
                    None
                }
            };
        }
        None
    }
}
