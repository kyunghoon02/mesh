#![no_std]
#![no_main]

mod crypto;
mod storage;
mod ui;
mod comm;

use core::cell::RefCell;
use critical_section::Mutex;
use common::{PacketType, SecurePacket};
use esp_backtrace as _;
use esp_hal::{
    clock::ClockControl,
    gpio::{AnyPin, Input, PullUp, IO},
    interrupt,
    peripherals::Peripherals,
    prelude::*,
    rng::Rng,
    timer::timg::TimerGroup,
};
use esp_wifi::{esp_now::EspNow, initialize, EspWifiInitFor};

// 공유 상태
static BUTTON_PRESSED: Mutex<RefCell<bool>> = Mutex::new(RefCell::new(false));
static BUTTON_PIN: Mutex<RefCell<Option<Input<AnyPin>>>> = Mutex::new(RefCell::new(None));

// ISR: #[interrupt] 속성은 함수 바로 위에 적용하여 벡터 테이블에 등록
#[interrupt]
fn GPIO() {
    critical_section::with(|cs| {
        let mut button = BUTTON_PIN.borrow(cs).borrow_mut();
        if let Some(ref mut pin) = *button {
            pin.clear_interrupt();
            // 인터럽트 핸들러에서는 최소 작업만 수행
            // 실제 처리는 메인 루프에서 처리하고 여기서는 플래그만 세팅
            BUTTON_PRESSED.borrow(cs).replace(true);
        }
    });
}

#[entry]
fn main() -> ! {
    // Peripherals::take()는 Option이므로 안전하게 처리
    let peripherals = Peripherals::take().expect("Failed to take peripherals");
    let system = peripherals.SYSTEM.split();
    let _clocks = ClockControl::boot_defaults(system.clock_control).freeze();
    let io = IO::new(peripherals.GPIO, peripherals.IO_MUX);
    let mut rng = Rng::new(peripherals.RNG);


    // 버튼 인터럽트 설정 (눌렀을 때 LOW로 떨어지는 입력)
    let mut btn = Input::new(io.pins.gpio0.into(), PullUp);
    // FallingEdge를 감지해서 눌림 이벤트로 사용
    btn.listen(esp_hal::gpio::Event::FallingEdge);
    critical_section::with(|cs| BUTTON_PIN.borrow(cs).replace(Some(btn)));

    interrupt::enable(
        esp_hal::peripherals::Interrupt::GPIO,
        interrupt::Priority::Priority1,
    )
    .unwrap();

    let mut storage = storage::StorageManager::new();

    // 로드 또는 신규 생성
    let km = if let Some(key) = storage.load_key() {
        crypto::KeyManager {
            secret_key: k256::SecretKey::from_slice(&key).unwrap(),
        }
    } else {
        let new_km = crypto::KeyManager::generate_new(&mut rng);
        storage
            .save_key(&new_km.secret_key.to_bytes().into())
            .expect("Key Save Failed");
        new_km
    };

    // 페어링된 노드 B MAC 로드 (없으면 임시 기본값)
    let trusted_node_b_mac = storage
        .load_peer_mac()
        .unwrap_or([0x30, 0xAE, 0xA4, 0x98, 0x76, 0x54]);

    // ESP-NOW 초기화 (키 생성 이후 RNG 소유권 이동)
    let timg0 = TimerGroup::new(peripherals.TIMG0, &_clocks);
    let wifi_init = initialize(
        EspWifiInitFor::Wifi,
        timg0.timer0,
        rng,
        system.radio_clock_control,
        &_clocks,
    )
    .expect("esp-wifi init failed");
    let esp_now = EspNow::new(&wifi_init, peripherals.WIFI).expect("esp-now init failed");
    let comm = comm::CommManager::new(esp_now, trusted_node_b_mac);

    // 서명 요청을 임시 저장하는 슬롯 (버튼 승인 전까지 대기)
    let mut pending_packet: Option<SecurePacket> = None;

    loop {
        // 흐름 요약
        // 1) ESP-NOW로 SignRequest 수신 -> pending_packet 저장
        // 2) 버튼 인터럽트 발생 -> 플래그 세팅
        // 3) 메인 루프에서 플래그 확인 -> 서명 수행 -> SignResponse 전송
        // ISR에서 세팅된 버튼 플래그를 안전하게 읽고 초기화
        let pressed = critical_section::with(|cs| {
            let mut val = BUTTON_PRESSED.borrow(cs).borrow_mut();
            if *val {
                *val = false;
                true
            } else {
                false
            }
        });

        if pressed {
            esp_println::println!("물리 버튼 입력 감지");
            if let Some(packet) = pending_packet.take() {
                if packet.payload_type == PacketType::SignRequest {
                    let len = packet.ciphertext_len as usize;
                    if len == 32 {
                        // payload는 32바이트 해시로 가정
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&packet.ciphertext[..32]);
                        // 해시 서명 후 응답 패킷 생성
                        if let Some(sig) = km.sign_hash(&hash) {
                            if let Some(mut resp) =
                                SecurePacket::new(PacketType::SignResponse, &sig, [0u8; 16])
                            {
                                // counter/boot_id는 원본 요청과 맞춰서 응답
                                resp.counter = packet.counter;
                                resp.boot_id = packet.boot_id;
                                let _ = comm.send_packet(&resp);
                            }
                        }
                    } else {
                        esp_println::println!("서명 요청 페이로드 길이 오류");
                    }
                }
            }
        }

        if let Some(packet) = comm.receive_packet() {
            esp_println::println!("신뢰할 수 있는 게이트웨이로부터 패킷 수신!");
            if packet.payload_type == PacketType::SignRequest {
                if pending_packet.is_some() {
                    // 이미 대기 중인 요청이 있으면 큐잉 없이 무시
                    esp_println::println!("이전 서명 요청이 처리 중입니다.");
                } else {
                    // 새 요청을 저장하고 버튼 입력을 기다림
                    pending_packet = Some(packet);
                    esp_println::println!("서명 요청 대기 중 (버튼 입력 필요)");
                }
            }
        }
    }
}
