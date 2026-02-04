#![no_std]
#![no_main]

mod crypto;
mod storage;
mod ui;
mod comm;

use core::cell::RefCell;
use critical_section::Mutex;
use esp_backtrace as _;
use esp_hal::{
    clock::ClockControl,
    gpio::{AnyPin, Input, PullUp, IO},
    interrupt,
    peripherals::Peripherals,
    prelude::*,
    rng::Rng,
};

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
            // 버튼 상태 플래그를 안전하게 업데이트
            BUTTON_PRESSED.borrow(cs).replace(true);
        }
    });
}

fn init_comm(_trusted_node_b_mac: [u8; 6]) -> Option<comm::CommManager<'static>> {
    // TODO: esp-now 초기화 후 CommManager::new(esp_now, trusted_node_b_mac) 반환
    None
}

#[entry]
fn main() -> ! {
    // Peripherals::take()는 Option이므로 안전하게 처리
    let peripherals = Peripherals::take().expect("Failed to take peripherals");
    let system = peripherals.SYSTEM.split();
    let _clocks = ClockControl::boot_defaults(system.clock_control).freeze();
    let io = IO::new(peripherals.GPIO, peripherals.IO_MUX);
    let mut rng = Rng::new(peripherals.RNG);

    // 내가 신뢰하는 노드 B의 MAC 주소 (페어링 시 저장된 주소)
    // 개발 단계에서는 수동 입력 또는 저장소에서 로드
    let trusted_node_b_mac = [0x30, 0xAE, 0xA4, 0x98, 0x76, 0x54];
    let comm = init_comm(trusted_node_b_mac);

    // 버튼 인터럽트 설정
    let mut btn = Input::new(io.pins.gpio0.into(), PullUp);
    btn.listen(esp_hal::gpio::Event::FallingEdge);
    critical_section::with(|cs| BUTTON_PIN.borrow(cs).replace(Some(btn)));

    interrupt::enable(
        esp_hal::peripherals::Interrupt::GPIO,
        interrupt::Priority::Priority1,
    )
    .unwrap();

    let mut storage = storage::StorageManager::new();

    // 로드 또는 신규 생성
    let _km = if let Some(key) = storage.load_key() {
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

    loop {
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
        }

        if let Some(comm) = comm.as_ref() {
            if let Some(_packet) = comm.receive_packet() {
                esp_println::println!("신뢰할 수 있는 게이트웨이로부터 패킷 수신!");
            }
        }
    }
}
