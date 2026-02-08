#![no_std]
#![no_main]

mod comm;

use esp_backtrace as _;
use esp_hal::{
    clock::ClockControl,
    peripherals::Peripherals,
    prelude::*,
    rng::Rng,
    timer::timg::TimerGroup,
};
use esp_wifi::{initialize, EspWifiInitFor};

// 개발 단계: Node A MAC 주소 (페어링 로직으로 교체 예정)
const NODE_A_MAC: [u8; 6] = [0x30, 0xAE, 0xA4, 0x98, 0x76, 0x54];

#[entry]
fn main() -> ! {
    let peripherals = Peripherals::take().expect("Failed to take peripherals");
    let system = peripherals.SYSTEM.split();
    let clocks = ClockControl::boot_defaults(system.clock_control).freeze();
    let mut rng = Rng::new(peripherals.RNG);

    // ESP-WiFi/ESP-NOW 초기화
    let timg0 = TimerGroup::new(peripherals.TIMG0, &clocks);
    let wifi_init = initialize(
        EspWifiInitFor::Wifi,
        timg0.timer0,
        &mut rng,
        system.radio_clock_control,
        &clocks,
    )
    .expect("esp-wifi init failed");

    let esp_now = esp_wifi::esp_now::EspNow::new(&wifi_init, peripherals.WIFI)
        .expect("esp-now init failed");

    let mut comm = comm::CommManager::new(esp_now, NODE_A_MAC);

    loop {
        if let Some(_packet) = comm.receive_packet() {
            // TODO: Serial/WS로 전달
        }

        // TODO: Serial/WS에서 수신한 요청을 SecurePacket으로 만들어 send
    }
}
