#![no_std]
#![no_main]

mod comm;
mod serial;

use esp_backtrace as _;
use esp_hal::{
    clock::ClockControl,
    gpio::IO,
    peripherals::Peripherals,
    prelude::*,
    rng::Rng,
    timer::timg::TimerGroup,
    uart::{Config as UartConfig, Uart},
};
use esp_wifi::{initialize, EspWifiInitFor};
use postcard::to_slice;

// 개발 단계: Node A MAC 주소 (페어링 로직으로 교체 예정)
const NODE_A_MAC: [u8; 6] = [0x30, 0xAE, 0xA4, 0x98, 0x76, 0x54];

#[entry]
fn main() -> ! {
    let peripherals = Peripherals::take().expect("Failed to take peripherals");
    let system = peripherals.SYSTEM.split();
    let clocks = ClockControl::boot_defaults(system.clock_control).freeze();
    let io = IO::new(peripherals.GPIO, peripherals.IO_MUX);
    let mut rng = Rng::new(peripherals.RNG);

    // UART 초기화 (핀은 보드에 맞게 조정 필요)
    // ESP32-C3 일반 구성: TX=GPIO20, RX=GPIO21
    let uart_cfg = UartConfig::default().baudrate(115200);
    let uart = Uart::new(peripherals.UART0, io.pins.gpio20, io.pins.gpio21, &clocks, uart_cfg)
        .expect("uart init failed");
    let mut serial = serial::SerialManager::new(uart);

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

    let mut rx_buf = [0u8; 250];
    let mut tx_buf = [0u8; 250];

    loop {
        // Serial -> ESP-NOW
        if let Ok(len) = serial.read_frame_blocking(&mut rx_buf) {
            if let Ok(packet) = postcard::from_bytes::<common::SecurePacket>(&rx_buf[..len]) {
                let _ = comm.send_packet(&packet);
            }
        }

        // ESP-NOW -> Serial
        if let Some(packet) = comm.receive_packet() {
            if let Ok(serialized) = to_slice(&packet, &mut tx_buf) {
                let _ = serial.write_frame(serialized);
            }
        }
    }
}
