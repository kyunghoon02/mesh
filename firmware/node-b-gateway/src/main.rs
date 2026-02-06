#![no_std]
#![no_main]

mod comm;
mod serial;
mod state;

use esp_backtrace as _;
use esp_hal::{
    clock::ClockControl,
    gpio::IO,
    peripherals::Peripherals,
    prelude::*,
    rng::Rng,
    systimer::SystemTimer,
    timer::timg::TimerGroup,
    uart::{Config as UartConfig, Uart},
};
use esp_wifi::{initialize, EspWifiInitFor};
use postcard::{from_bytes, to_slice};

use common::{error_codes, SerialCommand, SerialFrame, SerialResponse};
use state::{PairingState, StateManager};

#[entry]
fn main() -> ! {
    let peripherals = Peripherals::take().expect("Failed to take peripherals");
    let system = peripherals.SYSTEM.split();
    let clocks = ClockControl::boot_defaults(system.clock_control).freeze();
    let io = IO::new(peripherals.GPIO, peripherals.IO_MUX);
    let mut rng = Rng::new(peripherals.RNG);

    // 페어링 윈도우 추적을 위한 시간 측정
    let systimer = SystemTimer::new(peripherals.SYSTIMER);
    let boot_time_ms = systimer.now() / 1000; // 밀리초 단위로 변환

    // 상태 머신 초기화
    let mut state_mgr = StateManager::new(boot_time_ms);

    // UART 초기화
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

    // CommManager는 페어링 후 peer MAC과 함께 초기화됨
    let mut comm: Option<comm::CommManager<'_>> = None;
    let mut esp_now_opt = Some(esp_now);

    let mut rx_buf = [0u8; 250];
    let mut response_buf = [0u8; 250];

    loop {
        let current_time_ms = systimer.now() / 1000;

        // Serial 명령 처리
        match serial.read_frame_blocking(&mut rx_buf) {
            Ok(len) => {
                if let Ok(frame) = from_bytes::<SerialFrame>(&rx_buf[..len]) {
                    let response = process_command(
                        &frame,
                        &mut state_mgr,
                        &mut comm,
                        &mut esp_now_opt,
                        current_time_ms,
                    );

                    // Serial로 응답 전송
                    if let Ok(serialized) = to_slice(&response, &mut response_buf) {
                        let _ = serial.write_frame(serialized);
                    }
                }
            }
            Err(_) => {
                // Serial 에러 - 계속 수신 대기
            }
        }

        // ESP-NOW 응답 확인 (페어링된 경우)
        if let Some(ref mut comm_mgr) = comm {
            if let Some(packet) = comm_mgr.receive_packet() {
                // ESP-NOW 응답을 Serial로 전달
                let response = SerialResponse::success(0, &[])
                    .unwrap_or_else(|| SerialResponse::error(0, error_codes::INVALID_COMMAND)); // TODO: sequence 추적
                if let Ok(serialized) = to_slice(&response, &mut response_buf) {
                    let _ = serial.write_frame(serialized);
                }
            }
        }
    }
}

/// Strict Command Set에 따라 Serial 명령 처리
fn process_command<'a>(
    frame: &SerialFrame,
    state_mgr: &mut StateManager,
    comm: &mut Option<comm::CommManager<'a>>,
    esp_now: &mut Option<esp_wifi::esp_now::EspNow<'a>>,
    current_time_ms: u64,
) -> SerialResponse {
    match frame.command {
        SerialCommand::EnterPairing => {
            match state_mgr.enter_pairing(current_time_ms) {
                Ok(_) => SerialResponse::success(frame.sequence_id, b"PAIRING_MODE")
                    .unwrap_or_else(|| SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND)),
                Err(_) => SerialResponse::error(frame.sequence_id, error_codes::INVALID_STATE),
            }
        }

        SerialCommand::GetPeerInfo => {
            if state_mgr.state() != PairingState::Pairing {
                return SerialResponse::error(frame.sequence_id, error_codes::INVALID_STATE);
            }

            // TODO: ESP-NOW 브로드캐스트로 Node A에게 peer info 요청
            // 현재는 플레이스홀더 반환
            SerialResponse::success(frame.sequence_id, b"PEER_INFO_REQUESTED")
                .unwrap_or_else(|| SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND))
        }

        SerialCommand::ConfirmPairing => {
            if state_mgr.state() != PairingState::Pairing {
                return SerialResponse::error(frame.sequence_id, error_codes::INVALID_STATE);
            }

            // payload에서 MAC 주소 6바이트 추출
            if frame.payload_len != 6 {
                return SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND);
            }

            let mut mac = [0u8; 6];
            mac.copy_from_slice(&frame.payload_bytes()[..6]);

            match state_mgr.confirm_pairing(mac) {
                Ok(_) => {
                    if let Some(esp_now) = esp_now.take() {
                        // 페어링된 MAC으로 CommManager 초기화
                        *comm = Some(comm::CommManager::new(esp_now, mac));
                        SerialResponse::success(frame.sequence_id, b"PAIRED")
                            .unwrap_or_else(|| SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND))
                    } else {
                        SerialResponse::error(frame.sequence_id, error_codes::INVALID_STATE)
                    }
                }
                Err(_) => SerialResponse::error(frame.sequence_id, error_codes::INVALID_STATE),
            }
        }

        SerialCommand::SignRequest => {
            if !state_mgr.can_sign() {
                return SerialResponse::error(frame.sequence_id, error_codes::NOT_PAIRED);
            }

            // ESP-NOW를 통해 Node A로 전달
            if let Some(ref mut comm_mgr) = comm {
                // payload에서 SecurePacket 역직렬화
                if let Ok(packet) = from_bytes::<common::SecurePacket>(frame.payload_bytes()) {
                    match comm_mgr.send_packet(&packet) {
                        Ok(_) => SerialResponse::success(frame.sequence_id, b"FORWARDED")
                            .unwrap_or_else(|| SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND)),
                        Err(_) => SerialResponse::error(frame.sequence_id, error_codes::ESPNOW_ERROR),
                    }
                } else {
                    SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND)
                }
            } else {
                SerialResponse::error(frame.sequence_id, error_codes::NOT_PAIRED)
            }
        }

        SerialCommand::GetStatus => {
            let status_byte = match state_mgr.state() {
                PairingState::Unpaired => 0u8,
                PairingState::Pairing => 1u8,
                PairingState::Ready => 2u8,
            };
            SerialResponse::success(frame.sequence_id, &[status_byte])
                .unwrap_or_else(|| SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND))
        }
    }
}
