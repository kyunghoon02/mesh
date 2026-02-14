#![no_std]
#![no_main]

mod comm;
mod serial;
mod state;
mod storage;

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
use esp_wifi::{EspWifiInitFor, initialize};
use postcard::{from_bytes, to_slice};

use common::{PacketType, SerialCommand, SerialFrame, SerialResponse, error_codes};
use state::{PairingState, StateManager};
use storage::PairingStorage;

const MAX_RETRIES: u8 = 3;
const RETRY_INTERVAL_MS: u64 = 1000;
const RESPONSE_TIMEOUT_MS: u64 = 5_000;
const MAX_SERIAL_PAYLOAD: usize = 240;
const MAX_SECURE_PAYLOAD: usize = 192;
const MIN_SECURE_PAYLOAD: usize = 1;
const MAX_SIGN_REQUEST_PAYLOAD: usize = 240;
const PROTOCOL_VERSION: u8 = 1;

struct PendingRequest {
    sequence_id: u32,
    packet: common::SecurePacket,
    first_sent_ms: u64,
    last_sent_ms: u64,
    retries: u8,
}

#[entry]
fn main() -> ! {
    let peripherals = Peripherals::take().expect("Failed to take peripherals");
    let system = peripherals.SYSTEM.split();
    let clocks = ClockControl::boot_defaults(system.clock_control).freeze();
    let io = IO::new(peripherals.GPIO, peripherals.IO_MUX);
    let mut rng = Rng::new(peripherals.RNG);

    // 부팅 시각을 기준으로 페어링 타임아웃을 계산하기 위해 타이머를 준비한다.
    let systimer = SystemTimer::new(peripherals.SYSTIMER);
    let boot_time_ms = systimer.now() / 1000;

    // 상태 관리자 생성 후 저장된 페어링 정보가 있으면 복원한다.
    let mut state_mgr = StateManager::new(boot_time_ms);
    let mut pairing_storage = PairingStorage::new();

    if let Some(mac) = pairing_storage.load_peer_mac() {
        state_mgr.restore_paired(mac);
        esp_println::println!("[pairing] 저장된 peer MAC 복원: {:?}", mac);
    } else {
        esp_println::println!("[pairing] 저장된 peer MAC이 없습니다.");
    }

    // UART를 통해 Relayer와의 Serial 채널을 연다.
    let uart_cfg = UartConfig::default().baudrate(115200);
    let uart = Uart::new(
        peripherals.UART0,
        io.pins.gpio20,
        io.pins.gpio21,
        &clocks,
        uart_cfg,
    )
    .expect("uart init failed");
    let mut serial = serial::SerialManager::new(uart);

    // ESP-NOW 송수신을 위해 Wi-Fi 스택을 초기화한다.
    let timg0 = TimerGroup::new(peripherals.TIMG0, &clocks);
    let wifi_init = initialize(
        EspWifiInitFor::Wifi,
        timg0.timer0,
        &mut rng,
        system.radio_clock_control,
        &clocks,
    )
    .expect("esp-wifi init failed");

    let esp_now =
        esp_wifi::esp_now::EspNow::new(&wifi_init, peripherals.WIFI).expect("esp-now init failed");

    // 복원이 된 MAC이 있으면 부팅 시점부터 바로 READY로 통신할 수 있게 준비한다.
    let mut comm: Option<comm::CommManager<'_>> = None;
    let mut esp_now_opt = Some(esp_now);
    if let Some(restored_mac) = state_mgr.peer_mac() {
        if let Some(esp_now_ready) = esp_now_opt.take() {
            comm = Some(comm::CommManager::new(esp_now_ready, restored_mac));
        }
    }

    let mut rx_buf = [0u8; 250];
    let mut response_buf = [0u8; 250];
    let mut pending: Option<PendingRequest> = None;

    let mut last_sequence_id: Option<u32> = None;

    loop {
        let current_time_ms = systimer.now() / 1000;

        // 페어링 모드가 5분을 넘기면 페어링을 강제로 종료한다.
        if state_mgr.expire_pairing_if_needed(current_time_ms) {
            esp_println::println!("[pairing] 페어링 대기 시간이 만료되어 상태를 초기화합니다.");
            pending = None;
        }

        // Serial 입력을 읽고 명령을 처리한다.
        match serial.poll_read_frame(&mut rx_buf) {
            Ok(Some(len)) => match from_bytes::<SerialFrame>(&rx_buf[..len]) {
                Ok(frame) => {
                    if frame.payload_len as usize > MAX_SERIAL_PAYLOAD {
                        let response =
                            SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND);
                        if let Ok(serialized) = to_slice(&response, &mut response_buf) {
                            let _ = serial.write_frame(serialized);
                        }
                        esp_println::println!("[serial] 잘못된 payload_len={}", frame.payload_len);
                        continue;
                    }

                    esp_println::println!(
                        "[serial] 수신: cmd={:?} seq={} payload_len={}",
                        frame.command,
                        frame.sequence_id,
                        frame.payload_len
                    );

                    if !is_valid_serial_command_payload(frame) {
                        let response =
                            SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND);
                        if let Ok(serialized) = to_slice(&response, &mut response_buf) {
                            let _ = serial.write_frame(serialized);
                        }
                        esp_println::println!(
                            "[serial] 잘못된 명령/길이: cmd={:?} payload_len={}",
                            frame.command,
                            frame.payload_len
                        );
                        continue;
                    }

                    if !is_valid_sequence_id(frame.sequence_id, &mut last_sequence_id) {
                        let response =
                            SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND);
                        if let Ok(serialized) = to_slice(&response, &mut response_buf) {
                            let _ = serial.write_frame(serialized);
                        }
                        esp_println::println!(
                            "[serial] 중복 시퀀스 거부: seq={}",
                            frame.sequence_id
                        );
                        continue;
                    }

                    let response = process_command(
                        &frame,
                        &mut state_mgr,
                        &mut comm,
                        &mut esp_now_opt,
                        current_time_ms,
                        &mut pending,
                        &mut pairing_storage,
                    );

                    if let Ok(serialized) = to_slice(&response, &mut response_buf) {
                        if let Err(_) = serial.write_frame(serialized) {
                            esp_println::println!(
                                "[serial] 응답 송신 실패 seq={}",
                                frame.sequence_id
                            );
                        }
                    } else {
                        esp_println::println!(
                            "[serial] 응답 직렬화 실패 seq={}",
                            frame.sequence_id
                        );
                    }
                }
                Err(err) => {
                    esp_println::println!(
                        "[serial] 프레임 역직렬화 실패 len={} err={:?}",
                        len,
                        err
                    );
                }
            },
            Ok(None) => {}
            Err(serial_err) => match serial_err {
                serial::SerialError::Io => esp_println::println!("[serial] IO 오류"),
                serial::SerialError::InvalidLen => {
                    esp_println::println!("[serial] 잘못된 길이 수신(0 또는 버퍼 초과)")
                }
                serial::SerialError::Empty => esp_println::println!("[serial] 빈 프레임 수신"),
            },
        }

        // ESP-NOW로부터 서명 응답/오류 수신 시 relayer 쪽 시퀀스로 즉시 반환한다.
        if let Some(ref mut comm_mgr) = comm {
            if let Some(packet) = comm_mgr.receive_packet() {
                if !matches!(
                    packet.payload_type,
                    PacketType::SignResponse | PacketType::ErrorMessage
                ) {
                    esp_println::println!(
                        "[esp-now] 처리 대상이 아닌 패킷: type={:?}, seq={}",
                        packet.payload_type,
                        packet.counter
                    );
                    continue;
                }

                let seq = match pending.as_ref().map(|p| p.sequence_id) {
                    Some(v) => v,
                    None => {
                        esp_println::println!(
                            "[esp-now] 매칭되지 않은 응답 수신: packet.seq={}",
                            packet.counter
                        );
                        continue;
                    }
                };

                let payload = match to_slice(&packet, &mut response_buf) {
                    Ok(v) => v,
                    Err(_) => {
                        esp_println::println!("[esp-now] 패킷 직렬화 실패 seq={}", seq);
                        let response = SerialResponse::error(seq, error_codes::INVALID_COMMAND);
                        if let Ok(serialized) = to_slice(&response, &mut response_buf) {
                            let _ = serial.write_frame(serialized);
                        }
                        pending = None;
                        continue;
                    }
                };

                let response = SerialResponse::success(seq, payload)
                    .unwrap_or_else(|| SerialResponse::error(seq, error_codes::INVALID_COMMAND));
                if let Ok(serialized) = to_slice(&response, &mut response_buf) {
                    let _ = serial.write_frame(serialized);
                }
                pending = None;
            }
        }

        // ESP-NOW 송신 대기 중 타임아웃/재시도 정책을 적용한다.
        if let Some(p) = pending.as_mut() {
            if current_time_ms.saturating_sub(p.first_sent_ms) >= RESPONSE_TIMEOUT_MS {
                let response = SerialResponse::error(p.sequence_id, error_codes::TIMEOUT);
                if let Ok(serialized) = to_slice(&response, &mut response_buf) {
                    let _ = serial.write_frame(serialized);
                }
                esp_println::println!(
                    "[timeout] seq={} 재시도={} 건 timeout",
                    p.sequence_id,
                    p.retries
                );
                pending = None;
            } else if current_time_ms.saturating_sub(p.last_sent_ms) >= RETRY_INTERVAL_MS {
                if p.retries < MAX_RETRIES {
                    if let Some(ref mut comm_mgr) = comm {
                        esp_println::println!(
                            "[retry] seq={} 재시도 횟수={}",
                            p.sequence_id,
                            p.retries + 1
                        );
                        let _ = comm_mgr.send_packet(&p.packet);
                        p.retries += 1;
                        p.last_sent_ms = current_time_ms;
                    } else {
                        esp_println::println!(
                            "[retry] seq={} comm 미생성으로 재시도 중단",
                            p.sequence_id
                        );
                    }
                } else {
                    esp_println::println!(
                        "[retry] seq={} 최대 재시도 초과 ({}/{})",
                        p.sequence_id,
                        p.retries,
                        MAX_RETRIES
                    );
                }
            }
        }
    }
}

fn process_command<'a>(
    frame: &SerialFrame,
    state_mgr: &mut StateManager,
    comm: &mut Option<comm::CommManager<'a>>,
    esp_now: &mut Option<esp_wifi::esp_now::EspNow<'a>>,
    current_time_ms: u64,
    pending: &mut Option<PendingRequest>,
    pairing_storage: &mut PairingStorage,
) -> SerialResponse {
    // 보안상 240 바이트 이상 payload는 모두 거부한다.
    if frame.payload_len as usize > MAX_SERIAL_PAYLOAD {
        return SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND);
    }

    match frame.command {
        SerialCommand::EnterPairing => match state_mgr.enter_pairing(current_time_ms) {
            Ok(_) => {
                esp_println::println!("[command] EnterPairing ok");
                SerialResponse::success(frame.sequence_id, b"PAIRING_MODE").unwrap_or_else(|| {
                    SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND)
                })
            }
            Err(_) => {
                esp_println::println!("[command] EnterPairing rejected: invalid state");
                SerialResponse::error(frame.sequence_id, error_codes::INVALID_STATE)
            }
        },

        SerialCommand::GetPeerInfo => {
            if !matches!(
                state_mgr.state(),
                PairingState::Pairing | PairingState::Ready
            ) {
                esp_println::println!(
                    "[command] GetPeerInfo rejected: state={:?}",
                    state_mgr.state()
                );
                return SerialResponse::error(frame.sequence_id, error_codes::INVALID_STATE);
            }

            match state_mgr.peer_mac() {
                Some(mac) => {
                    SerialResponse::success(frame.sequence_id, &mac).unwrap_or_else(|| {
                        SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND)
                    })
                }
                None => {
                    esp_println::println!("[command] GetPeerInfo: peer mac is not set");
                    SerialResponse::error(frame.sequence_id, error_codes::INVALID_STATE)
                }
            }
        }

        SerialCommand::ConfirmPairing => {
            if state_mgr.state() != PairingState::Pairing {
                esp_println::println!(
                    "[command] ConfirmPairing rejected: state={:?}",
                    state_mgr.state()
                );
                return SerialResponse::error(frame.sequence_id, error_codes::INVALID_STATE);
            }

            if frame.payload_len != 6 {
                esp_println::println!(
                    "[command] ConfirmPairing rejected: payload_len={}",
                    frame.payload_len
                );
                return SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND);
            }

            let mut mac = [0u8; 6];
            let payload = frame_payload_bytes(frame);
            mac.copy_from_slice(&payload[..6]);

            match state_mgr.confirm_pairing(mac) {
                Ok(_) => {
                    let should_save = pairing_storage.save_peer_mac(&mac).is_ok();
                    if !should_save {
                        esp_println::println!("[pairing] peer mac 영속 저장 실패: {:?}", mac);
                        return SerialResponse::error(
                            frame.sequence_id,
                            error_codes::INVALID_COMMAND,
                        );
                    }

                    if let Some(esp_now) = esp_now.take() {
                        // 저장된 MAC을 즉시 사용해 ESP-NOW Peer를 구성한다.
                        *comm = Some(comm::CommManager::new(esp_now, mac));
                    }

                    esp_println::println!("[pairing] ConfirmPairing success: {:?}", mac);
                    SerialResponse::success(frame.sequence_id, b"PAIRED").unwrap_or_else(|| {
                        SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND)
                    })
                }
                Err(_) => {
                    esp_println::println!("[pairing] ConfirmPairing rejected: invalid state");
                    SerialResponse::error(frame.sequence_id, error_codes::INVALID_STATE)
                }
            }
        }

        SerialCommand::SignRequest => {
            if !state_mgr.can_sign() {
                return SerialResponse::error(frame.sequence_id, error_codes::NOT_PAIRED);
            }

            if !is_expected_payload_len(frame) {
                esp_println::println!(
                    "[command] SignRequest rejected: invalid payload_len={}",
                    frame.payload_len
                );
                return SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND);
            }

            if pending.is_some() {
                esp_println::println!("[command] SignRequest rejected: pending request exists");
                return SerialResponse::error(frame.sequence_id, error_codes::INVALID_STATE);
            }

            let Some(comm_mgr) = comm.as_mut() else {
                esp_println::println!("[command] SignRequest rejected: no pair channel");
                return SerialResponse::error(frame.sequence_id, error_codes::NOT_PAIRED);
            };

            // payload는 SecurePacket 직렬화 값이어야 하며 최소 프로토콜 유효성 검사를 통과해야 한다.
            match from_bytes::<common::SecurePacket>(frame_payload_bytes(frame)) {
                Ok(packet) => {
                    if !is_valid_secure_packet_for_sign_request(&packet) {
                        esp_println::println!(
                            "[command] SignRequest rejected: invalid secure packet (version={}, payload_len={})",
                            packet.version,
                            packet.ciphertext_len
                        );
                        return SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND);
                    }

                    match comm_mgr.send_packet(&packet) {
                        Ok(_) => {
                            *pending = Some(PendingRequest {
                                sequence_id: frame.sequence_id,
                                packet,
                                first_sent_ms: current_time_ms,
                                last_sent_ms: current_time_ms,
                                retries: 0,
                            });
                            SerialResponse::success(frame.sequence_id, b"FORWARDED").unwrap_or_else(
                                || {
                                    SerialResponse::error(
                                        frame.sequence_id,
                                        error_codes::INVALID_COMMAND,
                                    )
                                },
                            )
                        }
                        Err(_) => {
                            esp_println::println!(
                                "[command] SignRequest rejected: ESP-NOW send failed seq={}",
                                frame.sequence_id
                            );
                            SerialResponse::error(frame.sequence_id, error_codes::ESPNOW_ERROR)
                        }
                    }
                }
                Err(_) => {
                    esp_println::println!(
                        "[command] SignRequest rejected: SecurePacket decode failed seq={}",
                        frame.sequence_id
                    );
                    SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND)
                }
            }
        }

        SerialCommand::GetStatus => {
            let status_byte = match state_mgr.state() {
                PairingState::Unpaired => 0u8,
                PairingState::Pairing => 1u8,
                PairingState::Ready => 2u8,
            };
            SerialResponse::success(frame.sequence_id, &[status_byte]).unwrap_or_else(|| {
                SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND)
            })
        }
    }
}





fn is_valid_serial_command_payload(frame: &SerialFrame) -> bool {
    if frame.payload_len > MAX_SERIAL_PAYLOAD as u16 {
        return false;
    }

    match frame.command {
        SerialCommand::EnterPairing => frame.payload_len == 0,
        SerialCommand::GetPeerInfo => frame.payload_len == 0,
        SerialCommand::ConfirmPairing => frame.payload_len == 6,
        SerialCommand::SignRequest => {
            let len = frame.payload_len as usize;
            (1..=MAX_SIGN_REQUEST_PAYLOAD).contains(&len)
        }
        SerialCommand::GetStatus => frame.payload_len == 0,
        _ => false,
    }
}

fn is_valid_sequence_id(sequence_id: u32, last_sequence_id: &mut Option<u32>) -> bool {
    if let Some(last) = last_sequence_id {
        if sequence_id <= *last {
            return false;
        }
    }

    *last_sequence_id = Some(sequence_id);
    true
}

fn is_valid_secure_packet_for_sign_request(packet: &common::SecurePacket) -> bool {
    if packet.version != PROTOCOL_VERSION {
        return false;
    }

    if packet.payload_type != PacketType::SignRequest {
        return false;
    }

    let payload_len = packet.ciphertext_len as usize;
    if payload_len < MIN_SECURE_PAYLOAD || payload_len > MAX_SECURE_PAYLOAD {
        return false;
    }

    if packet.auth_tag == [0u8; 16] {
        return false;
    }

    true
}
fn frame_payload_bytes(frame: &SerialFrame) -> &[u8] {
    let len = frame.payload_len as usize;
    if len > MAX_SERIAL_PAYLOAD {
        &[]
    } else {
        &frame.payload[..len]
    }
}
