#![no_std]
#![no_main]

mod comm;
mod serial;
mod state;
mod storage;

use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    rng::Rng,
    time::Instant,
    timer::timg::TimerGroup,
    usb_serial_jtag::UsbSerialJtag,
};
use postcard::{from_bytes, to_slice};

use common::{PacketType, SerialCommand, SerialFrame, SerialResponse, error_codes};
use state::{PairingState, StateManager};
use storage::PairingStorage;

macro_rules! log {
    ($($arg:tt)*) => {{
        let _ = core::format_args!($($arg)*);
    }};
}

const MAX_RETRIES: u8 = 0;
const RETRY_INTERVAL_MS: u64 = 1000;
const RESPONSE_TIMEOUT_MS: u64 = 60_000;
const MAX_SERIAL_PAYLOAD: usize = 240;
const MAX_SECURE_PAYLOAD: usize = 192;
const MIN_SECURE_PAYLOAD: usize = 1;
const MAX_SIGN_REQUEST_PAYLOAD: usize = 240;
const PROTOCOL_VERSION: u8 = 1;
const HANDSHAKE_BOOT_ID: u32 = 1;
esp_bootloader_esp_idf::esp_app_desc!();

struct PendingRequest {
    sequence_id: u32,
    packet: common::SecurePacket,
    first_sent_ms: u64,
    last_sent_ms: u64,
    retries: u8,
}

#[esp_hal::main]
fn main() -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    esp_alloc::heap_allocator!(size: 72 * 1024);
    let rng = Rng::new(peripherals.RNG);

    let boot_time_ms = now_ms();
    let mut state_mgr = StateManager::new(boot_time_ms);
    let mut pairing_storage = PairingStorage::new();

    if let Some(mac) = pairing_storage.load_peer_mac() {
        state_mgr.restore_paired(mac);
        log!("[pairing][event=restore.ok] mac={:?}", mac);
    } else {
        log!("[pairing][event=restore.miss]");
    }

    let usb_serial = UsbSerialJtag::new(peripherals.USB_DEVICE);
    let mut serial = serial::SerialManager::new(usb_serial);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let wifi_init = esp_wifi::init(timg0.timer0, rng).expect("esp-wifi init failed");
    let (mut wifi_controller, interfaces) =
        esp_wifi::wifi::new(&wifi_init, peripherals.WIFI).expect("esp-now init failed");
    wifi_controller
        .set_mode(esp_wifi::wifi::WifiMode::Sta)
        .expect("wifi sta mode failed");
    wifi_controller.start().expect("wifi start failed");
    let esp_now = interfaces.esp_now;

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
        let current_time_ms = now_ms();

        if state_mgr.expire_pairing_if_needed(current_time_ms) {
            log!("[pairing][event=state_expire] reset due timeout");
            pending = None;
        }

        match serial.poll_read_frame(&mut rx_buf) {
            Ok(Some(len)) => match from_bytes::<SerialFrame>(&rx_buf[..len]) {
                Ok(frame) => {
                    if frame.payload_len as usize > MAX_SERIAL_PAYLOAD {
                        let response =
                            SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND);
                        if let Ok(serialized) = to_slice(&response, &mut response_buf) {
                            let _ = serial.write_frame(serialized);
                        }
                        log!(
                            "[serial][event=recv.invalid_payload_len] payload_len={}",
                            frame.payload_len
                        );
                        continue;
                    }

                    log!(
                        "[serial][event=recv.frame] cmd={:?} seq={} payload_len={}",
                        frame.command,
                        frame.sequence_id,
                        frame.payload_len
                    );

                    if !is_valid_serial_command_payload(&frame) {
                        let response =
                            SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND);
                        if let Ok(serialized) = to_slice(&response, &mut response_buf) {
                            let _ = serial.write_frame(serialized);
                        }
                        log!(
                            "[serial][event=recv.invalid_command] cmd={:?} payload_len={}",
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
                        log!(
                            "[serial][event=recv.duplicate_sequence] seq={}",
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
                            log!(
                                "[serial][event=send.response_failed] seq={}",
                                frame.sequence_id
                            );
                        }
                    } else {
                        log!(
                            "[serial][event=send.serialize_failed] seq={}",
                            frame.sequence_id
                        );
                    }
                }
                Err(_err) => {
                    log!(
                        "[serial][event=recv.frame_decode_failed] len={} err={:?}",
                        len,
                        _err
                    );
                }
            },
            Ok(None) => {}
            Err(serial_err) => match serial_err {
                serial::SerialError::Io => log!("[serial][event=io_error]"),
                serial::SerialError::InvalidLen => {
                    log!("[serial][event=recv.invalid_length]")
                }
                serial::SerialError::Empty => log!("[serial][event=recv.empty_frame]"),
            },
        }

        if let Some(ref mut comm_mgr) = comm {
            if let Some(packet) = comm_mgr.receive_packet() {
                let seq = match pending.as_ref().map(|p| p.sequence_id) {
                    Some(v) => v,
                    None => {
                        log!(
                            "[espnow][event=recv.unmatched_seq] packet_seq={}",
                            packet.counter
                        );
                        continue;
                    }
                };

                let payload = match to_slice(&packet, &mut response_buf) {
                    Ok(v) => v,
                    Err(_) => {
                        log!("[espnow][event=serialize.packet_failed] seq={}", seq);
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

        if let Some(p) = pending.as_mut() {
            if current_time_ms.saturating_sub(p.first_sent_ms) >= RESPONSE_TIMEOUT_MS {
                let response = SerialResponse::error(p.sequence_id, error_codes::TIMEOUT);
                if let Ok(serialized) = to_slice(&response, &mut response_buf) {
                    let _ = serial.write_frame(serialized);
                }
                log!(
                    "[boundary][event=timeout] seq={} retries={}",
                    p.sequence_id,
                    p.retries
                );
                pending = None;
            } else if current_time_ms.saturating_sub(p.last_sent_ms) >= RETRY_INTERVAL_MS {
                if p.retries < MAX_RETRIES {
                    if let Some(ref mut comm_mgr) = comm {
                        log!(
                            "[boundary][event=retry.send] seq={} attempt={}",
                            p.sequence_id,
                            p.retries + 1
                        );
                        let _ = comm_mgr.send_packet(&p.packet);
                        p.retries += 1;
                        p.last_sent_ms = current_time_ms;
                    } else {
                        log!(
                            "[boundary][event=retry.halt_comm_missing] seq={}",
                            p.sequence_id
                        );
                    }
                } else {
                    log!(
                        "[boundary][event=retry.give_up] seq={} retries={} max={}",
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
    if frame.payload_len as usize > MAX_SERIAL_PAYLOAD {
        return SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND);
    }

    match frame.command {
        SerialCommand::EnterPairing => match state_mgr.enter_pairing(current_time_ms) {
            Ok(_) => {
                log!("[command][event=enter_pairing.ok]");
                SerialResponse::success(frame.sequence_id, b"PAIRING_MODE").unwrap_or_else(|| {
                    SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND)
                })
            }
            Err(_) => {
                log!("[command][event=enter_pairing.rejected.invalid_state]");
                SerialResponse::error(frame.sequence_id, error_codes::INVALID_STATE)
            }
        },

        SerialCommand::GetPeerInfo => {
            if !matches!(state_mgr.state(), PairingState::Pairing | PairingState::Ready) {
                log!(
                    "[command][event=get_peer_info.rejected.invalid_state] state={:?}",
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
                    log!("[command][event=get_peer_info.rejected.no_mac]");
                    SerialResponse::error(frame.sequence_id, error_codes::INVALID_STATE)
                }
            }
        }

        SerialCommand::ConfirmPairing => {
            if frame.payload_len != 6 {
                log!(
                    "[command][event=confirm_pairing.rejected.invalid_payload_len] len={}",
                    frame.payload_len
                );
                return SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND);
            }

            let mut mac = [0u8; 6];
            let payload = frame_payload_bytes(frame);
            mac.copy_from_slice(&payload[..6]);

            let state = state_mgr.state();
            let is_retrigger = state == PairingState::Ready && state_mgr.peer_mac() == Some(mac);
            if state != PairingState::Pairing && !is_retrigger {
                log!(
                    "[command][event=confirm_pairing.rejected.invalid_state] state={:?}",
                    state
                );
                return SerialResponse::error(frame.sequence_id, error_codes::INVALID_STATE);
            }

            if is_retrigger {
                if let Some(comm_mgr) = comm.as_mut() {
                    let handshake = build_handshake_packet(current_time_ms);
                    if let Err(err) = comm_mgr.send_packet(&handshake) {
                        return SerialResponse::success(frame.sequence_id, comm::send_error_label(err))
                            .unwrap_or_else(|| {
                                SerialResponse::error(frame.sequence_id, error_codes::ESPNOW_ERROR)
                            });
                    }
                } else {
                    return SerialResponse::error(frame.sequence_id, error_codes::NOT_PAIRED);
                }

                return SerialResponse::success(frame.sequence_id, b"PAIRING_PROMPTED")
                    .unwrap_or_else(|| {
                        SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND)
                    });
            }

            match state_mgr.confirm_pairing(mac) {
                Ok(_) => {
                    let should_save = pairing_storage.save_peer_mac(&mac).is_ok();
                    if !should_save {
                        log!("[pairing][event=save_mac.failed] mac={:?}", mac);
                        return SerialResponse::error(
                            frame.sequence_id,
                            error_codes::INVALID_COMMAND,
                        );
                    }

                    if let Some(esp_now) = esp_now.take() {
                        *comm = Some(comm::CommManager::new(esp_now, mac));
                    }

                    if let Some(comm_mgr) = comm.as_mut() {
                        let handshake = build_handshake_packet(current_time_ms);
                        if let Err(err) = comm_mgr.send_packet(&handshake) {
                            return SerialResponse::success(frame.sequence_id, comm::send_error_label(err))
                                .unwrap_or_else(|| {
                                    SerialResponse::error(
                                        frame.sequence_id,
                                        error_codes::ESPNOW_ERROR,
                                    )
                                });
                        }
                    } else {
                        return SerialResponse::error(frame.sequence_id, error_codes::NOT_PAIRED);
                    }

                    log!("[pairing][event=confirm_pairing.success] mac={:?}", mac);
                    SerialResponse::success(frame.sequence_id, b"PAIRED").unwrap_or_else(|| {
                        SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND)
                    })
                }
                Err(_) => {
                    log!("[pairing][event=confirm_pairing.rejected.invalid_state]");
                    SerialResponse::error(frame.sequence_id, error_codes::INVALID_STATE)
                }
            }
        }

        SerialCommand::SignRequest => {
            if !state_mgr.can_sign() {
                return SerialResponse::error(frame.sequence_id, error_codes::NOT_PAIRED);
            }

            if !is_valid_sign_request_payload_len(frame.payload_len) {
                log!(
                    "[command][event=sign_request.rejected.invalid_payload_len] len={}",
                    frame.payload_len
                );
                return SerialResponse::error(frame.sequence_id, error_codes::INVALID_COMMAND);
            }

            if pending.is_some() {
                log!("[command][event=sign_request.rejected.pending]");
                return SerialResponse::error(frame.sequence_id, error_codes::INVALID_STATE);
            }

            let Some(comm_mgr) = comm.as_mut() else {
                log!("[command][event=sign_request.rejected.no_pairing_channel]");
                return SerialResponse::error(frame.sequence_id, error_codes::NOT_PAIRED);
            };

            match from_bytes::<common::SecurePacket>(frame_payload_bytes(frame)) {
                Ok(packet) => {
                    if !is_valid_secure_packet_for_sign_request(&packet) {
                        log!(
                            "[command][event=sign_request.rejected.invalid_packet] version={} payload_len={}",
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
                            log!(
                                "[command][event=sign_request.rejected.esp_now_send_failed] seq={}",
                                frame.sequence_id
                            );
                            SerialResponse::error(frame.sequence_id, error_codes::ESPNOW_ERROR)
                        }
                    }
                }
                Err(_) => {
                    log!(
                        "[command][event=sign_request.rejected.packet_decode_failed] seq={}",
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

fn now_ms() -> u64 {
    Instant::now().duration_since_epoch().as_millis()
}

fn build_handshake_packet(counter: u64) -> common::SecurePacket {
    let mut packet = common::SecurePacket::new(PacketType::Handshake, &[], [0u8; 16])
        .expect("handshake packet should fit");
    packet.boot_id = HANDSHAKE_BOOT_ID;
    packet.counter = counter;
    packet
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
    }
}

fn is_valid_sign_request_payload_len(payload_len: u16) -> bool {
    let len = payload_len as usize;
    (1..=MAX_SIGN_REQUEST_PAYLOAD).contains(&len)
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
