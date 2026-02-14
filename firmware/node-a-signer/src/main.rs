#![no_std]
#![no_main]

mod comm;
mod crypto;
mod storage;
mod ui;

use core::cell::RefCell;
use core::fmt::Write;

use common::{PacketType, SecurePacket, SignRequestPayload};
use critical_section::Mutex;
use embedded_graphics::pixelcolor::Rgb565;
use esp_backtrace as _;
use esp_hal::{
    clock::ClockControl,
    delay::Delay,
    gpio::{AnyPin, IO, Input, Level, Output, PullUp},
    peripherals::Peripherals,
    prelude::*,
    rng::Rng,
    systimer::SystemTimer,
    timer::timg::TimerGroup,
};
use esp_wifi::{EspWifiInitFor, esp_now::EspNow, initialize};
use heapless::String;
use mipidsi::{
    Builder,
    interface::{Generic8BitBus, ParallelInterface},
    models::ST7789,
    options::{ColorOrder, Orientation, Rotation},
};
use postcard::from_bytes;

// T-Display S3 1.9인치 기준 화면 크기
const DISPLAY_WIDTH: u16 = 170;
const DISPLAY_HEIGHT: u16 = 320;

// 8080 인터페이스 핀 배치
const DISPLAY_OFFSET_X: u16 = 0;
const DISPLAY_OFFSET_Y: u16 = 0;

// 버튼 입력(단일 버튼, 짧은/긴 누름 구분)
static BUTTON_PIN: Mutex<RefCell<Option<Input<AnyPin>>>> = Mutex::new(RefCell::new(None));

const PROTOCOL_VERSION: u8 = 1;
const MAX_PAYLOAD_LEN: usize = 192;
const PAIRING_WINDOW_MS: u64 = 5 * 60_000;

struct PendingSign {
    hash: [u8; 32],
    counter: u64,
    boot_id: u32,
}

struct PendingPairing {
    counter: u64,
    boot_id: u32,
    peer_mac: [u8; 6],
}

fn format_mac(mac: &[u8; 6]) -> String<20> {
    let mut text = String::new();
    let _ = write!(
        text,
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    text
}

fn is_replay_and_nonce_valid(
    packet: &SecurePacket,
    last_boot_id: &mut Option<u32>,
    last_counter: &mut Option<u64>,
) -> bool {
    if packet.version != PROTOCOL_VERSION {
        return false;
    }

    if packet.ciphertext_len as usize > MAX_PAYLOAD_LEN {
        return false;
    }

    // 동일 세션(boot_id) 유지 시에는 counter가 증가해야만 유효한 요청
    if last_boot_id != Some(packet.boot_id) {
        *last_boot_id = Some(packet.boot_id);
        *last_counter = None;
    }

    if let Some(last) = *last_counter {
        if packet.counter <= last {
            return false;
        }
    }

    *last_counter = Some(packet.counter);
    true
}

fn is_valid_sign_request_packet(packet: &SecurePacket) -> bool {
    if packet.version != PROTOCOL_VERSION {
        return false;
    }

    if packet.payload_type != PacketType::SignRequest {
        return false;
    }

    let len = packet.ciphertext_len as usize;
    if len == 0 || len > MAX_PAYLOAD_LEN {
        return false;
    }

    if packet.auth_tag == [0u8; 16] {
        return false;
    }

    true
}

#[entry]
fn main() -> ! {
    let peripherals = Peripherals::take().expect("Failed to take peripherals");
    let system = peripherals.SYSTEM.split();
    let clocks = ClockControl::boot_defaults(system.clock_control).freeze();
    let io = IO::new(peripherals.GPIO, peripherals.IO_MUX);
    let mut rng = Rng::new(peripherals.RNG);

    // 버튼 입력 설정
    let user_btn = Input::new(io.pins.gpio14.into(), PullUp);
    critical_section::with(|cs| {
        BUTTON_PIN.borrow(cs).replace(Some(user_btn));
    });

    // ST7789 초기화 (8080 병렬 인터페이스)
    let _lcd_power = Output::new(io.pins.gpio15, Level::High);
    let mut bl = Output::new(io.pins.gpio38, Level::Low);
    bl.set_high();

    let _lcd_cs = Output::new(io.pins.gpio6, Level::Low);
    let _lcd_rd = Output::new(io.pins.gpio9, Level::High);
    let dc = Output::new(io.pins.gpio7, Level::Low);
    let wr = Output::new(io.pins.gpio8, Level::High);
    let rst = Output::new(io.pins.gpio5, Level::High);

    let d0 = Output::new(io.pins.gpio39, Level::Low);
    let d1 = Output::new(io.pins.gpio40, Level::Low);
    let d2 = Output::new(io.pins.gpio41, Level::Low);
    let d3 = Output::new(io.pins.gpio42, Level::Low);
    let d4 = Output::new(io.pins.gpio45, Level::Low);
    let d5 = Output::new(io.pins.gpio46, Level::Low);
    let d6 = Output::new(io.pins.gpio47, Level::Low);
    let d7 = Output::new(io.pins.gpio48, Level::Low);

    let bus = Generic8BitBus::new((d0, d1, d2, d3, d4, d5, d6, d7));
    let di = ParallelInterface::new(bus, dc, wr);
    let mut delay = Delay::new(&clocks);

    let mut display = Builder::new(ST7789, di)
        .reset_pin(rst)
        .display_size(DISPLAY_WIDTH, DISPLAY_HEIGHT)
        .display_offset(DISPLAY_OFFSET_X, DISPLAY_OFFSET_Y)
        .color_order(ColorOrder::Bgr)
        .orientation(Orientation::new().rotate(Rotation::Deg0))
        .init(&mut delay)
        .unwrap();
    let _ = display.clear(Rgb565::BLACK);

    let mut ui = ui::UiManager::new(display);
    let mut storage = storage::StorageManager::new();

    // 키 로딩/생성
    let km = if let Some(key) = storage.load_key() {
        crypto::KeyManager {
            secret_key: k256::SecretKey::from_slice(&key).unwrap(),
        }
    } else {
        let new_km = crypto::KeyManager::generate_new(&mut rng);
        storage
            .save_key(&new_km.secret_key.to_bytes().into())
            .expect("Key save failed");
        new_km
    };

    // 주소 생성 후 화면 표시
    // 주소를 먼저 생성한 뒤 AEAD 키를 파생
    let addr = km.get_eth_address();
    let aead_key = crypto::KeyManager::derive_aead_key_from_address(&addr);
    let mut addr_str: String<42> = String::new();
    let _ = write!(addr_str, "0x");
    for b in addr {
        let _ = write!(addr_str, "{:02x}", b);
    }
    ui.display_address(&addr_str);

    // 저장된 페어링 대상 MAC을 로드
    let stored_peer_mac = storage.load_peer_mac();
    let trusted_node_b_mac = stored_peer_mac.unwrap_or([0u8; 6]);
    let mut has_paired_peer = stored_peer_mac.is_some();
    let mut current_peer_mac = trusted_node_b_mac;

    // ESP-NOW 초기화
    let timg0 = TimerGroup::new(peripherals.TIMG0, &clocks);
    let wifi_init = initialize(
        EspWifiInitFor::Wifi,
        timg0.timer0,
        rng,
        system.radio_clock_control,
        &clocks,
    )
    .expect("esp-wifi init failed");
    let esp_now = EspNow::new(&wifi_init, peripherals.WIFI).expect("esp-now init failed");
    let mut comm = comm::CommManager::new(esp_now, current_peer_mac);

    let mut pending_sign: Option<PendingSign> = None;
    let mut pending_pairing: Option<PendingPairing> = None;
    let mut last_counter: Option<u64> = None;
    let mut last_boot_id: Option<u32> = None;

    let systimer = SystemTimer::new(peripherals.SYSTIMER);
    let boot_time_ms = systimer.now() / 1000;
    let pairing_deadline_ms = boot_time_ms + PAIRING_WINDOW_MS;
    let mut press_start_ms: Option<u64> = None;
    let mut prev_low = false;
    const MIN_PRESS_MS: u64 = 50;
    const LONG_PRESS_MS: u64 = 1200;

    loop {
        // 버튼 이벤트(짧게/길게)
        let button_low = critical_section::with(|cs| {
            let mut btn = BUTTON_PIN.borrow(cs).borrow_mut();
            btn.as_mut()
                .map(|p| p.is_low().unwrap_or(false))
                .unwrap_or(false)
        });

        let now_ms = systimer.now() / 1000;

        if button_low && !prev_low {
            press_start_ms = Some(now_ms);
        }

        if !has_paired_peer && now_ms > pairing_deadline_ms {
            if pending_pairing.is_some() {
                pending_pairing = None;
                ui.display_message("페어링", "요청", "만료됨");
            }
        }

        if !button_low && prev_low {
            if let Some(start) = press_start_ms.take() {
                let duration = now_ms.saturating_sub(start);

                if duration >= LONG_PRESS_MS {
                    if let Some(pair) = pending_pairing.take() {
                        if send_node_a_response(
                            &mut comm,
                            pair.peer_mac,
                            &aead_key,
                            pair.counter,
                            pair.boot_id,
                            PacketType::ErrorMessage,
                            b"DENY",
                        ) {
                            ui.display_message("페어링", "긴 누름", "취소 처리됨");
                            has_paired_peer = false;
                            current_peer_mac = pair.peer_mac;
                        }
                    } else if let Some(pending) = pending_sign.take() {
                        if send_node_a_response(
                            &mut comm,
                            current_peer_mac,
                            &aead_key,
                            pending.counter,
                            pending.boot_id,
                            PacketType::ErrorMessage,
                            b"DENY",
                        ) {
                            ui.display_message("서명", "긴 누름", "거절됨");
                        }
                    }
                } else if duration >= MIN_PRESS_MS {
                    if let Some(pair) = pending_pairing.take() {
                        if storage.save_peer_mac(&pair.peer_mac).is_ok() {
                            has_paired_peer = true;
                            current_peer_mac = pair.peer_mac;
                            if send_node_a_response(
                                &mut comm,
                                pair.peer_mac,
                                &aead_key,
                                pair.counter,
                                pair.boot_id,
                                PacketType::Handshake,
                                b"OK",
                            ) {
                                ui.display_message("페어링", "짧게 누름", "승인됨");
                            } else {
                                ui.display_message("페어링", "승인됨", "응답 전송 실패");
                            }
                        } else {
                            ui.display_message("페어링", "저장 실패", "재시도 필요");
                        }
                    } else if let Some(pending) = pending_sign.take() {
                        if let Some(sig) = km.sign_hash(&pending.hash) {
                            if send_node_a_response(
                                &mut comm,
                                current_peer_mac,
                                &aead_key,
                                pending.counter,
                                pending.boot_id,
                                PacketType::SignResponse,
                                &sig,
                            ) {
                                ui.display_message("서명", "짧게 누름", "승인 완료");
                            }
                        }
                    }
                }
            }
        }
        prev_low = button_low;

        if let Some(envelope) = comm.receive_packet_with_src() {
            let packet = envelope.packet;
            let src_addr = envelope.src_addr;
            let is_trusted_src = envelope.trusted;

            // 버전, 길이, nonce(counter), replay 검사
            if !is_replay_and_nonce_valid(&packet, &mut last_boot_id, &mut last_counter) {
                esp_println::println!("패킷 유효성 검사 실패: 버전/카운터 오류");
                continue;
            }

            // 페어링이 끝난 뒤에는 저장된 peer만 허용
            if has_paired_peer && !is_trusted_src {
                esp_println::println!("미등록 MAC 패킷 차단: {:?}", src_addr);
                continue;
            }

            match packet.payload_type {
                PacketType::Handshake => {
                    if pending_pairing.is_some() || pending_sign.is_some() {
                        esp_println::println!("현재 처리 중인 요청이 있어 Handshake 무시");
                        continue;
                    }

                    if now_ms > pairing_deadline_ms {
                        esp_println::println!("pairing window closed");
                        continue;
                    }

                    if has_paired_peer {
                        esp_println::println!("이미 페어링된 상태에서 Handshake 무시");
                        continue;
                    }

                    if packet.ciphertext_len as usize != 0 {
                        esp_println::println!("Handshake payload_len invalid");
                        continue;
                    }

                    let hint = format_mac(&src_addr);
                    ui.display_pairing_request(Some(hint.as_str()));
                    pending_pairing = Some(PendingPairing {
                        counter: packet.counter,
                        boot_id: packet.boot_id,
                        peer_mac: src_addr,
                    });
                }

                PacketType::SignRequest => {
                    if !is_valid_sign_request_packet(&packet) {
                        esp_println::println!("SignRequest payload_len invalid");
                        continue;
                    }

                    if !has_paired_peer {
                        esp_println::println!("페어링 미완료 상태에서 SignRequest 무시");
                        continue;
                    }

                    if pending_sign.is_some() {
                        esp_println::println!("이미 서명 요청 처리 중");
                        continue;
                    }

                    let (payload_buf, payload_len) = match crypto::decrypt_payload(
                        packet.boot_id,
                        packet.counter,
                        &packet.ciphertext,
                        packet.ciphertext_len as usize,
                        &aead_key,
                        &packet.auth_tag,
                    ) {
                        Some(v) => v,
                        None => {
                            esp_println::println!("SignRequest 복호화 실패");
                            continue;
                        }
                    };

                    let payload =
                        match from_bytes::<SignRequestPayload>(&payload_buf[..payload_len]) {
                            Ok(v) => v,
                            Err(_) => {
                                esp_println::println!("SignRequest 형식 오류");
                                continue;
                            }
                        };

                    ui.display_sign_request_intent(&payload.intent, &payload.hash);

                    let hash = payload.hash;

                    pending_sign = Some(PendingSign {
                        hash,
                        counter: packet.counter,
                        boot_id: packet.boot_id,
                    });
                    esp_println::println!("사용자 서명 승인 대기");
                }

                PacketType::SignResponse | PacketType::ErrorMessage => {
                    // Node A에서 수신할 필요가 없는 응답 타입
                    esp_println::println!("응답 패킷 수신(필요 없음)");
                }
            }
        }
    }
}

fn send_node_a_response(
    comm: &mut comm::CommManager<'_>,
    dest_mac: [u8; 6],
    aead_key: &[u8; 32],
    counter: u64,
    boot_id: u32,
    packet_type: PacketType,
    payload: &[u8],
) -> bool {
    let prev_peer = comm.peer_address();
    comm.update_peer_address(dest_mac);

    let (ciphertext, auth_tag) = match crypto::encrypt_payload(boot_id, counter, payload, aead_key)
    {
        Some(v) => v,
        None => {
            comm.update_peer_address(prev_peer);
            return false;
        }
    };

    let Some(mut pkt) = SecurePacket::new(packet_type, &ciphertext[..payload.len()], auth_tag)
    else {
        comm.update_peer_address(prev_peer);
        return false;
    };

    pkt.counter = counter;
    pkt.boot_id = boot_id;

    let result = comm.send_packet(&pkt).is_ok();
    comm.update_peer_address(prev_peer);
    result
}
