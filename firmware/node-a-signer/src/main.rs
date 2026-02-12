#![no_std]
#![no_main]

mod crypto;
mod storage;
mod ui;
mod comm;

use core::cell::RefCell;
use core::fmt::Write;
use critical_section::Mutex;
use common::{PacketType, SecurePacket, SignRequestPayload};
use esp_backtrace as _;
use esp_hal::{
    clock::ClockControl,
    delay::Delay,
    gpio::{AnyPin, Input, PullUp, IO, Output, Level},
    peripherals::Peripherals,
    prelude::*,
    rng::Rng,
    systimer::SystemTimer,
    timer::timg::TimerGroup,
};
use esp_wifi::{esp_now::EspNow, initialize, EspWifiInitFor};
use embedded_graphics::pixelcolor::Rgb565;
use heapless::String;
use postcard::from_bytes;
use mipidsi::{
    Builder,
    models::ST7789,
    interface::{ParallelInterface, Generic8BitBus},
    options::{ColorOrder, Orientation, Rotation},
};

// 디스플레이 해상도 (T-Display S3 기준)
const DISPLAY_WIDTH: u16 = 170;
const DISPLAY_HEIGHT: u16 = 320;

// T-Display S3 1.9인치 ST7789 (8080 병렬) 핀맵
// LCD_BL=GPIO38
// LCD_D0=GPIO39, D1=GPIO40, D2=GPIO41, D3=GPIO42
// LCD_D4=GPIO45, D5=GPIO46, D6=GPIO47, D7=GPIO48
// LCD_WR=GPIO08, LCD_RD=GPIO09, LCD_DC=GPIO07
// LCD_CS=GPIO06, LCD_RES=GPIO05, LCD_Power_On=GPIO15

// 패널 오프셋 (화면이 좌우로 밀리면 X 오프셋 조정)
const DISPLAY_OFFSET_X: u16 = 0;
const DISPLAY_OFFSET_Y: u16 = 0;

// 버튼 핀맵 (보드에 맞게 수정 필요)
// 사용자 버튼(GPIO14) 예시. GPIO0(BOOT)은 시스템 전용으로 남김.

// 공유 상태 (폴링 방식으로 처리)
static BUTTON_PIN: Mutex<RefCell<Option<Input<AnyPin>>>> = Mutex::new(RefCell::new(None));

struct PendingSign {
    hash: [u8; 32],
    counter: u64,
    boot_id: u32,
}

struct PendingPairing {
    counter: u64,
    boot_id: u32,
}

#[entry]
fn main() -> ! {
    // Peripherals::take()는 Option이므로 안전하게 처리
    let peripherals = Peripherals::take().expect("Failed to take peripherals");
    let system = peripherals.SYSTEM.split();
    let clocks = ClockControl::boot_defaults(system.clock_control).freeze();
    let io = IO::new(peripherals.GPIO, peripherals.IO_MUX);
    let mut rng = Rng::new(peripherals.RNG);

    // 버튼 입력 설정 (단일 버튼)
    let user_btn = Input::new(io.pins.gpio14.into(), PullUp);
    critical_section::with(|cs| {
        BUTTON_PIN.borrow(cs).replace(Some(user_btn));
    });

    // =========================
    // ST7789 디스플레이 초기화 (8080 병렬)
    // =========================
    // 전원/제어 핀
    let _lcd_power = Output::new(io.pins.gpio15, Level::High);
    let mut bl = Output::new(io.pins.gpio38, Level::Low);
    bl.set_high();

    let _lcd_cs = Output::new(io.pins.gpio6, Level::Low);
    let _lcd_rd = Output::new(io.pins.gpio9, Level::High);
    let dc = Output::new(io.pins.gpio7, Level::Low);
    let wr = Output::new(io.pins.gpio8, Level::High);
    let rst = Output::new(io.pins.gpio5, Level::High);

    // 8비트 데이터 버스
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

    // 주소 표시 (부팅 직후)
    let addr = km.get_eth_address();
    let mut addr_str: String<42> = String::new();
    let _ = write!(addr_str, "0x");
    for b in addr {
        let _ = write!(addr_str, "{:02x}", b);
    }
    ui.display_address(&addr_str);

    // 페어링된 노드 B MAC 로드 (없으면 임시 기본값)
    let trusted_node_b_mac = storage
        .load_peer_mac()
        .unwrap_or([0x30, 0xAE, 0xA4, 0x98, 0x76, 0x54]);

    // ESP-NOW 초기화 (키 생성 이후 RNG 소유권 이동)
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
    let comm = comm::CommManager::new(esp_now, trusted_node_b_mac);

    // 서명 요청을 임시 저장하는 슬롯 (버튼 승인 전까지 대기)
    let mut pending_sign: Option<PendingSign> = None;
    let mut pending_pairing: Option<PendingPairing> = None;
    let mut last_counter: Option<u64> = None;
    let mut last_boot_id: Option<u32> = None;

    // 버튼 눌림 길이 판별용
    let systimer = SystemTimer::new(peripherals.SYSTIMER);
    let mut press_start_ms: Option<u64> = None;
    let mut prev_low = false;
    const MIN_PRESS_MS: u64 = 50;
    const LONG_PRESS_MS: u64 = 1200;

    loop {
        // 흐름 요약
        // 1) ESP-NOW로 SignRequest 수신 -> pending_sign 저장
        // 2) 버튼 인터럽트 발생 -> 플래그 세팅
        // 3) 메인 루프에서 플래그 확인 -> 서명 수행 -> SignResponse 전송

        // 버튼 폴링 (눌림: LOW)
        let button_low = critical_section::with(|cs| {
            let mut btn = BUTTON_PIN.borrow(cs).borrow_mut();
            btn.as_mut()
                .map(|p| p.is_low().unwrap_or(false))
                .unwrap_or(false)
        });

        let now_ms = systimer.now() / 1000;

        // 눌림 시작
        if button_low && !prev_low {
            press_start_ms = Some(now_ms);
        }
        // 눌림 종료 -> 길이 판단
        if !button_low && prev_low {
            if let Some(start) = press_start_ms.take() {
                let duration = now_ms.saturating_sub(start);

                if duration >= LONG_PRESS_MS {
                    esp_println::println!("길게 누름 감지 (거절)");
                    if let Some(pair) = pending_pairing.take() {
                        if let Some(mut resp) =
                            SecurePacket::new(PacketType::ErrorMessage, b"DENY", [0u8; 16])
                        {
                            resp.counter = pair.counter;
                            resp.boot_id = pair.boot_id;
                            let _ = comm.send_packet(&resp);
                        }
                        ui.display_message("페어링 거절", "요청을 거절했습니다", "");
                    } else if let Some(pending) = pending_sign.take() {
                        if let Some(mut resp) =
                            SecurePacket::new(PacketType::ErrorMessage, b"DENY", [0u8; 16])
                        {
                            resp.counter = pending.counter;
                            resp.boot_id = pending.boot_id;
                            let _ = comm.send_packet(&resp);
                        }
                        ui.display_message("서명 거절", "요청을 거절했습니다", "");
                    }
                } else if duration >= MIN_PRESS_MS {
                    esp_println::println!("짧게 누름 감지 (승인)");
                    if let Some(pair) = pending_pairing.take() {
                        if let Some(mut resp) =
                            SecurePacket::new(PacketType::Handshake, b"OK", [0u8; 16])
                        {
                            resp.counter = pair.counter;
                            resp.boot_id = pair.boot_id;
                            let _ = comm.send_packet(&resp);
                        }
                        ui.display_message("페어링 승인", "연결을 허용했습니다", "");
                    } else if let Some(pending) = pending_sign.take() {
                        if let Some(sig) = km.sign_hash(&pending.hash) {
                            if let Some(mut resp) =
                                SecurePacket::new(PacketType::SignResponse, &sig, [0u8; 16])
                            {
                                resp.counter = pending.counter;
                                resp.boot_id = pending.boot_id;
                                let _ = comm.send_packet(&resp);
                                ui.display_message("서명 완료", "승인 결과를 전송했습니다", "");
                            }
                        }
                    }
                }
            }
        }
        prev_low = button_low;

        if let Some(packet) = comm.receive_packet() {
            // 기본 검증
            if packet.version != 1 {
                esp_println::println!("버전 불일치 - 차단");
                continue;
            }

            // 세션(boot_id) 변경 감지 시 카운터 리셋
            if last_boot_id != Some(packet.boot_id) {
                last_boot_id = Some(packet.boot_id);
                last_counter = None;
            }
            if let Some(last) = last_counter {
                if packet.counter <= last {
                    esp_println::println!("리플레이 의심 - 차단");
                    continue;
                }
            }

            match packet.payload_type {
                PacketType::Handshake => {
                    if pending_pairing.is_some() || pending_sign.is_some() {
                        esp_println::println!("이미 처리 중인 요청이 있습니다.");
                        continue;
                    }
                    // 페어링 요청 화면 표시
                    ui.display_pairing_request(None);
                    pending_pairing = Some(PendingPairing {
                        counter: packet.counter,
                        boot_id: packet.boot_id,
                    });
                    last_counter = Some(packet.counter);
                }
                PacketType::SignRequest => {
                    if packet.ciphertext_len as usize != 32 {
                        esp_println::println!("페이로드 길이 오류 - 차단");
                        continue;
                    }

                    // 복호화 (auth_tag가 0이면 평문으로 처리)
                    let (payload_buf, payload_len) = match crypto::decrypt_payload(
                        packet.boot_id,
                        packet.counter,
                        &packet.ciphertext,
                        packet.ciphertext_len as usize,
                        &packet.auth_tag,
                    ) {
                        Some(v) => v,
                        None => {
                            esp_println::println!("복호화 실패 - 차단");
                            continue;
                        }
                    };

                    last_counter = Some(packet.counter);

                    if pending_sign.is_some() {
                        // 이미 대기 중인 요청이 있으면 큐잉 없이 무시
                        esp_println::println!("이전 서명 요청이 처리 중입니다.");
                        continue;
                    }

                    // SignRequestPayload 우선 디코딩 시도
                    let payload = from_bytes::<SignRequestPayload>(&payload_buf[..payload_len]).ok();
                    let hash = if let Some(p) = payload.as_ref() {
                        ui.display_sign_request_intent(&p.intent, &p.hash);
                        p.hash
                    } else if payload_len == 32 {
                        // 하위 호환: 해시만 온 경우
                        let mut h = [0u8; 32];
                        h.copy_from_slice(&payload_buf[..32]);
                        ui.display_sign_request(&h);
                        h
                    } else {
                        esp_println::println!("페이로드 디코딩 실패");
                        continue;
                    };

                    // 새 요청을 저장하고 버튼 입력을 기다림
                    pending_sign = Some(PendingSign {
                        hash,
                        counter: packet.counter,
                        boot_id: packet.boot_id,
                    });
                    esp_println::println!("서명 요청 대기 중 (버튼 입력 필요)");
                }
                _ => {
                    // 그 외 타입은 무시
                }
            }
        }
    }
}
