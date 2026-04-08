#![no_std]
#![no_main]
#![allow(warnings)]

mod comm;
mod crypto;
mod storage;
mod ui;

use core::cell::RefCell;
use core::fmt::Write;

use common::{PacketType, SecurePacket, SignRequestPayload};
use critical_section::Mutex;
use embedded_graphics::{pixelcolor::Rgb565, prelude::{DrawTarget, RgbColor}};
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    delay::Delay,
    gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull},
    rng::Rng,
    time::Instant,
    timer::timg::TimerGroup,
};
use heapless::String;
use mipidsi::{
    Builder,
    interface::{Generic8BitBus, ParallelInterface},
    models::ST7789,
    options::{ColorOrder, Orientation, Rotation},
};
use postcard::from_bytes;

const DISPLAY_WIDTH: u16 = 170;
const DISPLAY_HEIGHT: u16 = 320;
const DISPLAY_OFFSET_X: u16 = 35;
const DISPLAY_OFFSET_Y: u16 = 0;

static BUTTON_PIN: Mutex<RefCell<Option<Input<'static>>>> = Mutex::new(RefCell::new(None));

const PROTOCOL_VERSION: u8 = 1;
const MAX_PAYLOAD_LEN: usize = 192;
const PAIRING_WINDOW_MS: u64 = 5 * 60_000;
const MIN_PRESS_MS: u64 = 50;
const LONG_PRESS_MS: u64 = 1200;
const STATUS_MESSAGE_MS: u64 = 1500;
const REQUEST_TIMEOUT_MS: u64 = 60_000;
const RESPONSE_RETRY_COUNT: usize = 3;
esp_bootloader_esp_idf::esp_app_desc!();

struct PendingSign {
    hash: [u8; 32],
    counter: u64,
    boot_id: u32,
    requested_at_ms: u64,
}

struct PendingPairing {
    counter: u64,
    boot_id: u32,
    peer_mac: [u8; 6],
    requested_at_ms: u64,
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

fn now_ms() -> u64 {
    Instant::now().duration_since_epoch().as_millis()
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

    if *last_boot_id != Some(packet.boot_id) {
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

#[esp_hal::main]
fn main() -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    esp_alloc::heap_allocator!(size: 96 * 1024);
    let mut rng = Rng::new(peripherals.RNG);

    let user_btn = Input::new(
        peripherals.GPIO14,
        InputConfig::default().with_pull(Pull::Up),
    );
    critical_section::with(|cs| {
        BUTTON_PIN.borrow(cs).replace(Some(user_btn));
    });

    let _lcd_power = Output::new(peripherals.GPIO15, Level::High, OutputConfig::default());
    let mut bl = Output::new(peripherals.GPIO38, Level::Low, OutputConfig::default());
    let _ = bl.set_high();

    let _lcd_cs = Output::new(peripherals.GPIO6, Level::Low, OutputConfig::default());
    let _lcd_rd = Output::new(peripherals.GPIO9, Level::High, OutputConfig::default());
    let dc = Output::new(peripherals.GPIO7, Level::Low, OutputConfig::default());
    let wr = Output::new(peripherals.GPIO8, Level::High, OutputConfig::default());
    let rst = Output::new(peripherals.GPIO5, Level::High, OutputConfig::default());

    let d0 = Output::new(peripherals.GPIO39, Level::Low, OutputConfig::default());
    let d1 = Output::new(peripherals.GPIO40, Level::Low, OutputConfig::default());
    let d2 = Output::new(peripherals.GPIO41, Level::Low, OutputConfig::default());
    let d3 = Output::new(peripherals.GPIO42, Level::Low, OutputConfig::default());
    let d4 = Output::new(peripherals.GPIO45, Level::Low, OutputConfig::default());
    let d5 = Output::new(peripherals.GPIO46, Level::Low, OutputConfig::default());
    let d6 = Output::new(peripherals.GPIO47, Level::Low, OutputConfig::default());
    let d7 = Output::new(peripherals.GPIO48, Level::Low, OutputConfig::default());

    let bus = Generic8BitBus::new((d0, d1, d2, d3, d4, d5, d6, d7));
    let di = ParallelInterface::new(bus, dc, wr);
    let mut delay = Delay::new();

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

    let km = if let Some(key) = storage.load_key() {
        crypto::KeyManager {
            secret_key: k256::SecretKey::from_slice(&key).unwrap(),
        }
    } else {
        let new_km = crypto::KeyManager::generate_new(&mut rng);
        storage
            .save_key(&new_km.secret_key.to_bytes().into())
            .expect("key save failed");
        new_km
    };

    let addr = km.get_eth_address();
    let aead_key = crypto::KeyManager::derive_aead_key_from_address(&addr);
    let mut addr_str: String<42> = String::new();
    let _ = write!(addr_str, "0x");
    for b in addr {
        let _ = write!(addr_str, "{:02x}", b);
    }
    ui.display_address(&addr_str);

    let stored_peer_mac = storage.load_peer_mac();
    let mut has_paired_peer = stored_peer_mac.is_some();
    let mut current_peer_mac = stored_peer_mac.unwrap_or([0u8; 6]);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let wifi_init = esp_wifi::init(timg0.timer0, rng).expect("esp-wifi init failed");
    let (mut wifi_controller, interfaces) =
        esp_wifi::wifi::new(&wifi_init, peripherals.WIFI).expect("esp-now init failed");
    wifi_controller
        .set_mode(esp_wifi::wifi::WifiMode::Sta)
        .expect("wifi sta mode failed");
    wifi_controller.start().expect("wifi start failed");
    let esp_now = interfaces.esp_now;
    let mut comm = comm::CommManager::new(esp_now, current_peer_mac);

    let mut pending_sign: Option<PendingSign> = None;
    let mut pending_pairing: Option<PendingPairing> = None;
    let mut last_counter: Option<u64> = None;
    let mut last_boot_id: Option<u32> = None;
    let pairing_deadline_ms = u64::MAX;
    let mut press_start_ms: Option<u64> = None;
    let mut prev_low = false;
    let mut return_to_home_at_ms: Option<u64> = None;

    loop {
        let button_low = critical_section::with(|cs| {
            let mut btn = BUTTON_PIN.borrow(cs).borrow_mut();
            btn.as_mut().map(|p| p.is_low()).unwrap_or(false)
        });

        let current_time_ms = now_ms();

        if button_low && !prev_low {
            press_start_ms = Some(current_time_ms);
        }

        if !has_paired_peer && current_time_ms > pairing_deadline_ms && pending_pairing.is_some() {
            pending_pairing = None;
            ui.display_message("Pairing", "Request expired", "Hold to retry");
            return_to_home_at_ms = Some(current_time_ms + STATUS_MESSAGE_MS);
        }

        if let Some(pending) = pending_pairing.as_ref() {
            if current_time_ms.saturating_sub(pending.requested_at_ms) >= REQUEST_TIMEOUT_MS {
                pending_pairing = None;
                ui.display_message("Pairing", "Request timed out", "Back to wallet");
                return_to_home_at_ms = Some(current_time_ms + STATUS_MESSAGE_MS);
            }
        }

        if let Some(pending) = pending_sign.as_ref() {
            if current_time_ms.saturating_sub(pending.requested_at_ms) >= REQUEST_TIMEOUT_MS {
                pending_sign = None;
                ui.display_message("Signing", "Request timed out", "Back to wallet");
                return_to_home_at_ms = Some(current_time_ms + STATUS_MESSAGE_MS);
            }
        }

        if !button_low && prev_low {
            if let Some(start) = press_start_ms.take() {
                let duration = current_time_ms.saturating_sub(start);

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
                            ui.display_message("Pairing", "Long press", "Request denied");
                            has_paired_peer = false;
                            current_peer_mac = pair.peer_mac;
                        } else {
                            ui.display_message("Pairing", "Deny sent failed", "Back to wallet");
                        }
                        return_to_home_at_ms = Some(current_time_ms + STATUS_MESSAGE_MS);
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
                            ui.display_message("Signing", "Long press", "Request denied");
                        } else {
                            ui.display_message("Signing", "Deny send failed", "Back to wallet");
                        }
                        return_to_home_at_ms = Some(current_time_ms + STATUS_MESSAGE_MS);
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
                                ui.display_message("Pairing", "Short press", "Approved");
                            } else {
                                ui.display_message("Pairing", "Approved", "Reply send failed");
                            }
                            return_to_home_at_ms = Some(current_time_ms + STATUS_MESSAGE_MS);
                        } else {
                            ui.display_message("Pairing", "Save failed", "Retry needed");
                            return_to_home_at_ms = Some(current_time_ms + STATUS_MESSAGE_MS);
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
                                ui.display_message("Signing", "Short press", "Approved");
                            } else {
                                ui.display_message("Signing", "Approve failed", "Back to wallet");
                            }
                            return_to_home_at_ms = Some(current_time_ms + STATUS_MESSAGE_MS);
                        } else {
                            ui.display_message("Signing", "Sign failed", "Back to wallet");
                            return_to_home_at_ms = Some(current_time_ms + STATUS_MESSAGE_MS);
                        }
                    } else {
                        ui.display_address(&addr_str);
                        return_to_home_at_ms = None;
                    }
                }
            }
        }
        prev_low = button_low;

        if let Some(deadline_ms) = return_to_home_at_ms {
            if current_time_ms >= deadline_ms
                && pending_pairing.is_none()
                && pending_sign.is_none()
                && !button_low
            {
                ui.display_address(&addr_str);
                return_to_home_at_ms = None;
            }
        }

        if let Some(envelope) = comm.receive_packet_with_src() {
            let packet = envelope.packet;
            let src_addr = envelope.src_addr;
            let is_trusted_src = envelope.trusted;

            if !is_replay_and_nonce_valid(&packet, &mut last_boot_id, &mut last_counter) {
                esp_println::println!("packet rejected: version/counter check failed");
                continue;
            }

            if has_paired_peer && !is_trusted_src {
                esp_println::println!("packet rejected: untrusted mac {:?}", src_addr);
                continue;
            }

            match packet.payload_type {
                PacketType::Handshake => {
                    if pending_pairing.is_some() || pending_sign.is_some() {
                        esp_println::println!("handshake ignored: busy");
                        continue;
                    }

                    if current_time_ms > pairing_deadline_ms {
                        esp_println::println!("handshake ignored: pairing window closed");
                        continue;
                    }

                    if has_paired_peer {
                        esp_println::println!("handshake ignored: already paired");
                        continue;
                    }

                    if packet.ciphertext_len as usize != 0 {
                        esp_println::println!("handshake ignored: invalid payload len");
                        continue;
                    }

                    let hint = format_mac(&src_addr);
                    ui.display_pairing_request(Some(hint.as_str()));
                    pending_pairing = Some(PendingPairing {
                        counter: packet.counter,
                        boot_id: packet.boot_id,
                        peer_mac: src_addr,
                        requested_at_ms: current_time_ms,
                    });
                    return_to_home_at_ms = None;
                }

                PacketType::SignRequest => {
                    if !is_valid_sign_request_packet(&packet) {
                        esp_println::println!("sign request ignored: invalid packet");
                        continue;
                    }

                    if !has_paired_peer {
                        esp_println::println!("sign request ignored: not paired");
                        continue;
                    }

                    if pending_sign.is_some() {
                        esp_println::println!("sign request ignored: pending");
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
                            esp_println::println!("sign request ignored: decrypt failed");
                            continue;
                        }
                    };

                    let payload =
                        match from_bytes::<SignRequestPayload>(&payload_buf[..payload_len]) {
                            Ok(v) => v,
                            Err(_) => {
                                esp_println::println!("sign request ignored: decode failed");
                                continue;
                            }
                        };

                    ui.display_sign_request_intent(&payload.intent, &payload.hash);

                    pending_sign = Some(PendingSign {
                        hash: payload.hash,
                        counter: packet.counter,
                        boot_id: packet.boot_id,
                        requested_at_ms: current_time_ms,
                    });
                    return_to_home_at_ms = None;
                    esp_println::println!("sign request pending user approval");
                }

                PacketType::SignResponse | PacketType::ErrorMessage => {
                    esp_println::println!("response packet ignored on signer");
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

    let mut unicast_ok = false;
    for _ in 0..RESPONSE_RETRY_COUNT {
        if comm.send_packet(&pkt).is_ok() {
            unicast_ok = true;
        }
        let _ = comm.send_packet_to(comm::BROADCAST_MAC, &pkt);
    }
    comm.update_peer_address(prev_peer);
    unicast_ok
}
