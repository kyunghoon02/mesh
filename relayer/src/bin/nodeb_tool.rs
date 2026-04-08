use std::env;
use std::io::{Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chacha20poly1305::{
    ChaCha20Poly1305, Key,
    aead::{AeadInPlace, KeyInit},
};
use common::{
    PacketType, SecurePacket, SerialCommand, SerialFrame, SerialResponse, SignRequestPayload,
    TransactionIntent,
};
use heapless::String as HString;
use postcard::{from_bytes, to_allocvec, to_slice};
use serialport::{DataBits, FlowControl, Parity, SerialPort, StopBits};
use sha3::{Digest, Keccak256};

const DEFAULT_PORT: &str = "COM4";
const DEFAULT_BAUD: u32 = 115_200;
const DEFAULT_CHAIN_ID: u64 = 11155111;
const DEFAULT_RISK: u8 = 0;
const DEFAULT_TO: &str = "0x1111111111111111111111111111111111111111";
const DEFAULT_SUMMARY: &str = "Mesh demo transfer";

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        print_usage();
        return Ok(());
    }

    let command = args.remove(0);
    let port = take_option(&mut args, "--port").unwrap_or_else(|| DEFAULT_PORT.to_string());
    let baud = take_option(&mut args, "--baud")
        .map(|v| v.parse::<u32>().map_err(|_| format!("invalid baud: {v}")))
        .transpose()?
        .unwrap_or(DEFAULT_BAUD);

    match command.as_str() {
        "status" => run_status(&port, baud),
        "pair" => run_pair(&port, baud, &mut args),
        "peer" => run_peer(&port, baud),
        "sign-demo" => run_sign_demo(&port, baud, &mut args),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        _ => Err(format!("unknown command: {command}")),
    }
}

fn run_status(port: &str, baud: u32) -> Result<(), String> {
    let mut link = SerialLink::open(port, baud)?;
    let frame = SerialFrame::new(SerialCommand::GetStatus, next_seq(), &[])
        .ok_or("failed to build GetStatus frame")?;
    let response = link.send_frame(&frame)?;
    let payload = ensure_success(response, "status")?;
    let status = *payload.first().ok_or("empty status payload")?;
    println!("status={} ({})", status, status_name(status));
    Ok(())
}

fn run_pair(port: &str, baud: u32, args: &mut Vec<String>) -> Result<(), String> {
    let mac_text = take_option(args, "--node-a-mac")
        .or_else(|| take_option(args, "--mac"))
        .ok_or("missing --node-a-mac AA:BB:CC:DD:EE:FF")?;
    let mac = parse_mac(&mac_text)?;

    let mut link = SerialLink::open(port, baud)?;
    let frame = SerialFrame::new(SerialCommand::ConfirmPairing, next_seq(), &mac)
        .ok_or("failed to build ConfirmPairing frame")?;
    let response = link.send_frame(&frame)?;
    let payload = ensure_success(response, "pair")?;

    println!("pair response: {}", String::from_utf8_lossy(&payload));
    println!("paired mac: {}", format_mac(&mac));
    Ok(())
}

fn run_peer(port: &str, baud: u32) -> Result<(), String> {
    let mut link = SerialLink::open(port, baud)?;
    let frame = SerialFrame::new(SerialCommand::GetPeerInfo, next_seq(), &[])
        .ok_or("failed to build GetPeerInfo frame")?;
    let response = link.send_frame(&frame)?;
    let payload = ensure_success(response, "peer query")?;

    if payload.len() != 6 {
        return Err(format!("unexpected peer payload length: {}", payload.len()));
    }

    let mut mac = [0u8; 6];
    mac.copy_from_slice(&payload);
    println!("peer mac: {}", format_mac(&mac));
    Ok(())
}

fn run_sign_demo(port: &str, baud: u32, args: &mut Vec<String>) -> Result<(), String> {
    let wallet =
        take_option(args, "--wallet").ok_or("missing --wallet 0x... from Node A screen")?;
    let wallet_addr = parse_address(&wallet)?;
    let target = take_option(args, "--to").unwrap_or_else(|| DEFAULT_TO.to_string());
    let target_addr = parse_address(&target)?;
    let chain_id = take_option(args, "--chain-id")
        .map(|v| {
            v.parse::<u64>()
                .map_err(|_| format!("invalid chain id: {v}"))
        })
        .transpose()?
        .unwrap_or(DEFAULT_CHAIN_ID);
    let eth_value = take_option(args, "--value-wei")
        .map(|v| v.parse::<u128>().map_err(|_| format!("invalid value: {v}")))
        .transpose()?
        .unwrap_or(0);
    let risk_level = take_option(args, "--risk")
        .map(|v| v.parse::<u8>().map_err(|_| format!("invalid risk: {v}")))
        .transpose()?
        .unwrap_or(DEFAULT_RISK);
    let summary = take_option(args, "--summary").unwrap_or_else(|| DEFAULT_SUMMARY.to_string());

    let mut link = SerialLink::open(port, baud)?;
    let aead_key = derive_aead_key_from_address(&wallet_addr);
    let sequence_id = next_seq();
    let counter = next_counter();
    let packet = build_demo_sign_packet(
        chain_id,
        target_addr,
        eth_value,
        risk_level,
        &summary,
        counter,
        &aead_key,
    )?;

    println!("sending sign request...");
    println!("wallet: {}", hex_address(&wallet_addr));
    println!("to: {}", hex_address(&target_addr));
    println!("value wei: {eth_value}");
    println!("risk: {risk_level}");
    println!("summary: {summary}");
    println!("approve on Node A with short press, reject with long press.");

    let payload = to_allocvec(&packet).map_err(|e| format!("failed to serialize packet: {e}"))?;
    let frame = SerialFrame::new(SerialCommand::SignRequest, sequence_id, &payload)
        .ok_or("failed to build SignRequest frame")?;
    let response = link.send_frame(&frame)?;
    let inner_payload = ensure_success(response, "sign request")?;
    let inner = from_bytes::<SecurePacket>(&inner_payload)
        .map_err(|e| format!("failed to decode inner packet: {e}"))?;

    match inner.payload_type {
        PacketType::SignResponse => {
            let signature = decrypt_packet_payload(&inner, &aead_key)
                .ok_or("failed to decrypt sign response")?;
            println!("sign approved");
            println!("signature: 0x{}", hex::encode(&signature));
            Ok(())
        }
        PacketType::ErrorMessage => {
            let message = decrypt_packet_payload(&inner, &aead_key)
                .ok_or("failed to decrypt error response")?;
            println!(
                "device returned error: {}",
                String::from_utf8_lossy(&message)
            );
            Ok(())
        }
        other => Err(format!("unexpected packet type in response: {:?}", other)),
    }
}

struct SerialLink {
    port: Box<dyn SerialPort>,
}

impl SerialLink {
    fn open(port: &str, baud: u32) -> Result<Self, String> {
        let port = serialport::new(port, baud)
            .data_bits(DataBits::Eight)
            .stop_bits(StopBits::One)
            .parity(Parity::None)
            .flow_control(FlowControl::None)
            .timeout(Duration::from_secs(12))
            .open()
            .map_err(|e| e.to_string())?;
        Ok(Self { port })
    }

    fn send_frame(&mut self, frame: &SerialFrame) -> Result<SerialResponse, String> {
        let bytes = to_allocvec(frame).map_err(|e| format!("frame encode failed: {e}"))?;
        let len = (bytes.len() as u16).to_le_bytes();

        self.port.write_all(&len).map_err(|e| e.to_string())?;
        self.port.write_all(&bytes).map_err(|e| e.to_string())?;
        self.port.flush().map_err(|e| e.to_string())?;

        let mut len_buf = [0u8; 2];
        self.port
            .read_exact(&mut len_buf)
            .map_err(|e| format!("response length read failed: {e}"))?;

        let resp_len = u16::from_le_bytes(len_buf) as usize;
        if resp_len == 0 || resp_len > 1024 {
            return Err(format!("invalid response length: {resp_len}"));
        }

        let mut resp_buf = vec![0u8; resp_len];
        self.port
            .read_exact(&mut resp_buf)
            .map_err(|e| format!("response body read failed: {e}"))?;

        from_bytes::<SerialResponse>(&resp_buf).map_err(|e| format!("response decode failed: {e}"))
    }
}

fn ensure_success(response: SerialResponse, label: &str) -> Result<Vec<u8>, String> {
    if !response.success {
        return Err(format!(
            "{} failed: error_code={} ({})",
            label,
            response.error_code,
            hardware_error_name(response.error_code)
        ));
    }

    Ok(response.payload_bytes().to_vec())
}

fn build_demo_sign_packet(
    chain_id: u64,
    target_address: [u8; 20],
    eth_value: u128,
    risk_level: u8,
    summary: &str,
    counter: u64,
    aead_key: &[u8; 32],
) -> Result<SecurePacket, String> {
    let mut summary_text: HString<64> = HString::new();
    summary_text
        .push_str(summary)
        .map_err(|_| "summary too long; max 64 bytes".to_string())?;

    let intent = TransactionIntent {
        chain_id,
        target_address,
        eth_value,
        risk_level,
        summary: summary_text,
    };

    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(b"mesh-demo-sign");
    hash_input.extend_from_slice(&chain_id.to_be_bytes());
    hash_input.extend_from_slice(&target_address);
    hash_input.extend_from_slice(&eth_value.to_be_bytes());
    hash_input.push(risk_level);
    hash_input.extend_from_slice(summary.as_bytes());

    let hash = Keccak256::digest(&hash_input);
    let mut request_hash = [0u8; 32];
    request_hash.copy_from_slice(&hash);

    let payload_struct = SignRequestPayload {
        hash: request_hash,
        intent,
    };
    let mut plain_buf = [0u8; 192];
    let plain = to_slice(&payload_struct, &mut plain_buf)
        .map_err(|e| format!("failed to serialize sign payload: {e}"))?;

    let boot_id = 1u32;
    let (ciphertext, tag) = encrypt_payload(boot_id, counter, plain, aead_key);
    let mut packet = SecurePacket::new(PacketType::SignRequest, &ciphertext[..plain.len()], tag)
        .ok_or("failed to build secure packet")?;
    packet.boot_id = boot_id;
    packet.counter = counter;
    Ok(packet)
}

fn encrypt_payload(
    boot_id: u32,
    counter: u64,
    plain: &[u8],
    aead_key: &[u8; 32],
) -> ([u8; 192], [u8; 16]) {
    let mut buf = [0u8; 192];
    buf[..plain.len()].copy_from_slice(plain);

    let key = Key::from_slice(aead_key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = build_nonce(boot_id, counter);
    let tag = cipher
        .encrypt_in_place_detached(&nonce, b"", &mut buf[..plain.len()])
        .expect("encryption should succeed for demo payload");

    (buf, tag.into())
}

fn decrypt_packet_payload(packet: &SecurePacket, aead_key: &[u8; 32]) -> Option<Vec<u8>> {
    let cipher_len = packet.ciphertext_len as usize;
    if cipher_len == 0 || cipher_len > packet.ciphertext.len() {
        return None;
    }

    let mut buf = [0u8; 192];
    buf[..cipher_len].copy_from_slice(&packet.ciphertext[..cipher_len]);

    let key = Key::from_slice(aead_key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = build_nonce(packet.boot_id, packet.counter);

    cipher
        .decrypt_in_place_detached(
            &nonce,
            b"",
            &mut buf[..cipher_len],
            chacha20poly1305::Tag::from_slice(&packet.auth_tag),
        )
        .ok()?;

    Some(buf[..cipher_len].to_vec())
}

fn build_nonce(boot_id: u32, counter: u64) -> chacha20poly1305::Nonce {
    let mut out = [0u8; 12];
    out[..4].copy_from_slice(&boot_id.to_be_bytes());
    out[4..].copy_from_slice(&counter.to_be_bytes());
    chacha20poly1305::Nonce::clone_from_slice(&out)
}

fn derive_aead_key_from_address(address: &[u8; 20]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(address);
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

fn take_option(args: &mut Vec<String>, name: &str) -> Option<String> {
    let index = args.iter().position(|arg| arg == name)?;
    if index + 1 >= args.len() {
        return None;
    }
    let value = args.remove(index + 1);
    args.remove(index);
    Some(value)
}

fn parse_mac(value: &str) -> Result<[u8; 6], String> {
    let parts = value.split([':', '-']).collect::<Vec<_>>();
    if parts.len() != 6 {
        return Err(format!("invalid mac address: {value}"));
    }

    let mut out = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(part, 16).map_err(|_| format!("invalid mac byte: {part}"))?;
    }
    Ok(out)
}

fn parse_address(value: &str) -> Result<[u8; 20], String> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    if trimmed.len() != 40 {
        return Err(format!("invalid address length: {value}"));
    }

    let bytes = hex::decode(trimmed).map_err(|_| format!("invalid hex address: {value}"))?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn hex_address(address: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(address))
}

fn next_seq() -> u32 {
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        & 0xffff_ffff) as u32
}

fn next_counter() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn status_name(status: u8) -> &'static str {
    match status {
        0 => "Unpaired",
        1 => "Pairing",
        2 => "Ready",
        _ => "Unknown",
    }
}

fn hardware_error_name(code: u8) -> &'static str {
    match code {
        common::error_codes::SUCCESS => "SUCCESS",
        common::error_codes::INVALID_STATE => "INVALID_STATE",
        common::error_codes::NOT_PAIRED => "NOT_PAIRED",
        common::error_codes::PAIRING_TIMEOUT => "PAIRING_TIMEOUT",
        common::error_codes::ESPNOW_ERROR => "ESPNOW_ERROR",
        common::error_codes::TIMEOUT => "TIMEOUT",
        common::error_codes::INVALID_COMMAND => "INVALID_COMMAND",
        _ => "UNKNOWN",
    }
}

fn print_usage() {
    println!("nodeb_tool commands:");
    println!("  status [--port COM4] [--baud 115200]");
    println!("  pair --node-a-mac F0:F5:BD:44:8D:60 [--port COM4]");
    println!("  peer [--port COM4]");
    println!(
        "  sign-demo --wallet 0x... [--to 0x1111111111111111111111111111111111111111] [--value-wei 0] [--chain-id 11155111] [--risk 0] [--summary \"Mesh demo transfer\"] [--port COM4]"
    );
}
