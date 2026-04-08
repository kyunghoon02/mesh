use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::{
    ChaCha20Poly1305, Key,
    aead::{AeadInPlace, KeyInit},
};
use common::{
    PacketType, SecurePacket, SerialCommand, SerialFrame, SerialResponse, SignRequestPayload,
    TransactionIntent,
};
use heapless::String as HString;
use k256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use postcard::{from_bytes, to_allocvec, to_slice};
use sha3::{Digest, Keccak256};

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
    match command.as_str() {
        "encode" => run_encode(&mut args),
        "decode" => run_decode(&mut args),
        "wallet-from-key" => run_wallet_from_key(&mut args),
        "wallet-from-mesh-key-file" => run_wallet_from_mesh_key_file(&mut args),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        _ => Err(format!("unknown command: {command}")),
    }
}

fn run_encode(args: &mut Vec<String>) -> Result<(), String> {
    if args.is_empty() {
        return Err("missing encode subcommand".to_string());
    }

    let subcommand = args.remove(0);
    let sequence_id = take_option(args, "--seq")
        .map(|v| v.parse::<u32>().map_err(|_| format!("invalid seq: {v}")))
        .transpose()?
        .unwrap_or_else(next_seq);

    let frame = match subcommand.as_str() {
        "status" => SerialFrame::new(SerialCommand::GetStatus, sequence_id, &[]),
        "enter-pairing" => SerialFrame::new(SerialCommand::EnterPairing, sequence_id, &[]),
        "peer" => SerialFrame::new(SerialCommand::GetPeerInfo, sequence_id, &[]),
        "pair" => {
            let mac_text = take_option(args, "--node-a-mac")
                .or_else(|| take_option(args, "--mac"))
                .ok_or("missing --node-a-mac AA:BB:CC:DD:EE:FF")?;
            let mac = parse_mac(&mac_text)?;
            SerialFrame::new(SerialCommand::ConfirmPairing, sequence_id, &mac)
        }
        "sign-demo" => {
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
            let summary =
                take_option(args, "--summary").unwrap_or_else(|| DEFAULT_SUMMARY.to_string());
            let counter = take_option(args, "--counter")
                .map(|v| {
                    v.parse::<u64>()
                        .map_err(|_| format!("invalid counter: {v}"))
                })
                .transpose()?
                .unwrap_or_else(next_counter);

            let aead_key = derive_aead_key_from_address(&wallet_addr);
            let packet = build_demo_sign_packet(
                chain_id,
                target_addr,
                eth_value,
                risk_level,
                &summary,
                counter,
                &aead_key,
            )?;
            let payload =
                to_allocvec(&packet).map_err(|e| format!("failed to serialize packet: {e}"))?;
            SerialFrame::new(SerialCommand::SignRequest, sequence_id, &payload)
        }
        _ => return Err(format!("unknown encode subcommand: {subcommand}")),
    }
    .ok_or("failed to build serial frame")?;

    let frame_bytes = to_allocvec(&frame).map_err(|e| format!("frame encode failed: {e}"))?;
    let mut framed = Vec::with_capacity(frame_bytes.len() + 2);
    framed.extend_from_slice(&(frame_bytes.len() as u16).to_le_bytes());
    framed.extend_from_slice(&frame_bytes);
    println!("{}", hex::encode(framed));
    Ok(())
}

fn run_decode(args: &mut Vec<String>) -> Result<(), String> {
    let hex_text = take_option(args, "--hex").ok_or("missing --hex <response bytes>")?;
    let wallet = take_option(args, "--wallet");
    let bytes = hex::decode(hex_text.trim()).map_err(|_| "invalid hex input".to_string())?;
    if bytes.len() < 2 {
        return Err("response too short".to_string());
    }

    let resp_len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
    if bytes.len() < 2 + resp_len {
        return Err(format!(
            "response length mismatch: expected {} payload bytes, got {}",
            resp_len,
            bytes.len().saturating_sub(2)
        ));
    }

    let response = from_bytes::<SerialResponse>(&bytes[2..2 + resp_len])
        .map_err(|e| format!("failed to decode SerialResponse: {e}"))?;

    println!("sequence_id={}", response.sequence_id);
    println!("success={}", response.success);
    println!("error_code={}", response.error_code);
    println!("error_name={}", hardware_error_name(response.error_code));

    if !response.success {
        return Ok(());
    }

    let payload = response.payload_bytes();
    println!("payload_len={}", payload.len());

    if payload.len() == 1 {
        println!("status={}", payload[0]);
        println!("status_name={}", status_name(payload[0]));
        return Ok(());
    }

    if payload.len() == 6 {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(payload);
        println!("peer_mac={}", format_mac(&mac));
        return Ok(());
    }

    if let Ok(inner) = from_bytes::<SecurePacket>(payload) {
        println!("inner_packet_type={:?}", inner.payload_type);
        println!("inner_counter={}", inner.counter);
        println!("inner_boot_id={}", inner.boot_id);
        println!("inner_ciphertext_len={}", inner.ciphertext_len);

        if let Some(wallet) = wallet {
            let wallet_addr = parse_address(&wallet)?;
            let aead_key = derive_aead_key_from_address(&wallet_addr);
            if let Some(plain) = decrypt_packet_payload(&inner, &aead_key) {
                println!("inner_plain_hex=0x{}", hex::encode(&plain));
                if let Ok(text) = core::str::from_utf8(&plain) {
                    println!("inner_plain_text={text}");
                }
                if inner.payload_type == PacketType::SignResponse && plain.len() == 65 {
                    println!("signature=0x{}", hex::encode(&plain));
                }
            } else {
                println!("inner_plain_text=<decrypt failed>");
            }
        }

        return Ok(());
    }

    if let Ok(text) = core::str::from_utf8(payload) {
        println!("payload_text={text}");
    } else {
        println!("payload_hex=0x{}", hex::encode(payload));
    }

    Ok(())
}

fn run_wallet_from_key(args: &mut Vec<String>) -> Result<(), String> {
    let key_hex = take_option(args, "--key-hex").ok_or("missing --key-hex <64 hex chars>")?;
    let key = parse_secret_key(&key_hex)?;
    println!("{}", wallet_from_secret_key(&key)?);
    Ok(())
}

fn run_wallet_from_mesh_key_file(args: &mut Vec<String>) -> Result<(), String> {
    let path = take_option(args, "--file").ok_or("missing --file <mesh_key_dump.bin>")?;
    let bytes = fs::read(&path).map_err(|e| format!("failed to read {path}: {e}"))?;
    let key = extract_latest_key_from_mesh_key_partition(&bytes)?;
    println!("{}", wallet_from_secret_key(&key)?);
    Ok(())
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
        .expect("demo payload encryption should succeed");

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

fn parse_secret_key(value: &str) -> Result<[u8; 32], String> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    if trimmed.len() != 64 {
        return Err(format!("invalid secret key length: {}", value.len()));
    }

    let bytes = hex::decode(trimmed).map_err(|_| "invalid secret key hex".to_string())?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn wallet_from_secret_key(secret_bytes: &[u8; 32]) -> Result<String, String> {
    let secret = SecretKey::from_slice(secret_bytes)
        .map_err(|_| "invalid secp256k1 secret key".to_string())?;
    let public = secret.public_key();
    let encoded = public.to_encoded_point(false);
    let public_bytes = &encoded.as_bytes()[1..];

    let hash = Keccak256::digest(public_bytes);
    Ok(format!("0x{}", hex::encode(&hash[12..32])))
}

fn extract_latest_key_from_mesh_key_partition(bytes: &[u8]) -> Result<[u8; 32], String> {
    const SLOT_SIZE: usize = 64;
    const MAGIC_BYTE: u8 = 0xA5;

    if bytes.len() < SLOT_SIZE {
        return Err("mesh_key dump is too small".to_string());
    }

    let mut best_counter: Option<u32> = None;
    let mut best_key: Option<[u8; 32]> = None;

    for slot in bytes.chunks_exact(SLOT_SIZE) {
        if slot[0] == 0xFF || slot[0] != MAGIC_BYTE {
            continue;
        }

        let counter = u32::from_le_bytes([slot[1], slot[2], slot[3], slot[4]]);
        if best_counter.is_none_or(|prev| counter >= prev) {
            let mut key = [0u8; 32];
            key.copy_from_slice(&slot[5..37]);
            best_counter = Some(counter);
            best_key = Some(key);
        }
    }

    best_key.ok_or("no wallet key found in mesh_key dump".to_string())
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
    println!("nodeb_codec commands:");
    println!("  encode status [--seq N]");
    println!("  encode enter-pairing [--seq N]");
    println!("  encode peer [--seq N]");
    println!("  encode pair --node-a-mac F0:F5:BD:44:8D:60 [--seq N]");
    println!(
        "  encode sign-demo --wallet 0x... [--to 0x1111111111111111111111111111111111111111] [--value-wei 0] [--chain-id 11155111] [--risk 0] [--summary \"Mesh demo transfer\"] [--seq N] [--counter N]"
    );
    println!("  decode --hex <response bytes> [--wallet 0x...]");
    println!("  wallet-from-key --key-hex <64 hex chars>");
    println!("  wallet-from-mesh-key-file --file <mesh_key_dump.bin>");
}
