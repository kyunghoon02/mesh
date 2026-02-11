use std::sync::{
    atomic::{AtomicU32, AtomicU64, Ordering},
    Arc,
};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use tokio_postgres::{Client as PgClient, NoTls};
use tracing::{error, info, warn};

use common::{PacketType, SecurePacket};

mod serial;
use serial::SerialClient;

#[derive(Clone)]
struct AppState {
    upstream: String,
    eoa_address: String,
    sca_address: String,
    factory_address: Option<String>,
    db: Option<Arc<PgClient>>,
    chain_id: Option<u64>,
    approval_mode: ApprovalMode,
    serial: Option<SerialClient>,
    seq: Arc<AtomicU32>,
    counter: Arc<AtomicU64>,
    client: reqwest::Client,
}

#[derive(Clone, Copy)]
enum ApprovalMode {
    Pass,
    Block,
}

impl ApprovalMode {
    fn from_env() -> Self {
        match std::env::var("APPROVAL_MODE")
            .unwrap_or_else(|_| "pass".to_string())
            .to_lowercase()
            .as_str()
        {
            "block" => ApprovalMode::Block,
            _ => ApprovalMode::Pass,
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    // 필수: 업스트림 RPC
    let upstream = std::env::var("UPSTREAM_RPC").unwrap_or_default();
    let eoa_address = std::env::var("EOA_ADDRESS").unwrap_or_default();
    let sca_address = std::env::var("SCA_ADDRESS").unwrap_or_default();
    let factory_address = std::env::var("FACTORY_ADDRESS").ok();
    let db_url = std::env::var("DATABASE_URL").ok();
    // 선택: 바인딩 주소
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    // 선택: Node B Serial 연결
    let serial_port = std::env::var("SERIAL_PORT").ok();
    let serial_baud: u32 = std::env::var("SERIAL_BAUD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(115_200);

    let serial = match serial_port.as_deref() {
        Some(port) => match SerialClient::open(port, serial_baud).await {
            Ok(c) => {
                info!("serial connected: {} @{}", port, serial_baud);
                Some(c)
            }
            Err(e) => {
                warn!("serial open failed: {}", e);
                None
            }
        },
        None => None,
    };

    if upstream.is_empty() {
        eprintln!("Missing env var: UPSTREAM_RPC. Server will still start but will return 500.");
    }
    if eoa_address.is_empty() && sca_address.is_empty() {
        eprintln!("Missing env vars: EOA_ADDRESS or SCA_ADDRESS.");
    }

    let client = reqwest::Client::new();
    let chain_id = match std::env::var("CHAIN_ID") {
        Ok(v) => parse_chain_id_str(&v),
        Err(_) => {
            if upstream.is_empty() {
                None
            } else {
                fetch_chain_id(&client, &upstream).await
            }
        }
    };

    let db = match db_url {
        Some(url) => init_db(&url).await,
        None => None,
    };

    let state = Arc::new(AppState {
        upstream,
        eoa_address,
        sca_address,
        factory_address,
        db,
        chain_id,
        approval_mode: ApprovalMode::from_env(),
        serial,
        seq: Arc::new(AtomicU32::new(1)),
        counter: Arc::new(AtomicU64::new(1)),
        client,
    });

    let app = Router::new().route("/", post(rpc_handler)).with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("bind failed");

    info!("relayer listening on {}", bind_addr);
    axum::serve(listener, app).await.unwrap();
}

async fn rpc_handler(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let value: Value = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let response = if value.is_array() {
        let mut responses = Vec::new();
        for req in value.as_array().unwrap() {
            if let Some(resp) = handle_single(req, &state).await {
                responses.push(resp);
            }
        }
        if responses.is_empty() {
            Value::Null
        } else {
            Value::Array(responses)
        }
    } else {
        match handle_single(&value, &state).await {
            Some(resp) => resp,
            None => Value::Null,
        }
    };

    let mut res = Json(response).into_response();
    res.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(res)
}

async fn handle_single(req: &Value, state: &AppState) -> Option<Value> {
    let obj = req.as_object()?;
    let has_id = obj.contains_key("id");
    let id = obj.get("id").cloned().unwrap_or(Value::Null);

    // Notifications: no response
    if !has_id || id.is_null() {
        return None;
    }

    let method = obj.get("method")?.as_str()?;

    if method == "eth_accounts" || method == "eth_requestAccounts" {
        let addr = resolve_account(state).await;
        return Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": [addr],
        }));
    }

    if method == "mesh_getStatus" {
        if let Some(serial) = &state.serial {
            match serial.get_status().await {
                Ok(status) => {
                    return Some(json!({"jsonrpc":"2.0","id":id,"result": status}));
                }
                Err(e) => {
                    return Some(json!({
                        "jsonrpc":"2.0",
                        "id":id,
                        "error": {"code": -32010, "message": e}
                    }));
                }
            }
        } else {
            return Some(json!({
                "jsonrpc":"2.0",
                "id":id,
                "error": {"code": -32010, "message": "SERIAL_PORT not configured"}
            }));
        }
    }

    if method == "mesh_prepareDeploy" {
        return Some(handle_prepare_deploy(req, state).await);
    }

    if method == "mesh_getChainConfig" {
        return Some(handle_get_chain_config(req, state).await);
    }

    if method == "mesh_setChainConfig" {
        return Some(handle_set_chain_config(req, state).await);
    }

    if method == "eth_sendTransaction" {
        log_send_tx(req);
        if let Some(resp) = send_sign_request_if_possible(state, req, method).await {
            return Some(resp);
        }
    }

    if method == "eth_sendRawTransaction" {
        log_send_raw(req);
        if let Some(resp) = send_sign_request_if_possible(state, req, method).await {
            return Some(resp);
        }
    }

    // Forward any other RPC to upstream
    if state.upstream.is_empty() {
        return Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32000, "message": "UPSTREAM_RPC not configured"}
        }));
    }

    match state
        .client
        .post(&state.upstream)
        .json(req)
        .send()
        .await
    {
        Ok(resp) => match resp.json::<Value>().await {
            Ok(v) => Some(v),
            Err(e) => {
                error!("upstream decode error: {}", e);
                Some(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32000, "message": "upstream decode error"}
                }))
            }
        },
        Err(e) => {
            error!("upstream request error: {}", e);
            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32000, "message": "upstream request failed"}
            }))
        }
    }
}

async fn handle_prepare_deploy(req: &Value, state: &AppState) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let params = req.get("params").and_then(|p| p.as_array());
    let first = params.and_then(|p| p.get(0)).and_then(|v| v.as_object());

    let owner = first
        .and_then(|m| m.get("owner"))
        .and_then(|v| v.as_str())
        .and_then(parse_address);

    let from = first
        .and_then(|m| m.get("from"))
        .and_then(|v| v.as_str())
        .and_then(parse_address);

    let passkey = first
        .and_then(|m| {
            m.get("passkey_pubkey")
                .or_else(|| m.get("passkeyPubkey"))
        })
        .and_then(|v| v.as_str())
        .and_then(parse_hex_bytes);

    let salt = first
        .and_then(|m| m.get("salt"))
        .and_then(|v| v.as_str())
        .and_then(parse_bytes32)
        .unwrap_or([0u8; 32]);

    let factory = first
        .and_then(|m| m.get("factory"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| state.factory_address.clone());

    let owner = match owner {
        Some(v) => v,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "invalid owner"}
            })
        }
    };

    let passkey = match passkey {
        Some(v) => v,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "invalid passkey_pubkey"}
            })
        }
    };

    let factory = match factory {
        Some(v) => v,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "missing factory address"}
            })
        }
    };

    let calldata = encode_create_account(owner, &passkey, salt);
    let data_hex = to_hex(&calldata);

    let mut tx = json!({
        "to": factory,
        "data": data_hex,
        "value": "0x0"
    });

    if let Some(from_addr) = from {
        tx["from"] = Value::String(address_to_hex(from_addr));
    }

    let predicted = if !state.upstream.is_empty() {
        fetch_predicted_address(state, &factory, owner, &passkey, salt).await
    } else {
        None
    };

    json!({
        "jsonrpc":"2.0",
        "id": id,
        "result": {
            "tx": tx,
            "request": {
                "method": "eth_sendTransaction",
                "params": [tx],
                "jsonrpc": "2.0",
                "id": 1
            },
            "predicted_address": predicted
        }
    })
}

async fn handle_get_chain_config(req: &Value, state: &AppState) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let chain_id = extract_chain_id(req).or(state.chain_id);

    let chain_id = match chain_id {
        Some(v) => v,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "missing chain_id"}
            })
        }
    };

    let db = match &state.db {
        Some(db) => db,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32020, "message": "DATABASE_URL not configured"}
            })
        }
    };

    match get_chain_config(db, chain_id).await {
        Ok(Some(cfg)) => json!({
            "jsonrpc":"2.0",
            "id": id,
            "result": cfg
        }),
        Ok(None) => json!({
            "jsonrpc":"2.0",
            "id": id,
            "result": null
        }),
        Err(e) => json!({
            "jsonrpc":"2.0",
            "id": id,
            "error": {"code": -32020, "message": e}
        }),
    }
}

async fn handle_set_chain_config(req: &Value, state: &AppState) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let params = req.get("params").and_then(|p| p.as_array());
    let first = params.and_then(|p| p.get(0)).and_then(|v| v.as_object());

    let chain_id = first
        .and_then(|m| m.get("chain_id"))
        .and_then(parse_chain_id_value)
        .or(state.chain_id);

    let chain_id = match chain_id {
        Some(v) => v,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "missing chain_id"}
            })
        }
    };

    let mode = first
        .and_then(|m| m.get("mode"))
        .and_then(|v| v.as_str())
        .unwrap_or("EOA");

    let sca_address = first
        .and_then(|m| m.get("sca_address"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let factory_address = first
        .and_then(|m| m.get("factory_address"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let status = first
        .and_then(|m| m.get("status"))
        .and_then(|v| v.as_str())
        .unwrap_or("inactive")
        .to_string();

    let db = match &state.db {
        Some(db) => db,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32020, "message": "DATABASE_URL not configured"}
            })
        }
    };

    match upsert_chain_config(db, chain_id, mode, sca_address, factory_address, status).await {
        Ok(_) => json!({
            "jsonrpc":"2.0",
            "id": id,
            "result": true
        }),
        Err(e) => json!({
            "jsonrpc":"2.0",
            "id": id,
            "error": {"code": -32020, "message": e}
        }),
    }
}

async fn send_sign_request_if_possible(
    state: &AppState,
    req: &Value,
    method: &str,
) -> Option<Value> {
    let require_hw = matches!(state.approval_mode, ApprovalMode::Block);

    let serial = match &state.serial {
        Some(s) => s,
        None => {
            if require_hw {
                return Some(json!({
                    "jsonrpc": "2.0",
                    "id": req.get("id").cloned().unwrap_or(Value::Null),
                    "error": {"code": -32011, "message": "SERIAL_PORT not configured"}
                }));
            }
            return None;
        }
    };

    // SecurePacket 생성 (암호화는 추후 구현, 현재는 payload에 축약 데이터만 담음)
    let counter = state.counter.fetch_add(1, Ordering::Relaxed);
    let packet = build_secure_packet(method, req, counter);

    let seq = state.seq.fetch_add(1, Ordering::Relaxed);
    match serial.send_sign_request(seq, &packet).await {
        Ok(resp) => {
            if resp.success {
                None
            } else if require_hw {
                Some(json!({
                    "jsonrpc": "2.0",
                    "id": req.get("id").cloned().unwrap_or(Value::Null),
                    "error": {"code": -32012, "message": format!("hardware rejected: {}", resp.error_code)}
                }))
            } else {
                warn!("hardware rejected: {}", resp.error_code);
                None
            }
        }
        Err(e) => {
            if require_hw {
                Some(json!({
                    "jsonrpc": "2.0",
                    "id": req.get("id").cloned().unwrap_or(Value::Null),
                    "error": {"code": -32012, "message": e}
                }))
            } else {
                warn!("serial send failed: {}", e);
                None
            }
        }
    }
}

fn build_secure_packet(method: &str, req: &Value, counter: u64) -> SecurePacket {
    let mut payload = match method {
        "eth_sendRawTransaction" => req
            .get("params")
            .and_then(|p| p.get(0))
            .and_then(|v| v.as_str())
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default(),
        _ => req
            .get("params")
            .and_then(|p| p.get(0))
            .map(|v| serde_json::to_vec(v).unwrap_or_default())
            .unwrap_or_default(),
    };

    if payload.len() > 192 {
        payload.truncate(192);
    }

    let mut packet = SecurePacket::new(PacketType::SignRequest, &payload, [0u8; 16])
        .unwrap_or_else(|| SecurePacket::new(PacketType::SignRequest, &[], [0u8; 16]).unwrap());
    packet.counter = counter;
    packet
}

fn log_send_tx(req: &Value) {
    let params = req.get("params").and_then(|p| p.as_array());
    let tx = params.and_then(|p| p.get(0)).and_then(|v| v.as_object());
    if let Some(tx) = tx {
        let from = tx.get("from").and_then(|v| v.as_str()).unwrap_or("-");
        let to = tx.get("to").and_then(|v| v.as_str()).unwrap_or("-");
        let value = tx
            .get("value")
            .and_then(|v| v.as_str())
            .and_then(hex_to_u128);
        let data_len = tx
            .get("data")
            .and_then(|v| v.as_str())
            .map(|s| s.len())
            .unwrap_or(0);

        info!(
            "eth_sendTransaction from={} to={} value={} data_len={}",
            from,
            to,
            value.map(|v| v.to_string()).unwrap_or("-".into()),
            data_len
        );
    } else {
        info!("eth_sendTransaction received");
    }
}

fn log_send_raw(req: &Value) {
    let params = req.get("params").and_then(|p| p.as_array());
    let raw = params.and_then(|p| p.get(0)).and_then(|v| v.as_str());
    if let Some(raw) = raw {
        info!("eth_sendRawTransaction len={}", raw.len());
    } else {
        info!("eth_sendRawTransaction received");
    }
}

fn hex_to_u128(s: &str) -> Option<u128> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u128::from_str_radix(s, 16).ok()
}

fn parse_chain_id_str(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn parse_chain_id_value(v: &Value) -> Option<u64> {
    if let Some(s) = v.as_str() {
        return parse_chain_id_str(s);
    }
    v.as_u64()
}

fn extract_chain_id(req: &Value) -> Option<u64> {
    let params = req.get("params")?.as_array()?;
    let first = params.get(0)?;
    if let Some(obj) = first.as_object() {
        return obj.get("chain_id").and_then(parse_chain_id_value);
    }
    None
}

fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return None;
    }
    hex::decode(s).ok()
}

fn parse_address(s: &str) -> Option<[u8; 20]> {
    let bytes = parse_hex_bytes(s)?;
    if bytes.len() != 20 {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn parse_bytes32(s: &str) -> Option<[u8; 32]> {
    let bytes = parse_hex_bytes(s)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn parse_abi_address(s: &str) -> Option<[u8; 20]> {
    let bytes = parse_hex_bytes(s)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes[12..]);
    Some(out)
}

fn address_to_hex(addr: [u8; 20]) -> String {
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    out.push_str(&hex::encode(addr));
    out
}

fn to_hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(2 + data.len() * 2);
    out.push_str("0x");
    out.push_str(&hex::encode(data));
    out
}

fn encode_create_account(owner: [u8; 20], passkey: &[u8], salt: [u8; 32]) -> Vec<u8> {
    // function selector: createAccount(address,bytes,bytes32)
    let mut hasher = Keccak256::new();
    hasher.update(b"createAccount(address,bytes,bytes32)");
    let selector = &hasher.finalize()[..4];

    let mut out = Vec::with_capacity(4 + 32 * 3 + 32 + passkey.len() + 32);
    out.extend_from_slice(selector);

    // head (3 * 32 bytes)
    // 1) address owner
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(&owner);
    // 2) offset to bytes data (0x60)
    out.extend_from_slice(&u256_be(0x60));
    // 3) bytes32 salt
    out.extend_from_slice(&salt);

    // tail: bytes length + data + padding
    out.extend_from_slice(&u256_be(passkey.len() as u64));
    out.extend_from_slice(passkey);
    let pad = (32 - (passkey.len() % 32)) % 32;
    if pad != 0 {
        out.extend_from_slice(&vec![0u8; pad]);
    }
    out
}

fn u256_be(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

fn encode_get_address(owner: [u8; 20], passkey: &[u8], salt: [u8; 32]) -> Vec<u8> {
    // function selector: getAddress(address,bytes,bytes32)
    let mut hasher = Keccak256::new();
    hasher.update(b"getAddress(address,bytes,bytes32)");
    let selector = &hasher.finalize()[..4];

    let mut out = Vec::with_capacity(4 + 32 * 3 + 32 + passkey.len() + 32);
    out.extend_from_slice(selector);

    // head (3 * 32 bytes)
    // 1) address owner
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(&owner);
    // 2) offset to bytes data (0x60)
    out.extend_from_slice(&u256_be(0x60));
    // 3) bytes32 salt
    out.extend_from_slice(&salt);

    // tail: bytes length + data + padding
    out.extend_from_slice(&u256_be(passkey.len() as u64));
    out.extend_from_slice(passkey);
    let pad = (32 - (passkey.len() % 32)) % 32;
    if pad != 0 {
        out.extend_from_slice(&vec![0u8; pad]);
    }
    out
}

async fn fetch_predicted_address(
    state: &AppState,
    factory: &str,
    owner: [u8; 20],
    passkey: &[u8],
    salt: [u8; 32],
) -> Option<String> {
    let calldata = encode_get_address(owner, passkey, salt);
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{
            "to": factory,
            "data": to_hex(&calldata)
        }, "latest"]
    });

    let resp = state.client.post(&state.upstream).json(&payload).send().await.ok()?;
    let v: Value = resp.json().await.ok()?;
    let result = v.get("result")?.as_str()?;
    let addr = parse_abi_address(result)?;
    Some(address_to_hex(addr))
}

async fn init_db(url: &str) -> Option<Arc<PgClient>> {
    let (client, connection) = tokio_postgres::connect(url, NoTls).await.ok()?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            error!("postgres connection error: {}", e);
        }
    });

    if let Err(e) = client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS chain_registry (
                chain_id BIGINT PRIMARY KEY,
                mode TEXT NOT NULL,
                sca_address TEXT,
                factory_address TEXT,
                status TEXT NOT NULL DEFAULT 'inactive',
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );",
        )
        .await
    {
        error!("postgres init failed: {}", e);
        return None;
    }

    Some(Arc::new(client))
}

async fn fetch_chain_id(client: &reqwest::Client, upstream: &str) -> Option<u64> {
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_chainId",
        "params": []
    });
    let resp = client.post(upstream).json(&payload).send().await.ok()?;
    let v: Value = resp.json().await.ok()?;
    let result = v.get("result")?.as_str()?;
    parse_chain_id_str(result)
}

async fn get_chain_config(db: &PgClient, chain_id: u64) -> Result<Option<Value>, String> {
    let row = db
        .query_opt(
            "SELECT chain_id, mode, sca_address, factory_address, status, updated_at \
             FROM chain_registry WHERE chain_id = $1",
            &[&(chain_id as i64)],
        )
        .await
        .map_err(|e| e.to_string())?;

    let row = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    Ok(Some(json!({
        "chain_id": row.get::<_, i64>(0) as u64,
        "mode": row.get::<_, String>(1),
        "sca_address": row.get::<_, Option<String>>(2),
        "factory_address": row.get::<_, Option<String>>(3),
        "status": row.get::<_, String>(4),
        "updated_at": row.get::<_, chrono::DateTime<chrono::Utc>>(5).to_rfc3339(),
    })))
}

async fn upsert_chain_config(
    db: &PgClient,
    chain_id: u64,
    mode: &str,
    sca_address: Option<String>,
    factory_address: Option<String>,
    status: String,
) -> Result<(), String> {
    db.execute(
        "INSERT INTO chain_registry (chain_id, mode, sca_address, factory_address, status) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (chain_id) DO UPDATE SET \
           mode = EXCLUDED.mode, \
           sca_address = EXCLUDED.sca_address, \
           factory_address = EXCLUDED.factory_address, \
           status = EXCLUDED.status, \
           updated_at = NOW()",
        &[&(chain_id as i64), &mode, &sca_address, &factory_address, &status],
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

async fn resolve_account(state: &AppState) -> String {
    if let (Some(db), Some(chain_id)) = (&state.db, state.chain_id) {
        if let Ok(Some(cfg)) = get_chain_config(db, chain_id).await {
            if let Some(mode) = cfg.get("mode").and_then(|v| v.as_str()) {
                if mode.eq_ignore_ascii_case("SCA") {
                    if let Some(addr) = cfg.get("sca_address").and_then(|v| v.as_str()) {
                        return addr.to_string();
                    }
                }
            }
        }
    }

    if !state.eoa_address.is_empty() {
        return state.eoa_address.clone();
    }
    if !state.sca_address.is_empty() {
        return state.sca_address.clone();
    }
    String::new()
}
