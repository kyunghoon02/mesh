use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use tracing::{error, info, warn};

use common::{PacketType, SecurePacket};

use crate::abi::{
    address_to_hex, encode_create_account, encode_get_address, parse_address, parse_bytes32,
    parse_hex_bytes, parse_abi_address, to_hex,
};
use crate::db::{get_chain_config, get_passkey, upsert_chain_config, upsert_passkey};
use crate::eth_rpc::fetch_tx_receipt_status;
use crate::{AppState, ApprovalMode};

pub async fn rpc_handler(
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

    // 알림 요청은 응답하지 않음
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

    if method == "mesh_getPasskey" {
        return Some(handle_get_passkey(req, state).await);
    }

    if method == "mesh_setPasskey" {
        return Some(handle_set_passkey(req, state).await);
    }

    if method == "mesh_confirmDeploy" {
        return Some(handle_confirm_deploy(req, state).await);
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

    // 그 외 RPC는 업스트림으로 전달
    let upstream = resolve_upstream(state, req).await;
    if upstream.is_empty() {
        return Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32000, "message": "UPSTREAM_RPC not configured"}
        }));
    }

    match state
        .client
        .post(&upstream)
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

    let chain_opt = extract_chain_id(req).or(state.chain_id);
    let chain_id = chain_opt.unwrap_or(0);

    let salt = first
        .and_then(|m| m.get("salt"))
        .and_then(|v| v.as_str())
        .and_then(parse_bytes32);

    let mut factory = None;
    if let (Some(db), Some(chain_id)) = (&state.db, chain_opt) {
        if let Ok(Some(cfg)) = get_chain_config(db, chain_id).await {
            factory = cfg
                .get("factory_address")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
        }
    }
    if factory.is_none() {
        factory = state.factory_address.clone();
    }

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
    if parse_address(&factory).is_none() {
        return json!({
            "jsonrpc":"2.0",
            "id": id,
            "error": {"code": -32602, "message": "invalid factory address"}
        });
    }

    let salt = salt.unwrap_or_else(|| compute_default_salt(owner, &passkey, chain_id));

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

    let predicted = {
        let upstream = resolve_upstream(state, req).await;
        if upstream.is_empty() {
            None
        } else {
            fetch_predicted_address(state, &upstream, &factory, owner, &passkey, salt).await
        }
    };

    if let (Some(db), Some(chain_id)) = (&state.db, state.chain_id) {
        let _ = upsert_chain_config(
            db,
            chain_id,
            "SCA",
            predicted.clone(),
            Some(factory.clone()),
            None,
            "pending".to_string(),
        )
        .await;
    }

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

    let factory_address = None;

    let rpc_url = first
        .and_then(|m| m.get("rpc_url").or_else(|| m.get("rpcUrl")))
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

    let mut factory_ok = state.factory_address.is_some();
    if !factory_ok {
        if let Ok(Some(cfg)) = get_chain_config(db, chain_id).await {
            factory_ok = cfg
                .get("factory_address")
                .and_then(|v| v.as_str())
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);
        }
    }
    if !factory_ok {
        return json!({
            "jsonrpc":"2.0",
            "id": id,
            "error": {"code": -32020, "message": "FACTORY_ADDRESS not configured"}
        });
    }
    if let Some(factory) = &state.factory_address {
        if parse_address(factory).is_none() {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32020, "message": "FACTORY_ADDRESS invalid"}
            });
        }
    }

    match upsert_chain_config(db, chain_id, mode, sca_address, factory_address, rpc_url, status).await {
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

async fn handle_set_passkey(req: &Value, state: &AppState) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let params = req.get("params").and_then(|p| p.as_array());
    let first = params.and_then(|p| p.get(0)).and_then(|v| v.as_object());

    let owner = first
        .and_then(|m| m.get("owner"))
        .and_then(|v| v.as_str())
        .and_then(parse_address);

    let chain_id = first
        .and_then(|m| m.get("chain_id"))
        .and_then(parse_chain_id_value)
        .or(state.chain_id);

    let passkey_hex = first
        .and_then(|m| {
            m.get("passkey_pubkey")
                .or_else(|| m.get("passkeyPubkey"))
        })
        .and_then(|v| v.as_str());

    let credential_id = first
        .and_then(|m| m.get("credential_id").or_else(|| m.get("credentialId")))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let rp_id = first
        .and_then(|m| m.get("rp_id").or_else(|| m.get("rpId")))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let owner = match owner {
        Some(v) => address_to_hex(v),
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "invalid owner"}
            })
        }
    };

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

    let passkey_hex = match passkey_hex.and_then(parse_hex_bytes) {
        Some(bytes) => to_hex(&bytes),
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "invalid passkey_pubkey"}
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

    match upsert_passkey(db, &owner, chain_id, &passkey_hex, credential_id, rp_id).await {
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

async fn handle_get_passkey(req: &Value, state: &AppState) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let params = req.get("params").and_then(|p| p.as_array());
    let first = params.and_then(|p| p.get(0)).and_then(|v| v.as_object());

    let owner = first
        .and_then(|m| m.get("owner"))
        .and_then(|v| v.as_str())
        .and_then(parse_address);

    let chain_id = first
        .and_then(|m| m.get("chain_id"))
        .and_then(parse_chain_id_value)
        .or(state.chain_id);

    let owner = match owner {
        Some(v) => address_to_hex(v),
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "invalid owner"}
            })
        }
    };

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

    match get_passkey(db, &owner, chain_id).await {
        Ok(Some(rec)) => json!({
            "jsonrpc":"2.0",
            "id": id,
            "result": rec
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

async fn handle_confirm_deploy(req: &Value, state: &AppState) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let params = req.get("params").and_then(|p| p.as_array());
    let first = params.and_then(|p| p.get(0)).and_then(|v| v.as_object());

    let chain_id = first
        .and_then(|m| m.get("chain_id"))
        .and_then(parse_chain_id_value)
        .or(state.chain_id);

    let tx_hash = first
        .and_then(|m| m.get("tx_hash"))
        .and_then(|v| v.as_str())
        .or_else(|| first.and_then(|m| m.get("txHash")).and_then(|v| v.as_str()));

    let sca_address = first
        .and_then(|m| m.get("sca_address"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let factory_address = None;

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

    let tx_hash = match tx_hash {
        Some(v) => v,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "missing tx_hash"}
            })
        }
    };

    let upstream = resolve_upstream(state, req).await;
    let status = match fetch_tx_receipt_status(&state.client, &upstream, tx_hash).await {
        Ok(Some(true)) => "active",
        Ok(Some(false)) => "failed",
        Ok(None) => "pending",
        Err(e) => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32030, "message": e}
            })
        }
    };

    if status != "pending" {
        if let Some(db) = &state.db {
            let _ = upsert_chain_config(
                db,
                chain_id,
                "SCA",
                sca_address,
                factory_address,
                None,
                status.to_string(),
            )
            .await;
        }
    }

    json!({
        "jsonrpc":"2.0",
        "id": id,
        "result": {
            "chain_id": chain_id,
            "status": status
        }
    })
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

    // SecurePacket 생성 (암호화는 추후 구현, 현재는 페이로드에 축약 데이터만 담음)
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

fn parse_chain_id_value(v: &Value) -> Option<u64> {
    if let Some(s) = v.as_str() {
        return crate::abi::parse_chain_id_str(s);
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

fn compute_default_salt(owner: [u8; 20], passkey: &[u8], chain_id: u64) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"mesh_salt_v1");
    hasher.update(owner);
    hasher.update(passkey);
    hasher.update(chain_id.to_be_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

async fn fetch_predicted_address(
    state: &AppState,
    upstream: &str,
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

    let resp = state.client.post(upstream).json(&payload).send().await.ok()?;
    let v: Value = resp.json().await.ok()?;
    let result = v.get("result")?.as_str()?;
    let addr = parse_abi_address(result)?;
    Some(address_to_hex(addr))
}

async fn resolve_upstream(state: &AppState, req: &Value) -> String {
    if let (Some(db), Some(chain_id)) = (&state.db, extract_chain_id(req).or(state.chain_id)) {
        if let Ok(Some(cfg)) = get_chain_config(db, chain_id).await {
            if let Some(url) = cfg.get("rpc_url").and_then(|v| v.as_str()) {
                if !url.trim().is_empty() {
                    return url.to_string();
                }
            }
        }
    }

    state.upstream.clone()
}

async fn resolve_account(state: &AppState) -> String {
    if let (Some(db), Some(chain_id)) = (&state.db, state.chain_id) {
        if let Ok(Some(cfg)) = get_chain_config(db, chain_id).await {
            if let Some(mode) = cfg.get("mode").and_then(|v| v.as_str()) {
                let status = cfg.get("status").and_then(|v| v.as_str()).unwrap_or("inactive");
                if mode.eq_ignore_ascii_case("SCA") && status.eq_ignore_ascii_case("active") {
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
