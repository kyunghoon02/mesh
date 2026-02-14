use core::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use chacha20poly1305::{
    ChaCha20Poly1305, Key,
    aead::{AeadInPlace, KeyInit},
};
use postcard::from_bytes;
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use tracing::{error, info, warn};

use common::{PacketType, SecurePacket, SerialResponse, SignRequestPayload, TransactionIntent};
use heapless::String as HString;

use crate::abi::{
    address_to_hex, encode_create_account, encode_get_address, encode_recover_owner,
    encode_set_passkey, parse_abi_address, parse_address, parse_bytes32, parse_hex_bytes, to_hex,
};
use crate::db::{get_chain_config, get_passkey, upsert_chain_config, upsert_passkey};
use crate::eth_rpc::{fetch_tx_receipt, parse_receipt_status};
use crate::AppState;

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

    // id媛 ?녾굅??null?대㈃ JSON-RPC ?붿껌 ?먯껜瑜?臾댁떆?쒕떎.
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
            let seq = state.seq.fetch_add(1, Ordering::Relaxed);
            match serial.get_status(seq).await {
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

    if method == "mesh_prepareSetPasskey" {
        return Some(handle_prepare_set_passkey(req, state).await);
    }

    if method == "mesh_prepareRecover" {
        return Some(handle_prepare_recover(req, state).await);
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

    if matches!(
        method,
        "eth_sign"
            | "personal_sign"
            | "eth_signTypedData"
            | "eth_signTypedData_v3"
            | "eth_signTypedData_v4"
    ) {
        if let Some(resp) = send_sign_request_if_possible(state, req, method).await {
            return Some(resp);
        }
    }

    // ?낆뒪?몃┝ RPC媛 ?놁쑝硫??먮윭濡?諛섑솚?섍퀬 ?붿껌?????댁긽 泥섎━?섏? ?딅뒗??
    let upstream = resolve_upstream(state, req).await;
    if upstream.is_empty() {
        return Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32000, "message": "UPSTREAM_RPC not configured"}
        }));
    }

    match state.client.post(&upstream).json(req).send().await {
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
        .and_then(|m| m.get("passkey_pubkey").or_else(|| m.get("passkeyPubkey")))
        .and_then(|v| v.as_str())
        .and_then(parse_hex_bytes);

    let chain_opt = extract_chain_id(req).or(state.chain_id);
    let chain_id = chain_opt.unwrap_or(0);

    let salt = first
        .and_then(|m| m.get("salt"))
        .and_then(|v| v.as_str())
        .and_then(parse_bytes32);

    let mut factory = None;
    // 泥댁씤蹂??⑥뒪??吏???щ?(誘몄???泥댁씤? EOA 蹂듦뎄留?
    let mut supports_passkey = false;
    if let (Some(db), Some(chain_id)) = (&state.db, chain_opt) {
        if let Ok(Some(cfg)) = get_chain_config(db, chain_id).await {
            factory = cfg
                .get("factory_address")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            supports_passkey = cfg
                .get("supports_passkey")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
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
            });
        }
    };

    // ?⑥뒪??吏??泥댁씤?먯꽌??passkey_pubkey ?꾩닔, 誘몄???泥댁씤? 鍮?媛??덉슜
    let passkey = if supports_passkey {
        match passkey {
            Some(v) => {
                if !is_valid_passkey(&v) {
                    return json!({
                        "jsonrpc":"2.0",
                        "id": id,
                        "error": {"code": -32602, "message": "invalid passkey_pubkey length"}
                    });
                }
                v
            }
            None => {
                return json!({
                    "jsonrpc":"2.0",
                    "id": id,
                    "error": {"code": -32602, "message": "invalid passkey_pubkey"}
                });
            }
        }
    } else {
        // Passkey 誘몄???泥댁씤? 鍮?pubkey ?덉슜
        passkey.unwrap_or_default()
    };

    let factory = match factory {
        Some(v) => v,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "missing factory address"}
            });
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
            supports_passkey,
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
            });
        }
    };

    let db = match &state.db {
        Some(db) => db,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32020, "message": "DATABASE_URL not configured"}
            });
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
            });
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

    // UI에서 전달된 passkey 지원 여부 기본값은 false.
    let supports_passkey = first
        .and_then(|m| {
            m.get("supports_passkey")
                .or_else(|| m.get("supportsPasskey"))
        })
        .and_then(|v| v.as_bool());

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
            });
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

    let supports_passkey = supports_passkey.unwrap_or(false);

    match upsert_chain_config(
        db,
        chain_id,
        mode,
        sca_address,
        factory_address,
        rpc_url,
        supports_passkey,
        status,
    )
    .await
    {
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

async fn handle_prepare_set_passkey(req: &Value, state: &AppState) -> Value {
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
            });
        }
    };

    let passkey_hex = first
        .and_then(|m| m.get("passkey_pubkey").or_else(|| m.get("passkeyPubkey")))
        .and_then(|v| v.as_str())
        .and_then(parse_hex_bytes);
    let passkey = match passkey_hex {
        Some(v) => {
            if !is_valid_passkey(&v) {
                return json!({
                    "jsonrpc":"2.0",
                    "id": id,
                    "error": {"code": -32602, "message": "invalid passkey_pubkey length"}
                });
            }
            v
        }
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "invalid passkey_pubkey"}
            });
        }
    };

    let from = first
        .and_then(|m| m.get("from"))
        .and_then(|v| v.as_str())
        .and_then(parse_address);

    let db = match &state.db {
        Some(db) => db,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32020, "message": "DATABASE_URL not configured"}
            });
        }
    };

    let cfg = match get_chain_config(db, chain_id).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32021, "message": "chain config not found"}
            });
        }
        Err(e) => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32020, "message": e}
            });
        }
    };

    let supports_passkey = cfg
        .get("supports_passkey")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !supports_passkey {
        return json!({
            "jsonrpc":"2.0",
            "id": id,
            "error": {"code": -32602, "message": "passkey not supported on this chain"}
        });
    }

    let sca_address = cfg.get("sca_address").and_then(|v| v.as_str());
    let status = cfg
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("inactive");
    if sca_address.is_none() {
        return json!({
            "jsonrpc":"2.0",
            "id": id,
            "error": {"code": -32602, "message": "sca_address is not configured"}
        });
    }
    if status != "active" {
        return json!({
            "jsonrpc":"2.0",
            "id": id,
            "error": {"code": -32020, "message": format!("sca not active: {}", status)}
        });
    }

    let sca = sca_address.unwrap().to_string();
    if parse_address(&sca).is_none() {
        return json!({
            "jsonrpc":"2.0",
            "id": id,
            "error": {"code": -32602, "message": "invalid sca_address"}
        });
    }

    let calldata = encode_set_passkey(&passkey);
    let mut tx = json!({
        "to": sca,
        "data": to_hex(&calldata),
        "value": "0x0"
    });
    if let Some(from_addr) = from {
        tx["from"] = Value::String(address_to_hex(from_addr));
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
            }
        }
    })
}

async fn handle_prepare_recover(req: &Value, state: &AppState) -> Value {
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
            });
        }
    };

    let owner = first
        .and_then(|m| m.get("owner"))
        .and_then(|v| v.as_str())
        .and_then(parse_address);
    let new_owner = first
        .and_then(|m| m.get("new_owner").or_else(|| m.get("newOwner")))
        .and_then(|v| v.as_str())
        .and_then(parse_address);

    let auth_data = first
        .and_then(|m| {
            m.get("authenticator_data")
                .or_else(|| m.get("authenticatorData"))
        })
        .and_then(|v| v.as_str())
        .and_then(parse_hex_bytes);
    let client_json = first
        .and_then(|m| {
            m.get("client_data_json")
                .or_else(|| m.get("clientDataJSON"))
        })
        .and_then(|v| v.as_str())
        .and_then(parse_hex_bytes);
    let signature = first
        .and_then(|m| m.get("signature"))
        .and_then(|v| v.as_str())
        .and_then(parse_hex_bytes);

    let from = first
        .and_then(|m| m.get("from"))
        .and_then(|v| v.as_str())
        .and_then(parse_address);

    let owner = match owner {
        Some(v) => v,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "invalid owner"}
            });
        }
    };

    let new_owner = match new_owner {
        Some(v) => v,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "invalid new_owner"}
            });
        }
    };

    let auth_data = match auth_data {
        Some(v) => v,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "invalid authenticator_data"}
            });
        }
    };
    let client_json = match client_json {
        Some(v) => v,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "invalid client_data_json"}
            });
        }
    };
    let signature = match signature {
        Some(v) => v,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "invalid signature"}
            });
        }
    };

    let db = match &state.db {
        Some(db) => db,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32020, "message": "DATABASE_URL not configured"}
            });
        }
    };

    let cfg = match get_chain_config(db, chain_id).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32021, "message": "chain config not found"}
            });
        }
        Err(e) => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32020, "message": e}
            });
        }
    };

    let supports_passkey = cfg
        .get("supports_passkey")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !supports_passkey {
        return json!({
            "jsonrpc":"2.0",
            "id": id,
            "error": {"code": -32602, "message": "passkey not supported on this chain"}
        });
    }

    if cfg.get("status").and_then(|v| v.as_str()) != Some("active") {
        return json!({
            "jsonrpc":"2.0",
            "id": id,
            "error": {"code": -32602, "message": "wallet is not active"}
        });
    }

    let sca_address = match cfg.get("sca_address").and_then(|v| v.as_str()) {
        Some(v) if parse_address(v).is_some() => v.to_string(),
        _ => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "sca_address is not configured"}
            });
        }
    };

    let stored_passkey = match get_passkey(db, &address_to_hex(owner), chain_id).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32021, "message": "passkey is not registered"}
            });
        }
        Err(e) => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32020, "message": e}
            });
        }
    };
    let passkey_stored = stored_passkey
        .get("passkey_pubkey")
        .and_then(|v| v.as_str())
        .is_some();
    if !passkey_stored {
        return json!({
            "jsonrpc":"2.0",
            "id": id,
            "error": {"code": -32021, "message": "passkey is not registered"}
        });
    }

    let calldata = encode_recover_owner(new_owner, &auth_data, &client_json, &signature);
    let mut tx = json!({
        "to": sca_address,
        "data": to_hex(&calldata),
        "value": "0x0"
    });
    if let Some(from_addr) = from {
        tx["from"] = Value::String(address_to_hex(from_addr));
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
            }
        }
    })
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

    let passkey_str = first
        .and_then(|m| m.get("passkey_pubkey").or_else(|| m.get("passkeyPubkey")))
        .and_then(|v| v.as_str());

    let from = first
        .and_then(|m| m.get("from"))
        .and_then(|v| v.as_str())
        .and_then(parse_address);

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
            });
        }
    };

    let chain_id = match chain_id {
        Some(v) => v,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "missing chain_id"}
            });
        }
    };

    let passkey_bytes = match passkey_str.and_then(parse_hex_bytes) {
        Some(bytes) => {
            if !is_valid_passkey(&bytes) {
                return json!({
                    "jsonrpc":"2.0",
                    "id": id,
                    "error": {"code": -32602, "message": "invalid passkey_pubkey length"}
                });
            }
            bytes
        }
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "invalid passkey_pubkey"}
            });
        }
    };

    let db = match &state.db {
        Some(db) => db,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32020, "message": "DATABASE_URL not configured"}
            });
        }
    };

    let cfg = match get_chain_config(db, chain_id).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32021, "message": "chain config not found"}
            });
        }
        Err(e) => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32020, "message": e}
            });
        }
    };

    if !cfg
        .get("supports_passkey")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return json!({
            "jsonrpc":"2.0",
            "id": id,
            "error": {"code": -32602, "message": "passkey not supported on this chain"}
        });
    }

    if let Err(e) = upsert_passkey(
        db,
        &owner,
        chain_id,
        &to_hex(&passkey_bytes),
        credential_id,
        rp_id,
    )
    .await
    {
        return json!({
            "jsonrpc":"2.0",
            "id": id,
            "error": {"code": -32020, "message": e}
        });
    }

    let should_prepare =
        from.is_some() && cfg.get("status").and_then(|v| v.as_str()) == Some("active");
    if !should_prepare {
        return json!({
            "jsonrpc":"2.0",
            "id": id,
            "result": {"stored": true}
        });
    }

    let sca_address = match cfg.get("sca_address").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "result": {"stored": true}
            });
        }
    };

    if parse_address(sca_address).is_none() {
        return json!({
            "jsonrpc":"2.0",
            "id": id,
            "result": {
                "stored": true,
                "warning": "invalid sca_address in chain config"
            }
        });
    }

    let from = address_to_hex(from.unwrap());
    let calldata = encode_set_passkey(&passkey_bytes);
    let tx = json!({
        "to": sca_address,
        "data": to_hex(&calldata),
        "value": "0x0",
        "from": from
    });

    json!({
        "jsonrpc":"2.0",
        "id": id,
        "result": {
            "stored": true,
            "tx": tx,
            "request": {
                "method": "eth_sendTransaction",
                "params": [tx],
                "jsonrpc": "2.0",
                "id": 1
            }
        }
    })
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
            });
        }
    };

    let chain_id = match chain_id {
        Some(v) => v,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "missing chain_id"}
            });
        }
    };

    let db = match &state.db {
        Some(db) => db,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32020, "message": "DATABASE_URL not configured"}
            });
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
            });
        }
    };

    let owner = first
        .and_then(|m| m.get("from"))
        .and_then(|v| v.as_str())
        .and_then(parse_address);

    let tx_hash = match tx_hash {
        Some(v) => v,
        None => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32602, "message": "missing tx_hash"}
            });
        }
    };

    let upstream = resolve_upstream(state, req).await;
    let receipt = match fetch_tx_receipt(&state.client, &upstream, tx_hash).await {
        Ok(v) => v,
        Err(e) => {
            return json!({
                "jsonrpc":"2.0",
                "id": id,
                "error": {"code": -32030, "message": e}
            });
        }
    };

    let status = match receipt.as_ref() {
        None => "pending",
        Some(r) => match parse_receipt_status(r) {
            Ok(true) => "active",
            Ok(false) => "failed",
            Err(e) => {
                return json!({
                    "jsonrpc":"2.0",
                    "id": id,
                    "error": {"code": -32030, "message": e}
                });
            }
        },
    };

    let mut setpasskey_request = None;

    if status != "pending" {
        if let Some(db) = &state.db {
            let receipt_factory = receipt.as_ref().and_then(extract_receipt_to_address);
            let resolved_factory = factory_address.clone().or(receipt_factory.clone());

            let receipt_sca = receipt
                .as_ref()
                .and_then(|r| {
                    extract_sca_from_account_created_event(r, resolved_factory.as_deref())
                })
                .or_else(|| receipt.as_ref().and_then(extract_receipt_contract_address));

            let resolved_sca = sca_address.clone().or(receipt_sca.clone());

            let mut supports_passkey = false;
            if let Ok(Some(cfg)) = get_chain_config(db, chain_id).await {
                supports_passkey = cfg
                    .get("supports_passkey")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
            }
            let sca_for_setpasskey = resolved_sca.clone();

            let _ = upsert_chain_config(
                db,
                chain_id,
                "SCA",
                resolved_sca.clone(),
                resolved_factory.clone(),
                None,
                supports_passkey,
                status.to_string(),
            )
            .await;

            if let Some(factory) = resolved_factory {
                info!("mesh_confirmDeploy factory resolved: {}", factory);
            }
            if let Some(sca) = resolved_sca {
                info!("mesh_confirmDeploy sca resolved: {}", sca);
            }

            if supports_passkey && status == "active" {
                if let (Some(owner_addr), Some(sca)) = (owner, sca_for_setpasskey.as_deref()) {
                    if let Ok(Some(passkey_record)) = get_passkey(db, &address_to_hex(owner_addr), chain_id).await
                    {
                        if let Some(pubkey) = passkey_record
                            .get("passkey_pubkey")
                            .and_then(|v| v.as_str())
                            .and_then(parse_hex_bytes)
                        {
                            if is_valid_passkey(&pubkey) {
                                let calldata = encode_set_passkey(&pubkey);
                                let tx = json!({
                                    "to": sca,
                                    "data": to_hex(&calldata),
                                    "value": "0x0",
                                    "from": address_to_hex(owner_addr)
                                });

                                setpasskey_request = Some(json!({
                                    "method": "eth_sendTransaction",
                                    "params": [tx],
                                    "jsonrpc": "2.0",
                                    "id": 1
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    json!({
        "jsonrpc":"2.0",
        "id": id,
        "result": {
            "chain_id": chain_id,
            "status": status,
            "sca_address": receipt
                .as_ref()
                .and_then(|r| {
                    sca_address
                        .clone()
                        .or_else(|| extract_sca_from_account_created_event(r, factory_address.as_deref()))
                        .or_else(|| extract_receipt_contract_address(r))
                }),
            "factory_address": receipt
                .as_ref()
                .and_then(|r| factory_address.clone().or_else(|| extract_receipt_to_address(r)))
            ,
            "setpasskey_request": setpasskey_request,
        }
    })
}

async fn send_sign_request_if_possible(
    state: &AppState,
    req: &Value,
    method: &str,
) -> Option<Value> {
    let request_id = req.get("id").cloned().unwrap_or(Value::Null);
    let serial = match &state.serial {
        Some(s) => s,
        None => {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32011, "message": "SERIAL_PORT not configured"}
            }));
        }
    };

    // SecurePacket 생성: SignRequestPayload 직렬화가 실패하면 즉시 에러로 반환한다.
    let counter = state.counter.fetch_add(1, Ordering::Relaxed);
    let packet = match build_secure_packet(method, req, counter, &state.aead_key) {
        Some(v) => v,
        None => {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32014,
                    "message": "invalid sign request payload"
                }
            }));
        }
    };

    let seq = state.seq.fetch_add(1, Ordering::Relaxed);
    match serial.send_sign_request(seq, &packet).await {
        Ok(resp) => {
            if resp.success {
                if let Some(signature) = extract_signature_from_response(&resp, &state.aead_key) {
                    return Some(json!({
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": to_hex(&signature)
                    }));
                }

                warn!(
                    "hardware sign response failed to decode signature: method={}",
                    method
                );

                return Some(json!({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32013,
                        "message": "invalid hardware signature response"
                    }
                }));
            } else {
                Some(json!({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32012, "message": format!("hardware rejected: {}", resp.error_code)}
                }))
            }
        }
        Err(e) => {
            Some(json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32012, "message": e}
            }))
        }
    }
}

fn build_secure_packet(
    method: &str,
    req: &Value,
    counter: u64,
    aead_key: &[u8; 32],
) -> Option<SecurePacket> {
    let hash32 = match build_request_hash(method, req) {
        Some(v) => v,
        None => {
            return None;
        }
    };

    let intent = build_intent(method, req);
    let payload_struct = SignRequestPayload {
        hash: hash32,
        intent,
    };
    let mut plain_buf = [0u8; 192];
    let plain_len = match postcard::to_slice(&payload_struct, &mut plain_buf) {
        Ok(slice) => slice.len(),
        Err(_) => return None,
    };
    let plain = &plain_buf[..plain_len];

    let boot_id = 1u32;

    let (ciphertext, tag) = encrypt_payload(boot_id, counter, plain, aead_key);
    let mut packet = SecurePacket::new(PacketType::SignRequest, &ciphertext[..plain_len], tag)?;
    packet.counter = counter;
    packet.boot_id = boot_id;
    Some(packet)
}

fn encrypt_payload(
    boot_id: u32,
    counter: u64,
    plain: &[u8],
    aead_key: &[u8; 32],
) -> ([u8; 192], [u8; 16]) {
    let mut buf = [0u8; 192];
    if !plain.is_empty() {
        buf[..plain.len()].copy_from_slice(plain);
    }

    let key = Key::from_slice(aead_key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = build_nonce(boot_id, counter);
    let tag = if plain.is_empty() {
        chacha20poly1305::Tag::from_slice(&[0u8; 16]).to_owned()
    } else {
        cipher
            .encrypt_in_place_detached(&nonce, b"", &mut buf[..plain.len()])
            .expect("aead")
    };
    (buf, tag.into())
}

fn build_nonce(boot_id: u32, counter: u64) -> chacha20poly1305::Nonce {
    let mut out = [0u8; 12];
    out[..4].copy_from_slice(&boot_id.to_be_bytes());
    out[4..].copy_from_slice(&counter.to_be_bytes());
    chacha20poly1305::Nonce::from_slice(&out).to_owned()
}

fn extract_signature_from_response(
    response: &SerialResponse,
    aead_key: &[u8; 32],
) -> Option<Vec<u8>> {
    let payload = response.payload_bytes();
    if payload.is_empty() {
        return None;
    }

    let packet = from_bytes::<SecurePacket>(payload).ok()?;
    if packet.payload_type != PacketType::SignResponse {
        return None;
    }

    if packet.ciphertext_len == 0 {
        return None;
    }

    let (plain, plain_len) = decrypt_packet_payload(&packet, aead_key)?;

    Some(plain[..plain_len].to_vec())
}

fn decrypt_packet_payload(
    packet: &SecurePacket,
    aead_key: &[u8; 32],
) -> Option<([u8; 192], usize)> {
    let cipher_len = packet.ciphertext_len as usize;
    if packet.auth_tag.iter().all(|b| *b == 0) {
        return None;
    }
    if cipher_len == 0 || cipher_len > packet.ciphertext.len() {
        return None;
    }

    let mut buf = [0u8; 192];
    buf[..cipher_len].copy_from_slice(&packet.ciphertext[..cipher_len]);

    let key = Key::from_slice(aead_key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = build_nonce(packet.boot_id, packet.counter);

    if cipher
        .decrypt_in_place_detached(
            &nonce,
            b"",
            &mut buf[..cipher_len],
            chacha20poly1305::Tag::from_slice(&packet.auth_tag),
        )
        .is_ok()
    {
        Some((buf, cipher_len))
    } else {
        None
    }
}

fn build_intent(method: &str, req: &Value) -> TransactionIntent {
    let chain_id = extract_chain_id(req).unwrap_or(0);
    let mut target_address = [0u8; 20];
    let mut eth_value = 0u128;
    let mut risk_level: u8 = 1;
    let mut summary: HString<64> = HString::new();

    if method == "eth_sendTransaction" {
        let tx = req
            .get("params")
            .and_then(|p| p.get(0))
            .and_then(|v| v.as_object());

        let to = tx.and_then(|m| m.get("to")).and_then(|v| v.as_str());
        if let Some(addr) = to.and_then(parse_address) {
            target_address = addr;
        }

        eth_value = tx
            .and_then(|m| m.get("value"))
            .and_then(|v| v.as_str())
            .and_then(hex_to_u128)
            .unwrap_or(0);

        let data_present = tx
            .and_then(|m| m.get("data"))
            .and_then(|v| v.as_str())
            .map(|s| s.len() > 2)
            .unwrap_or(false);

        if to.is_none() {
            let _ = write!(summary, "Contract Deploy");
            risk_level = 2;
        } else if data_present {
            let _ = write!(summary, "Contract Call");
            risk_level = 1;
        } else {
            let _ = write!(summary, "Transfer");
            risk_level = 0;
        }

        if eth_value > 0 {
            let _ = write!(summary, " {} wei", eth_value);
        }

        return TransactionIntent {
            chain_id,
            target_address,
            eth_value,
            risk_level,
            summary,
        };
    }

    if method == "eth_sign" {
        let _ = write!(summary, "Signature request: eth_sign");
        if let Some(addr) = req
            .get("params")
            .and_then(|p| p.get(0))
            .and_then(|v| v.as_str())
            .and_then(parse_address)
        {
            target_address = addr;
        }
        return TransactionIntent {
            chain_id,
            target_address,
            eth_value,
            risk_level,
            summary,
        };
    }

    if method == "personal_sign" {
        let _ = write!(summary, "Signature request: personal_sign");
        if let Some(addr) = req
            .get("params")
            .and_then(|p| p.get(1))
            .and_then(|v| v.as_str())
            .and_then(parse_address)
        {
            target_address = addr;
        }
        return TransactionIntent {
            chain_id,
            target_address,
            eth_value,
            risk_level,
            summary,
        };
    }

    if method == "eth_signTypedData"
        || method == "eth_signTypedData_v3"
        || method == "eth_signTypedData_v4"
    {
        let _ = write!(summary, "Signature request: typed data");
        if let Some(addr) = req
            .get("params")
            .and_then(|p| p.get(0))
            .and_then(|v| v.as_str())
            .and_then(parse_address)
        {
            target_address = addr;
        }
        return TransactionIntent {
            chain_id,
            target_address,
            eth_value,
            risk_level,
            summary,
        };
    }

    let _ = write!(summary, "Raw tx");

    TransactionIntent {
        chain_id,
        target_address,
        eth_value,
        risk_level,
        summary,
    }
}
fn build_request_hash(method: &str, req: &Value) -> Option<[u8; 32]> {
    let params = req.get("params").and_then(|v| v.as_array())?;

    let hash_input = match method {
        "eth_sendRawTransaction" => {
            let raw = params.get(0)?.as_str()?;
            Some(raw.as_bytes().to_vec())
        }
        "eth_sign" => {
            let msg = params
                .get(1)
                .or_else(|| params.get(0))
                .and_then(|v| v.as_str())?;
            parse_hex_bytes(msg).map(|bytes| bytes)
        }
        "personal_sign" => {
            let msg = parse_hex_bytes(
                params
                    .get(0)
                    .or_else(|| params.get(1))
                    .and_then(|v| v.as_str())?,
            )?;
            let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
            let mut data = Vec::with_capacity(prefix.len() + msg.len());
            data.extend_from_slice(prefix.as_bytes());
            data.extend_from_slice(&msg);
            Some(data)
        }
        "eth_signTypedData" | "eth_signTypedData_v3" | "eth_signTypedData_v4" => {
            let raw = params
                .get(1)
                .and_then(|v| v.as_str())
                .or_else(|| params.get(0).and_then(|v| v.as_str()))?;
            Some(raw.as_bytes().to_vec())
        }
        _ => {
            let param = params.get(0)?;
            serde_json::to_vec(param).ok()
        }
    };

    let bytes = hash_input?;
    let hash = Keccak256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    Some(out)
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

fn is_valid_passkey(pubkey: &[u8]) -> bool {
    pubkey.len() == 65
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

fn normalize_address_str(addr: &str) -> Option<String> {
    parse_address(addr).map(address_to_hex)
}

fn extract_receipt_to_address(receipt: &Value) -> Option<String> {
    receipt
        .get("to")
        .and_then(|v| v.as_str())
        .and_then(normalize_address_str)
}

fn extract_receipt_contract_address(receipt: &Value) -> Option<String> {
    receipt
        .get("contractAddress")
        .and_then(|v| v.as_str())
        .and_then(normalize_address_str)
}

fn extract_sca_from_account_created_event(
    receipt: &Value,
    factory_hint: Option<&str>,
) -> Option<String> {
    // MeshVaultFactory.AccountCreated(address,address,bytes32)
    let event_topic = format!(
        "0x{}",
        hex::encode(Keccak256::digest(
            b"AccountCreated(address,address,bytes32)"
        ))
    );
    let logs = receipt.get("logs")?.as_array()?;

    let normalized_factory_hint = factory_hint.and_then(normalize_address_str);
    for log in logs {
        let log_obj = match log.as_object() {
            Some(v) => v,
            None => continue,
        };

        if let Some(hint) = normalized_factory_hint.as_deref() {
            let log_addr = log_obj
                .get("address")
                .and_then(|v| v.as_str())
                .and_then(normalize_address_str);
            if log_addr.as_deref() != Some(hint) {
                continue;
            }
        }

        let topics = match log_obj.get("topics").and_then(|v| v.as_array()) {
            Some(v) => v,
            None => continue,
        };
        if topics.len() < 3 {
            continue;
        }

        let topic0 = match topics.get(0).and_then(|v| v.as_str()) {
            Some(v) => v.to_lowercase(),
            None => continue,
        };
        if topic0 != event_topic {
            continue;
        }

        let topic2 = match topics.get(2).and_then(|v| v.as_str()) {
            Some(v) => v,
            None => continue,
        };
        let account = match parse_abi_address(topic2) {
            Some(v) => v,
            None => continue,
        };
        return Some(address_to_hex(account));
    }

    None
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

    let resp = state
        .client
        .post(upstream)
        .json(&payload)
        .send()
        .await
        .ok()?;
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
                let status = cfg
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("inactive");
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
