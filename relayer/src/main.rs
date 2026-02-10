use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde_json::{json, Value};
use tracing::{error, info, warn};

mod serial;
use serial::SerialClient;

#[derive(Clone)]
struct AppState {
    upstream: String,
    sca_address: String,
    approval_mode: ApprovalMode,
    serial: Option<SerialClient>,
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

    // 필수: 업스트림 RPC, SCA 주소
    let upstream = std::env::var("UPSTREAM_RPC").unwrap_or_default();
    let sca_address = std::env::var("SCA_ADDRESS").unwrap_or_default();
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

    if upstream.is_empty() || sca_address.is_empty() {
        eprintln!(
            "Missing env vars: UPSTREAM_RPC and/or SCA_ADDRESS. Server will still start but will return 500."
        );
    }

    let state = Arc::new(AppState {
        upstream,
        sca_address,
        approval_mode: ApprovalMode::from_env(),
        serial,
        client: reqwest::Client::new(),
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
        return Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": [state.sca_address],
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

    if method == "eth_sendTransaction" {
        log_send_tx(req);
        if matches!(state.approval_mode, ApprovalMode::Block) {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32001, "message": "hardware approval required"}
            }));
        }
    }

    if method == "eth_sendRawTransaction" {
        log_send_raw(req);
        if matches!(state.approval_mode, ApprovalMode::Block) {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32001, "message": "hardware approval required"}
            }));
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
