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
use tracing::{error, info};

#[derive(Clone)]
struct AppState {
    upstream: String,
    sca_address: String,
    client: reqwest::Client,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let upstream = std::env::var("UPSTREAM_RPC").unwrap_or_default();
    let sca_address = std::env::var("SCA_ADDRESS").unwrap_or_default();
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    if upstream.is_empty() || sca_address.is_empty() {
        eprintln!(
            "Missing env vars: UPSTREAM_RPC and/or SCA_ADDRESS. Server will still start but will return 500."
        );
    }

    let state = Arc::new(AppState {
        upstream,
        sca_address,
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

    if method == "eth_sendTransaction" || method == "eth_sendRawTransaction" {
        info!("{} intercepted and forwarded", method);
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
