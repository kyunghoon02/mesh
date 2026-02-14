use axum::{Router, routing::post};
use reqwest::Client;
use sha3::{Digest, Keccak256};
use std::sync::{
    Arc,
    atomic::{AtomicU32, AtomicU64},
};
use tokio_postgres::Client as PgClient;
use tracing::{info, warn};

mod abi;
mod db;
mod eth_rpc;
mod rpc;
mod serial;

use crate::serial::SerialClient;

#[derive(Clone)]
pub struct AppState {
    pub upstream: String,
    pub eoa_address: String,
    pub sca_address: String,
    pub factory_address: Option<String>,
    pub db: Option<Arc<PgClient>>,
    pub chain_id: Option<u64>,
    pub serial: Option<SerialClient>,
    pub seq: Arc<AtomicU32>,
    pub counter: Arc<AtomicU64>,
    pub aead_key: [u8; 32],
    pub client: Client,
}

fn parse_aead_key_from_env_or_eoa() -> [u8; 32] {
    let raw = match std::env::var("MESH_AEAD_KEY") {
        Ok(v) => v,
        Err(_) => {
            warn!("MESH_AEAD_KEY가 설정되지 않았습니다. EOA_ADDRESS 기반으로 키를 파생합니다.");
            return derive_aead_key_from_eoa();
        }
    };

    let mut key_hex = raw.trim().to_ascii_lowercase();
    if let Some(v) = key_hex.strip_prefix("0x") {
        key_hex = v.to_string();
    }

    let decoded = match hex::decode(&key_hex) {
        Ok(v) => v,
        Err(_) => {
            warn!("MESH_AEAD_KEY 형식이 유효하지 않습니다. EOA_ADDRESS 기반으로 키를 파생합니다.");
            return derive_aead_key_from_eoa();
        }
    };

    if decoded.len() != 32 {
        warn!(
            "MESH_AEAD_KEY 길이가 잘못되었습니다. 현재 {}바이트, EOA_ADDRESS 기반 키로 대체합니다.",
            decoded.len()
        );
        return derive_aead_key_from_eoa();
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    key
}

fn derive_aead_key_from_eoa() -> [u8; 32] {
    let eoa = match std::env::var("EOA_ADDRESS").ok() {
        Some(v) => v,
        None => {
            warn!("EOA_ADDRESS도 설정되지 않아 기본 키(0x00)를 사용합니다.");
            return [0u8; 32];
        }
    };

    let addr = match crate::abi::parse_address(&eoa) {
        Some(a) => a,
        None => {
            warn!("EOA_ADDRESS 형식이 잘못되어 기본 키(0x00)를 사용합니다.");
            return [0u8; 32];
        }
    };

    let mut hasher = Keccak256::new();
    hasher.update(addr);
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();
    dotenvy::dotenv().ok();

    let upstream = std::env::var("UPSTREAM_RPC").unwrap_or_default();
    let eoa_address = std::env::var("EOA_ADDRESS").unwrap_or_default();
    let sca_address = std::env::var("SCA_ADDRESS").unwrap_or_default();
    let factory_address = std::env::var("FACTORY_ADDRESS").ok();
    let db_url = std::env::var("DATABASE_URL").ok();
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

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

    let client = Client::new();
    let chain_id = match std::env::var("CHAIN_ID") {
        Ok(v) => abi::parse_chain_id_str(&v),
        Err(_) => {
            if upstream.is_empty() {
                None
            } else {
                eth_rpc::fetch_chain_id(&client, &upstream).await
            }
        }
    };

    let db = match db_url {
        Some(url) => db::init_db(&url).await,
        None => None,
    };
    let aead_key = parse_aead_key_from_env_or_eoa();

    let state = Arc::new(AppState {
        upstream,
        eoa_address,
        sca_address,
        factory_address,
        db,
        chain_id,
        serial,
        seq: Arc::new(AtomicU32::new(1)),
        counter: Arc::new(AtomicU64::new(1)),
        aead_key,
        client,
    });

    let app = Router::new()
        .route("/", post(rpc::rpc_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("bind failed");

    info!("relayer listening on {}", bind_addr);
    axum::serve(listener, app).await.unwrap();
}
