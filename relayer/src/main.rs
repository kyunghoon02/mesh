use std::sync::{
    atomic::{AtomicU32, AtomicU64},
    Arc,
};

use axum::{routing::post, Router};
use reqwest::Client;
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
    pub approval_mode: ApprovalMode,
    pub serial: Option<SerialClient>,
    pub seq: Arc<AtomicU32>,
    pub counter: Arc<AtomicU64>,
    pub client: Client,
}

#[derive(Clone, Copy)]
pub enum ApprovalMode {
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

    // .env 파일이 있으면 로드
    dotenvy::dotenv().ok();

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

    let app = Router::new().route("/", post(rpc::rpc_handler)).with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("bind failed");

    info!("relayer listening on {}", bind_addr);
    axum::serve(listener, app).await.unwrap();
}
