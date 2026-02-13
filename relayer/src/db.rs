use std::sync::Arc;

use serde_json::{json, Value};
use tokio_postgres::{Client as PgClient, NoTls};
use tracing::error;

pub async fn init_db(url: &str) -> Option<Arc<PgClient>> {
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
                rpc_url TEXT,
                supports_passkey BOOLEAN NOT NULL DEFAULT FALSE,
                status TEXT NOT NULL DEFAULT 'inactive',
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            ALTER TABLE chain_registry ADD COLUMN IF NOT EXISTS rpc_url TEXT;
            ALTER TABLE chain_registry ADD COLUMN IF NOT EXISTS supports_passkey BOOLEAN NOT NULL DEFAULT FALSE;",
        )
        .await
    {
        error!("postgres init failed: {}", e);
        return None;
    }

    if let Err(e) = client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS passkey_registry (
                owner TEXT NOT NULL,
                chain_id BIGINT NOT NULL,
                passkey_pubkey TEXT NOT NULL,
                credential_id TEXT,
                rp_id TEXT,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (owner, chain_id)
            );",
        )
        .await
    {
        error!("postgres init failed: {}", e);
        return None;
    }

    Some(Arc::new(client))
}

pub async fn get_chain_config(db: &PgClient, chain_id: u64) -> Result<Option<Value>, String> {
    let row = db
        .query_opt(
            "SELECT chain_id, mode, sca_address, factory_address, rpc_url, supports_passkey, status, updated_at \
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
        "rpc_url": row.get::<_, Option<String>>(4),
        "supports_passkey": row.get::<_, bool>(5),
        "status": row.get::<_, String>(6),
        "updated_at": row.get::<_, chrono::DateTime<chrono::Utc>>(7).to_rfc3339(),
    })))
}

pub async fn upsert_chain_config(
    db: &PgClient,
    chain_id: u64,
    mode: &str,
    sca_address: Option<String>,
    factory_address: Option<String>,
    rpc_url: Option<String>,
    supports_passkey: bool,
    status: String,
) -> Result<(), String> {
    db.execute(
        "INSERT INTO chain_registry (chain_id, mode, sca_address, factory_address, rpc_url, supports_passkey, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (chain_id) DO UPDATE SET \
           mode = EXCLUDED.mode, \
           sca_address = COALESCE(EXCLUDED.sca_address, chain_registry.sca_address), \
           factory_address = COALESCE(EXCLUDED.factory_address, chain_registry.factory_address), \
           rpc_url = COALESCE(EXCLUDED.rpc_url, chain_registry.rpc_url), \
           supports_passkey = EXCLUDED.supports_passkey, \
           status = EXCLUDED.status, \
           updated_at = NOW()",
        &[
            &(chain_id as i64),
            &mode,
            &sca_address,
            &factory_address,
            &rpc_url,
            &supports_passkey,
            &status,
        ],
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub async fn upsert_passkey(
    db: &PgClient,
    owner: &str,
    chain_id: u64,
    passkey_pubkey: &str,
    credential_id: Option<String>,
    rp_id: Option<String>,
) -> Result<(), String> {
    db.execute(
        "INSERT INTO passkey_registry (owner, chain_id, passkey_pubkey, credential_id, rp_id) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (owner, chain_id) DO UPDATE SET \
           passkey_pubkey = EXCLUDED.passkey_pubkey, \
           credential_id = COALESCE(EXCLUDED.credential_id, passkey_registry.credential_id), \
           rp_id = COALESCE(EXCLUDED.rp_id, passkey_registry.rp_id), \
           updated_at = NOW()",
        &[
            &owner,
            &(chain_id as i64),
            &passkey_pubkey,
            &credential_id,
            &rp_id,
        ],
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub async fn get_passkey(
    db: &PgClient,
    owner: &str,
    chain_id: u64,
) -> Result<Option<Value>, String> {
    let row = db
        .query_opt(
            "SELECT owner, chain_id, passkey_pubkey, credential_id, rp_id, updated_at \
             FROM passkey_registry WHERE owner = $1 AND chain_id = $2",
            &[&owner, &(chain_id as i64)],
        )
        .await
        .map_err(|e| e.to_string())?;

    let row = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    Ok(Some(json!({
        "owner": row.get::<_, String>(0),
        "chain_id": row.get::<_, i64>(1) as u64,
        "passkey_pubkey": row.get::<_, String>(2),
        "credential_id": row.get::<_, Option<String>>(3),
        "rp_id": row.get::<_, Option<String>>(4),
        "updated_at": row.get::<_, chrono::DateTime<chrono::Utc>>(5).to_rfc3339(),
    })))
}
