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

pub async fn get_chain_config(db: &PgClient, chain_id: u64) -> Result<Option<Value>, String> {
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

pub async fn upsert_chain_config(
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
           sca_address = COALESCE(EXCLUDED.sca_address, chain_registry.sca_address), \
           factory_address = COALESCE(EXCLUDED.factory_address, chain_registry.factory_address), \
           status = EXCLUDED.status, \
           updated_at = NOW()",
        &[&(chain_id as i64), &mode, &sca_address, &factory_address, &status],
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}
