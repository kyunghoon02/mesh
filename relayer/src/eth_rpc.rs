use serde_json::{json, Value};

use crate::abi::parse_chain_id_str;

pub async fn fetch_chain_id(client: &reqwest::Client, upstream: &str) -> Option<u64> {
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

pub async fn fetch_tx_receipt_status(
    client: &reqwest::Client,
    upstream: &str,
    tx_hash: &str,
) -> Result<Option<bool>, String> {
    if upstream.is_empty() {
        return Err("UPSTREAM_RPC not configured".to_string());
    }
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getTransactionReceipt",
        "params": [tx_hash]
    });
    let resp = client
        .post(upstream)
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let v: Value = resp.json().await.map_err(|e| e.to_string())?;
    let result = v.get("result");
    if result.is_none() || result == Some(&Value::Null) {
        return Ok(None);
    }
    let status = result
        .and_then(|r| r.get("status"))
        .and_then(|s| s.as_str())
        .ok_or_else(|| "missing receipt status".to_string())?;
    let ok = match status {
        "0x1" => true,
        "0x0" => false,
        other => {
            let v = parse_chain_id_str(other).ok_or_else(|| "invalid receipt status".to_string())?;
            v == 1
        }
    };
    Ok(Some(ok))
}
