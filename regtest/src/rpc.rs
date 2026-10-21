//! Minimal JSON-RPC client for bitcoind. Errors come back as the node's message so a test can match on
//! the rejection reason.

use base64::Engine;
use serde_json::{json, Value};

pub struct Rpc {
    url: String,
    auth: String,
    agent: ureq::Agent,
}

impl Rpc {
    pub fn new(url: &str, user: &str, pass: &str) -> Self {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        // A scan of signet's UTXO set takes a while; a node that stops answering must not hang a party.
        let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(300)).build();
        Rpc { url: url.to_string(), auth: format!("Basic {token}"), agent }
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({ "jsonrpc": "1.0", "id": "bsb", "method": method, "params": params });
        let resp = self.agent.post(&self.url).set("Authorization", &self.auth).send_json(body);
        let v: Value = match resp {
            Ok(r) => r.into_json().map_err(|e| e.to_string())?,
            Err(ureq::Error::Status(_, r)) => r.into_json().map_err(|e| e.to_string())?,
            Err(e) => return Err(e.to_string()),
        };
        if !v["error"].is_null() {
            return Err(v["error"]["message"].as_str().unwrap_or("unknown error").to_string());
        }
        Ok(v["result"].clone())
    }

    pub fn height(&self) -> u32 {
        self.call("getblockcount", json!([])).unwrap().as_u64().unwrap() as u32
    }
}
