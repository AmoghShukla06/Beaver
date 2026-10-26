//! Records exchanged with the desktop UI. Field names match the JSON the UI already consumes.
use crate::intel::Hit;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Serialize)]
pub struct Conn {
    pub id: String,
    pub app_id: String,
    pub pid: Option<u32>,
    pub process_created: Option<f64>,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub protocol: String,
    pub status: String,
    pub source: String,
    pub first_seen: f64,
    pub last_seen: f64,
    pub domain: Option<String>,
    pub geo: Option<Value>,
    pub threat: Option<Hit>,
}

impl Conn {
    pub fn key(&self) -> (String, Option<u32>, Option<u64>, String, String, u16, Option<String>, Option<u16>) {
        (self.app_id.clone(), self.pid, self.process_created.map(f64::to_bits), self.protocol.clone(), self.local_ip.clone(),
         self.local_port, self.remote_ip.clone(), self.remote_port)
    }
}

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct Binary {
    pub path: String,
    pub state: String,
    pub location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inspected: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    #[serde(default)]
    pub os_binary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<f64>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct Evidence {
    pub rule: String,
    pub points: i32,
    pub title: String,
    pub detail: String,
    pub category: String,
    pub technique: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feeds: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<u16>>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct Risk {
    pub level: String,
    pub score: Option<i32>,
    pub evidence: Vec<Evidence>,
    pub reason: String,
    pub allowlisted: bool,
    pub intel_score: i32,
    pub behavior_score: i32,
    pub remote_tool: Option<String>,
}

#[derive(Clone, Serialize, Debug, Default)]
pub struct App {
    pub id: String,
    pub name: String,
    pub path: Option<String>,
    pub pids: Vec<u32>,
    pub connections: usize,
    pub parent: Option<String>,
    pub binary: Option<Binary>,
    pub risk: Risk,
    pub listening: usize,
    pub upload_bps: Option<f64>,
    pub download_bps: Option<f64>,
    pub uploaded: Option<u64>,
    pub downloaded: Option<u64>,
}
