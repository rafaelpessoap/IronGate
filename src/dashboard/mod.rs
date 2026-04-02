pub mod static_html;
pub mod websocket;

use axum::{
    routing::{get, post},
    Router, Json, extract::State
};
use tokio::sync::broadcast;
use parking_lot::RwLock;
use serde::Deserialize;
use std::sync::Arc;

use crate::analytics::AnalyticsEngine;
use crate::enforcer::Enforcer;

#[derive(Clone)]
pub struct AppState {
    pub tx: broadcast::Sender<websocket::WsMessage>,
    pub analytics: Arc<RwLock<AnalyticsEngine>>,
    pub enforcer: Arc<RwLock<Enforcer>>,
}

#[derive(Deserialize)]
pub struct IpActionPayload {
    ip: String,
}

pub async fn start_server(state: AppState) -> std::io::Result<()> {
    let app = Router::new()
        .route("/", get(static_html::index_html))
        .route("/style.css", get(static_html::style_css))
        .route("/app.js", get(static_html::app_js))
        .route("/ws", get(|ws, State(state): State<AppState>| async move {
            websocket::ws_handler(ws, state.tx).await
        }))
        .route("/api/status", get(api_status))
        .route("/api/ips", get(api_ips))
        .route("/api/guard-status", get(api_guard_status))
        .route("/api/block", post(api_block))
        .route("/api/whitelist", post(api_whitelist))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:9847").await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}

async fn api_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let analytics = state.analytics.read();
    let enforcer = state.enforcer.read();
    
    let total_reqs: u64 = analytics.states.values().map(|s| s.total_requests).sum();

    Json(serde_json::json!({
        "total_requests": total_reqs,
        "active_ips": analytics.states.len(),
        "active_bans": enforcer.active_bans.len()
    }))
}

async fn api_ips(State(state): State<AppState>) -> Json<Vec<serde_json::Value>> {
    let analytics = state.analytics.read();
    let mut ips = Vec::new();
    
    for (ip, s) in &analytics.states {
        ips.push(serde_json::json!({
            "ip": ip.to_string(),
            "score": s.threat_score,
            "requests": s.total_requests,
            "strikes": s.strikes,
        }));
    }
    Json(ips)
}

async fn api_guard_status(State(_state): State<AppState>) -> Json<serde_json::Value> {
    // Pode pegar metadados do `htaccess.rs` dps
    Json(serde_json::json!({
        "state": "active",
        "writes": 0
    }))
}

async fn api_block(State(state): State<AppState>, Json(payload): Json<IpActionPayload>) -> Json<serde_json::Value> {
    {
        let mut enforcer = state.enforcer.write();
        enforcer.add_ban(payload.ip.clone(), 86400);
        let _ = enforcer.flush_batch();
    }

    let _ = state.tx.send(websocket::WsMessage {
        r#type: "BLOCK".to_string(),
        ip: Some(payload.ip),
        score: Some(100.0),
        message: Some("Banido via API".to_string()),
    });
    Json(serde_json::json!({"status": "ok"}))
}

async fn api_whitelist(State(state): State<AppState>, Json(payload): Json<IpActionPayload>) -> Json<serde_json::Value> {
    {
        let mut enforcer = state.enforcer.write();
        enforcer.active_bans.remove(&payload.ip);
        enforcer.whitelist.insert(payload.ip.clone());
        let _ = enforcer.flush_batch();
    }
    Json(serde_json::json!({"status": "ok"}))
}
