pub mod static_html;
pub mod websocket;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use parking_lot::RwLock;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::analytics::AnalyticsEngine;
use crate::enforcer::Enforcer;
use crate::stats::StatsManager;

#[derive(Clone)]
pub struct AppState {
    pub tx: broadcast::Sender<websocket::WsMessage>,
    pub analytics: Arc<RwLock<AnalyticsEngine>>,
    pub enforcer: Arc<RwLock<Enforcer>>,
    pub bind_addr: String,
    pub stats: Arc<RwLock<StatsManager>>,
}

#[derive(Deserialize)]
pub struct IpActionPayload {
    ip: String,
}

pub async fn start_server(state: AppState) -> std::io::Result<()> {
    let bind_addr = state.bind_addr.clone();
    let app = Router::new()
        .route("/", get(static_html::index_html))
        .route("/style.css", get(static_html::style_css))
        .route("/app.js", get(static_html::app_js))
        .route(
            "/ws",
            get(|ws, State(state): State<AppState>| async move {
                websocket::ws_handler(ws, state.tx).await
            }),
        )
        .route("/api/status", get(api_status))
        .route("/api/ips", get(api_ips))
        .route("/api/guard-status", get(api_guard_status))
        .route("/api/stats", get(api_daily_stats))
        .route("/api/block", post(api_block))
        .route("/api/unblock", post(api_unblock))
        .route("/api/whitelist", post(api_whitelist))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
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
        "active_bans": enforcer.active_bans.len(),
        "dry_run": enforcer.dry_run
    }))
}

async fn api_ips(State(state): State<AppState>) -> Json<Vec<serde_json::Value>> {
    let analytics = state.analytics.read();
    let mut ips: Vec<serde_json::Value> = analytics
        .states
        .iter()
        .map(|(ip, s)| {
            serde_json::json!({
                "ip": ip.to_string(),
                "vhost": s.vhost,
                "score": s.threat_score,
                "requests": s.total_requests,
                "strikes": s.strikes,
                "user_agent": s.user_agent,
                "banned": s.ban_until.is_some(),
            })
        })
        .collect();
    ips.sort_by(|a, b| {
        b["score"]
            .as_f64()
            .partial_cmp(&a["score"].as_f64())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Json(ips)
}

async fn api_guard_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let enforcer = state.enforcer.read();
    let emergency = enforcer.guard.emergency_mode;
    let guard_state = if emergency { "emergency" } else { "active" };
    Json(serde_json::json!({
        "state": guard_state,
        "writes": enforcer.guard.total_writes,
        "blocked_writes": enforcer.guard.total_blocked_writes,
        "dry_run": enforcer.dry_run
    }))
}

async fn api_block(
    State(state): State<AppState>,
    Json(payload): Json<IpActionPayload>,
) -> Json<serde_json::Value> {
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

async fn api_unblock(
    State(state): State<AppState>,
    Json(payload): Json<IpActionPayload>,
) -> Json<serde_json::Value> {
    {
        let mut enforcer = state.enforcer.write();
        enforcer.active_bans.remove(&payload.ip);
        enforcer.pending_flush = true;
        let _ = enforcer.flush_batch();
    }
    Json(serde_json::json!({"status": "ok"}))
}

async fn api_whitelist(
    State(state): State<AppState>,
    Json(payload): Json<IpActionPayload>,
) -> Json<serde_json::Value> {
    {
        let mut enforcer = state.enforcer.write();
        enforcer.active_bans.remove(&payload.ip);
        enforcer.whitelist.insert(payload.ip.clone());
        enforcer.pending_flush = true;
        let _ = enforcer.flush_batch();
    }
    Json(serde_json::json!({"status": "ok"}))
}

async fn api_daily_stats(State(state): State<AppState>) -> Json<serde_json::Value> {
    let stats = state.stats.read();
    let current = stats.get_current();
    Json(serde_json::json!({
        "date": current.date,
        "total_requests": current.total_requests,
        "unique_ips": current.unique_ips,
        "total_bans": current.total_bans,
        "peak_active_ips": current.peak_active_ips,
        "peak_active_bans": current.peak_active_bans,
        "top_vhosts": current.top_vhosts,
        "rule_triggers": current.rule_triggers,
        "top_blocked_ips": current.top_blocked_ips,
    }))
}
