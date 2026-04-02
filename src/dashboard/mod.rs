pub mod static_html;
pub mod websocket;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct AppState {
    pub tx: broadcast::Sender<websocket::WsMessage>,
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
        .route(
            "/ws",
            get(|ws, State(state): State<AppState>| async move {
                websocket::ws_handler(ws, state.tx).await
            }),
        )
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

async fn api_status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "total_requests": 15420,
        "active_ips": 12,
        "active_bans": 3
    }))
}

async fn api_ips() -> Json<Vec<serde_json::Value>> {
    Json(vec![
        serde_json::json!({ "ip": "1.2.3.4", "score": 12.5, "requests": 50, "strikes": 0 }),
        serde_json::json!({ "ip": "200.1.1.5", "score": 85.0, "requests": 200, "strikes": 2 }),
    ])
}

async fn api_guard_status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "state": "active",
        "writes": 15
    }))
}

async fn api_block(
    State(state): State<AppState>,
    Json(payload): Json<IpActionPayload>,
) -> Json<serde_json::Value> {
    let _ = state.tx.send(websocket::WsMessage {
        r#type: "BLOCK".to_string(),
        ip: Some(payload.ip),
        score: Some(100.0),
        message: None,
    });
    Json(serde_json::json!({"status": "ok"}))
}

async fn api_whitelist(Json(_payload): Json<IpActionPayload>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}
