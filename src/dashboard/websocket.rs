use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::Response,
};
use tokio::sync::broadcast;
use serde::Serialize;
use futures_util::{sink::SinkExt, stream::StreamExt};

#[derive(Clone, Serialize, Debug)]
pub struct WsMessage {
    pub r#type: String,
    pub ip: Option<String>,
    pub score: Option<f32>,
    pub message: Option<String>,
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    tx: broadcast::Sender<WsMessage>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, tx))
}

async fn handle_socket(socket: WebSocket, tx: broadcast::Sender<WsMessage>) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = tx.subscribe();

    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if let Ok(json) = serde_json::to_string(&msg) {
                if sender.send(Message::Text(json)).await.is_err() {
                    break;
                }
            }
        }
    });

    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(_)) = receiver.next().await {
            // Ignora incoming
        }
    });

    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };
}
