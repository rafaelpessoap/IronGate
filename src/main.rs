use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;
use std::env;
use std::sync::Arc;
use tokio::sync::{mpsc, broadcast};
use parking_lot::RwLock;

use irongate::config::AppConfig;
use irongate::log_ingestor::LogIngestor;
use irongate::analytics::AnalyticsEngine;
use irongate::enforcer::Enforcer;
use irongate::dashboard::{self, AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("falha ao ligar logger");

    info!("Iniciando IronGate v0.1.0 (Fase 3 Core Pipeline)");

    let config_path = env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".into());
    let app_config = AppConfig::load_from_file(&config_path)?;

    // 1. Instância do Enforcer
    let htaccess_path = app_config.enforcer.htaccess_path.to_string_lossy().to_string();
    let enforcer = Arc::new(RwLock::new(Enforcer::new(&htaccess_path)?));

    // 2. Canais
    let (ws_tx, _) = broadcast::channel(100);
    let (log_tx, mut log_rx) = mpsc::channel(5000);
    let (block_tx, mut block_rx) = mpsc::channel(100);

    // 3. Analytics Engine
    let analytics = Arc::new(RwLock::new(AnalyticsEngine::new(app_config.clone(), block_tx.clone())));

    // 4. Log Ingestor
    let log_path = app_config.logs.watch_files.first()
        .cloned()
        .unwrap_or_else(|| "/usr/local/lsws/logs/access.log".to_string());
    let ingestor = LogIngestor::new(&log_path, log_tx);
    
    tokio::spawn(async move {
        if let Err(e) = ingestor.run().await {
            error!("Erro fatal no Ingestor: {}", e);
        }
    });

    // 5. Dashboard
    let app_state = AppState {
        tx: ws_tx.clone(),
        analytics: analytics.clone(),
        enforcer: enforcer.clone(),
    };
    tokio::spawn(async move {
        info!("Servidor Dashboard Axum ouvindo na porta 9847");
        if let Err(e) = dashboard::start_server(app_state).await {
            error!("Erro no servidor dashboard: {}", e);
        }
    });

    // 6. Router Principal (Event Loop Real-Time)
    let analytics_ref = analytics.clone();
    let block_tx_router = block_tx.clone();
    tokio::spawn(async move {
        while let Some(entry) = log_rx.recv().await {
            let block_action = {
                let mut engine = analytics_ref.write();
                engine.process_entry(entry)
            };
            // Se houve bloqueio, envia fora do lock (sem segurar o guard no await)
            if let Some((ip, secs)) = block_action {
                let _ = block_tx_router.send((ip, secs)).await;
            }
        }
    });

    // 7. Agente de Bloqueio & Websocket Notifier
    let ws_tx_ref = ws_tx.clone();
    let enforcer_ref = enforcer.clone();
    tokio::spawn(async move {
        while let Some((ip, seconds)) = block_rx.recv().await {
            let mut enf = enforcer_ref.write();
            enf.add_ban(ip.clone(), seconds);
            
            // Notifica via Websocket
            let _ = ws_tx_ref.send(irongate::dashboard::websocket::WsMessage {
                r#type: "BLOCK".to_string(),
                ip: Some(ip),
                score: Some(100.0),
                message: Some("Bloqueado pelo Analytics".to_string()),
            });
        }
    });

    // 8. Cronjob interno (Batching Flush e Cleanup)
    let enforcer_cron = enforcer.clone();
    let analytics_cron = analytics.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            {
                let mut enf = enforcer_cron.write();
                enf.cleanup_expired();
                let _ = enf.flush_batch();
            }
            {
                analytics_cron.write().cleanup_expired_states();
            }
        }
    });

    // Setup de graceful shutdown
    tokio::signal::ctrl_c().await?;
    info!("Sinal de interrupção recebido. Desligando IronGate graciosamente...");

    Ok(())
}
