use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use std::env;
use tokio::sync::broadcast;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("Iniciando IronGate v0.1.0 (Fase 2)");

    let config_path = env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".into());
    let _app_config = irongate::config::AppConfig::load_from_file(&config_path)?;
    info!("Configuração carregada: {:?}", config_path);

    let (tx, _rx) = broadcast::channel(100);
    let app_state = irongate::dashboard::AppState { tx };

    // Inicia o Servidor Dashboard Async
    tokio::spawn(async move {
        info!("Servidor Dashboard Axum ouvindo em http://0.0.0.0:9847");
        if let Err(e) = irongate::dashboard::start_server(app_state).await {
            tracing::error!("Erro no servidor dashboard: {}", e);
        }
    });

    // O pipeline do core vai rodar aqui...
    
    // Setup de graceful shutdown
    tokio::signal::ctrl_c().await?;
    info!("Desligando IronGate graciosamente...");

    Ok(())
}
