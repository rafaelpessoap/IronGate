use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("Iniciando IronGate v0.1.0 (Fase 1)");

    let config_path = env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".into());
    let _app_config = irongate::config::AppConfig::load_from_file(&config_path)?;
    info!("Configuração carregada: {:?}", config_path);

    // O pipeline vai aqui
    // log_ingestor -> analtyics -> enforcer

    // Setup de graceful shutdown
    tokio::signal::ctrl_c().await?;
    info!("Desligando IronGate graciosamente...");

    Ok(())
}
