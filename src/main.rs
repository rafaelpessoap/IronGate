use clap::Parser;
use parking_lot::RwLock;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

use irongate::analytics::AnalyticsEngine;
use irongate::cli::Cli;
use irongate::config::AppConfig;
use irongate::dashboard::{self, AppState};
use irongate::dns_verify::DnsVerifier;
use irongate::enforcer::Enforcer;
use irongate::log_ingestor::LogIngestor;
use irongate::notifications::Notifier;
use irongate::persistence::PersistenceManager;
use irongate::stats::StatsManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("falha ao ligar logger");

    let cli = Cli::parse();
    let app_config = AppConfig::load_from_file(&cli.config)?;

    // Handle CLI-only commands (status, ban, restore, etc.)
    if cli.execute_cli_command(&app_config)? {
        return Ok(());
    }

    // === DAEMON MODE ===
    info!("Iniciando IronGate v1.0.0 (Fase 4 - Completo)");

    if app_config.enforcer.dry_run {
        info!("MODO DRY-RUN ATIVO - Deteccao ativa, bloqueio desabilitado.");
    }

    // Config wrapped in Arc for hot-reload via SIGHUP
    let config = Arc::new(RwLock::new(app_config.clone()));

    // 1. Enforcer
    let mut enforcer_instance = Enforcer::new(&app_config.enforcer)?;
    for ip in &app_config.whitelist.ips {
        enforcer_instance.whitelist.insert(ip.clone());
    }
    for ip in &app_config.whitelist.server_ips {
        enforcer_instance.whitelist.insert(ip.clone());
    }
    info!(
        "Whitelist carregada: {} IPs",
        enforcer_instance.whitelist.len()
    );
    let enforcer = Arc::new(RwLock::new(enforcer_instance));

    // 2. Channels
    let (ws_tx, _) = broadcast::channel(100);
    let (log_tx, mut log_rx) = mpsc::channel(5000);
    let (block_tx, mut block_rx) = mpsc::channel(100);

    // 3. Analytics Engine & Persistence
    let persistence = PersistenceManager::new(&app_config.general.state_dir)?;
    let loaded_states = persistence.load();
    let analytics = Arc::new(RwLock::new(AnalyticsEngine::new(
        loaded_states,
        app_config.clone(),
        block_tx.clone(),
    )));

    // 4. Notifications (webhooks)
    let notifier = Arc::new(Notifier::new(app_config.webhooks.clone()));

    // 5. DNS Verifier for search engine bots
    let dns_verifier = Arc::new(DnsVerifier::new(&app_config.whitelist.search_engines));

    // 6. Daily Stats
    let stats = Arc::new(RwLock::new(StatsManager::new(
        &app_config.general.state_dir,
    )?));

    // 7. Log Ingestors (multi-vhost: spawn one per watch_file pattern)
    let watch_files = app_config.logs.watch_files.clone();
    for log_path in watch_files {
        let ingestor = LogIngestor::new(&log_path, log_tx.clone());
        tokio::spawn(async move {
            if let Err(e) = ingestor.run().await {
                error!("Erro fatal no Ingestor ({}): {}", log_path, e);
            }
        });
    }
    info!(
        "Monitorando {} fontes de log",
        app_config.logs.watch_files.len()
    );

    // 8. Dashboard
    let bind_addr = app_config.general.bind_addr.clone();
    let app_state = AppState {
        tx: ws_tx.clone(),
        analytics: analytics.clone(),
        enforcer: enforcer.clone(),
        bind_addr: bind_addr.clone(),
        stats: stats.clone(),
    };
    tokio::spawn(async move {
        info!("Dashboard Axum ouvindo em {}", bind_addr);
        if let Err(e) = dashboard::start_server(app_state).await {
            error!("Erro no servidor dashboard: {}", e);
        }
    });

    // 9. Router Principal (Log -> Analytics) with DNS verification
    let analytics_ref = analytics.clone();
    let dns_ref = dns_verifier.clone();
    let known_bots = app_config.known_bots.user_agents.clone();
    let whitelist_uas = app_config.whitelist.user_agents.clone();
    tokio::spawn(async move {
        while let Some(entry) = log_rx.recv().await {
            // Check known bad bot UAs
            let ua_lower = entry.user_agent.to_lowercase();
            let is_known_bad = known_bots
                .iter()
                .any(|bot| ua_lower.contains(&bot.to_lowercase()));

            // Check whitelisted UAs
            let is_whitelisted_ua = whitelist_uas
                .iter()
                .any(|wua| ua_lower.contains(&wua.to_lowercase()));

            // DNS verify potential search engine bots (async)
            if !is_known_bad && !is_whitelisted_ua {
                let potential_bot = ua_lower.contains("bot")
                    || ua_lower.contains("crawler")
                    || ua_lower.contains("spider");
                if potential_bot {
                    if let Some(_bot_name) = dns_ref.verify_bot(entry.client_ip).await {
                        // Verified search engine bot - skip analytics
                        continue;
                    }
                }
            }

            let block_action = {
                let mut engine = analytics_ref.write();
                engine.process_entry(entry)
            };
            if let Some((ip, secs)) = block_action {
                let _ = block_tx.send((ip, secs)).await;
            }
        }
    });

    // 10. Block Agent & WebSocket Notifier
    let ws_tx_ref = ws_tx.clone();
    let enforcer_ref = enforcer.clone();
    let notifier_ref = notifier.clone();
    tokio::spawn(async move {
        let mut ban_count_window: Vec<std::time::Instant> = Vec::new();
        while let Some((ip, seconds)) = block_rx.recv().await {
            {
                let mut enf = enforcer_ref.write();
                enf.add_ban(ip.clone(), seconds);
            }

            let _ = ws_tx_ref.send(irongate::dashboard::websocket::WsMessage {
                r#type: "BLOCK".to_string(),
                ip: Some(ip),
                score: Some(100.0),
                message: Some("Bloqueado pelo Analytics".to_string()),
            });

            // Track bans for mass-ban alert
            ban_count_window.push(std::time::Instant::now());
            ban_count_window.retain(|t| t.elapsed() < std::time::Duration::from_secs(60));
            if ban_count_window.len() > 50 {
                notifier_ref.alert_mass_ban(ban_count_window.len()).await;
                ban_count_window.clear(); // Don't spam alerts
            }
        }
    });

    // 11. Cronjob: Flush + Cleanup + Stats
    let enforcer_cron = enforcer.clone();
    let analytics_cron = analytics.clone();
    let stats_cron = stats.clone();
    let notifier_cron = notifier.clone();
    let flush_secs = app_config.enforcer.flush_interval_secs;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(flush_secs));
        loop {
            interval.tick().await;
            let was_emergency;
            {
                let mut enf = enforcer_cron.write();
                was_emergency = enf.guard.emergency_mode;
                enf.cleanup_expired();
                let _ = enf.flush_batch();

                // Check if we just entered emergency mode
                if enf.guard.emergency_mode && !was_emergency {
                    let notifier = notifier_cron.clone();
                    tokio::spawn(async move {
                        notifier.alert_emergency_mode().await;
                    });
                }
            }
            {
                analytics_cron.write().cleanup_expired_states();
            }
            // Update daily stats
            {
                let analytics = analytics_cron.read();
                let enforcer = enforcer_cron.read();
                let mut s = stats_cron.write();
                s.update(&analytics.states, enforcer.active_bans.len());
            }
        }
    });

    // 12. Cronjob: Persistence Snapshot + Stats Save
    let analytics_snap = analytics.clone();
    let stats_snap = stats.clone();
    let snap_interval = app_config.general.snapshot_interval_secs;
    let persistence_arc = Arc::new(persistence);
    tokio::spawn(async move {
        if snap_interval == 0 {
            return;
        }
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(snap_interval));
        loop {
            interval.tick().await;
            let engine = analytics_snap.read();
            persistence_arc.save(&engine.states);

            // Save daily stats alongside persistence
            stats_snap.read().save();
        }
    });

    // 13. DNS cache cleanup (every 30 minutes)
    let dns_cleanup = dns_verifier.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1800));
        loop {
            interval.tick().await;
            dns_cleanup.cleanup_cache();
        }
    });

    // 14. SIGHUP handler for hot-reload config
    let config_reload = config.clone();
    let config_path = cli.config.clone();
    #[cfg(unix)]
    {
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        tokio::spawn(async move {
            loop {
                sighup.recv().await;
                info!("SIGHUP recebido - recarregando configuracao...");
                match AppConfig::load_from_file(&config_path) {
                    Ok(new_config) => {
                        *config_reload.write() = new_config;
                        info!("Configuracao recarregada com sucesso via SIGHUP.");
                    }
                    Err(e) => {
                        error!(
                            "Falha ao recarregar config: {}. Mantendo config anterior.",
                            e
                        );
                    }
                }
            }
        });
    }

    // Graceful shutdown via SIGTERM/SIGINT
    tokio::signal::ctrl_c().await?;
    info!("Sinal de interrupcao recebido. Desligando IronGate graciosamente...");

    // Save final state
    {
        let engine = analytics.read();
        Arc::new(PersistenceManager::new(&app_config.general.state_dir)?).save(&engine.states);
        stats.read().save();
        info!("Estado final e stats salvos com sucesso.");
    }

    Ok(())
}
