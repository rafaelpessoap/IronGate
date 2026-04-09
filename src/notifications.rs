use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tracing::{info, error, warn};

#[derive(Debug, Deserialize, Clone)]
pub struct WebhookConfig {
    pub enabled: bool,
    #[serde(default)]
    pub urls: Vec<String>,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            urls: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct Alert {
    pub level: AlertLevel,
    pub title: String,
    pub message: String,
    pub timestamp: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for AlertLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertLevel::Info => write!(f, "INFO"),
            AlertLevel::Warning => write!(f, "WARNING"),
            AlertLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

pub struct Notifier {
    config: WebhookConfig,
    #[cfg(feature = "webhooks")]
    client: reqwest::Client,
    /// Rate limit: minimum interval between alerts of the same type
    last_alert: parking_lot::Mutex<Option<Instant>>,
}

/// Minimum 60 seconds between webhook alerts to prevent spam
const ALERT_COOLDOWN: Duration = Duration::from_secs(60);
/// HTTP timeout for webhook requests
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);

impl Notifier {
    pub fn new(config: WebhookConfig) -> Self {
        // Validate URLs upfront
        if config.enabled {
            for url in &config.urls {
                if !url.starts_with("https://") && !url.starts_with("http://") {
                    warn!("Webhook URL invalida ignorada (deve comecar com http:// ou https://): {}", url);
                }
            }
        }

        Self {
            config,
            #[cfg(feature = "webhooks")]
            client: reqwest::Client::builder()
                .timeout(WEBHOOK_TIMEOUT)
                .build()
                .unwrap_or_default(),
            last_alert: parking_lot::Mutex::new(None),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled && !self.config.urls.is_empty()
    }

    pub async fn send_alert(&self, alert: Alert) {
        if !self.is_enabled() {
            return;
        }

        // Rate limiting: no more than 1 alert per ALERT_COOLDOWN
        {
            let mut last = self.last_alert.lock();
            if let Some(t) = *last {
                if t.elapsed() < ALERT_COOLDOWN {
                    info!("[ALERT][THROTTLED] {} - {} (cooldown ativo)", alert.title, alert.message);
                    return;
                }
            }
            *last = Some(Instant::now());
        }

        info!("[ALERT][{}] {} - {}", alert.level, alert.title, alert.message);

        for url in &self.config.urls {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                continue;
            }
            // Fire-and-forget in a separate task so we never block the daemon
            let url = url.clone();
            let alert = alert.clone();
            #[cfg(feature = "webhooks")]
            let client = self.client.clone();

            tokio::spawn(async move {
                #[cfg(feature = "webhooks")]
                {
                    let body = if url.contains("discord") {
                        format_discord(&alert)
                    } else if url.contains("telegram") {
                        format_telegram(&alert)
                    } else {
                        match serde_json::to_value(&alert) {
                            Ok(v) => v,
                            Err(e) => {
                                error!("Falha ao serializar alerta: {}", e);
                                return;
                            }
                        }
                    };

                    match client.post(&url).json(&body).send().await {
                        Ok(resp) => {
                            if !resp.status().is_success() {
                                error!("Webhook {} retornou status {}", url, resp.status());
                            }
                        }
                        Err(e) => {
                            error!("Falha ao enviar webhook para {}: {}", url, e);
                        }
                    }
                }

                #[cfg(not(feature = "webhooks"))]
                {
                    let _ = (url, alert);
                    warn!("Webhooks desabilitados (feature 'webhooks' nao compilada)");
                }
            });
        }
    }
}

#[cfg(feature = "webhooks")]
fn format_discord(alert: &Alert) -> serde_json::Value {
    let color = match alert.level {
        AlertLevel::Info => 3447003,      // blue
        AlertLevel::Warning => 16776960,  // yellow
        AlertLevel::Critical => 15158332, // red
    };

    serde_json::json!({
        "embeds": [{
            "title": format!("[IronGate] {}", alert.title),
            "description": alert.message,
            "color": color,
            "timestamp": alert.timestamp,
            "footer": { "text": "IronGate Bot Protection" }
        }]
    })
}

#[cfg(feature = "webhooks")]
fn format_telegram(alert: &Alert) -> serde_json::Value {
    let emoji = match alert.level {
        AlertLevel::Info => "\u{2139}\u{fe0f}",
        AlertLevel::Warning => "\u{26a0}\u{fe0f}",
        AlertLevel::Critical => "\u{1f6a8}",
    };

    serde_json::json!({
        "text": format!("{} *[IronGate] {}*\n{}", emoji, alert.title, alert.message),
        "parse_mode": "Markdown"
    })
}

// Convenience functions for common alerts
impl Notifier {
    pub async fn alert_emergency_mode(&self) {
        self.send_alert(Alert {
            level: AlertLevel::Critical,
            title: "MODO EMERGENCIA ATIVADO".to_string(),
            message: "HtaccessGuard entrou em modo emergencia apos 3+ falhas consecutivas de escrita. Nenhuma regra sera escrita no .htaccess ate intervencao manual.".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }).await;
    }

    pub async fn alert_mass_ban(&self, count: usize) {
        self.send_alert(Alert {
            level: AlertLevel::Warning,
            title: "Possivel Ataque DDoS".to_string(),
            message: format!("{} IPs bloqueados simultaneamente. Verificar dashboard.", count),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }).await;
    }

    pub async fn alert_restart_failed(&self, error: &str) {
        self.send_alert(Alert {
            level: AlertLevel::Critical,
            title: "Falha no Graceful Restart do OLS".to_string(),
            message: format!("Comando de restart falhou: {}", error),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }).await;
    }
}
