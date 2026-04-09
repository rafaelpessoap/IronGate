use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

use crate::config::GracefulRestartConfig;

pub struct OlsRestartManager {
    enabled: bool,
    cmd: String,
    min_interval: Duration,
    max_per_hour: usize,
    history: VecDeque<Instant>,
    last_restart: Option<Instant>,
}

impl OlsRestartManager {
    pub fn new(config: &GracefulRestartConfig) -> Self {
        Self {
            enabled: config.enabled,
            cmd: config.cmd.clone(),
            min_interval: Duration::from_secs(config.min_interval_secs),
            max_per_hour: config.max_per_hour as usize,
            history: VecDeque::new(),
            last_restart: None,
        }
    }

    pub fn request_restart(&mut self, dry_run: bool) -> bool {
        if !self.enabled {
            return false;
        }

        if dry_run {
            info!("[DRY-RUN] Restart do OLS seria executado (skipped).");
            return false;
        }

        let now = Instant::now();

        // Limpa histórico maior de 1 hora
        let hour_ago = now - Duration::from_secs(3600);
        while let Some(&t) = self.history.front() {
            if t < hour_ago {
                self.history.pop_front();
            } else {
                break;
            }
        }

        // Cooldown mínimo
        if let Some(last) = self.last_restart {
            if now.duration_since(last) < self.min_interval {
                warn!("Restart adiado: no período de cooldown.");
                return false;
            }
        }

        // Taxa limite por hora
        if self.history.len() >= self.max_per_hour {
            error!(
                "Restart bloqueado: atingiu limite de {} restarts por hora.",
                self.max_per_hour
            );
            return false;
        }

        // Executa o comando configurado
        match std::process::Command::new("sh")
            .arg("-c")
            .arg(&self.cmd)
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    info!("OpenLiteSpeed reiniciado com sucesso via: {}", self.cmd);
                    self.history.push_back(now);
                    self.last_restart = Some(now);
                    true
                } else {
                    let err = String::from_utf8_lossy(&output.stderr);
                    error!("Falha ao reiniciar OpenLiteSpeed: {}", err);
                    false
                }
            }
            Err(e) => {
                error!("Erro fatal ao invocar comando de restart: {}", e);
                false
            }
        }
    }
}
