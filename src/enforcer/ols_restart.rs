use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tracing::{info, warn, error};

pub struct OlsRestartManager {
    min_interval: Duration,
    max_per_hour: usize,
    history: VecDeque<Instant>,
    last_restart: Option<Instant>,
}

impl OlsRestartManager {
    pub fn new() -> Self {
        Self {
            min_interval: Duration::from_secs(30),
            max_per_hour: 20,
            history: VecDeque::new(),
            last_restart: None,
        }
    }

    pub fn request_restart(&mut self) -> bool {
        let now = Instant::now();

        // 1. Limpa histórico maior de 1 hora
        let hour_ago = now - Duration::from_secs(3600);
        while let Some(&t) = self.history.front() {
            if t < hour_ago {
                self.history.pop_front();
            } else {
                break;
            }
        }

        // 2. Cooldown de Minutos/Segundos
        if let Some(last) = self.last_restart {
            if now.duration_since(last) < self.min_interval {
                warn!("Restart adiado: no período de cooldown de 30s.");
                return false;
            }
        }

        // 3. Taxa Limite de 1 hora
        if self.history.len() >= self.max_per_hour {
            error!("Restart bloqueado: atingiu limite de 20 restarts por hora para OLS.");
            return false;
        }

        // Efetua Restart
        match std::process::Command::new("systemctl")
            .arg("try-restart")
            .arg("lsws")
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    info!("OpenLiteSpeed reiniciado com sucesso via graceful restart.");
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
                error!("Erro fatal ao invocar systemctl: {}", e);
                false
            }
        }
    }
}
