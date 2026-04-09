pub mod htaccess;
pub mod ols_restart;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tracing::{error, info};

pub use htaccess::HtaccessGuard;
pub use ols_restart::OlsRestartManager;

use crate::config::EnforcerConfig;

pub struct Enforcer {
    pub guard: HtaccessGuard,
    pub active_bans: HashMap<String, Instant>,
    pub whitelist: HashSet<String>,
    pub restart_manager: OlsRestartManager,
    pub pending_flush: bool,
    pub last_flush: Instant,
    pub dry_run: bool,
    flush_interval: Duration,
}

impl Enforcer {
    pub fn new(config: &EnforcerConfig) -> Result<Self, htaccess::Error> {
        let guard = HtaccessGuard::new(
            config.htaccess_path.clone(),
            config.backup_dir.clone(),
            config.max_rules,
        )?;
        let restart_manager = OlsRestartManager::new(&config.graceful_restart);

        Ok(Self {
            guard,
            active_bans: HashMap::new(),
            whitelist: HashSet::new(),
            restart_manager,
            pending_flush: false,
            last_flush: Instant::now(),
            dry_run: config.dry_run,
            flush_interval: Duration::from_secs(config.flush_interval_secs),
        })
    }

    pub fn add_ban(&mut self, ip: String, duration_secs: u64) {
        if self.whitelist.contains(&ip) {
            return;
        }
        let expire_at = Instant::now() + Duration::from_secs(duration_secs);
        self.active_bans.insert(ip, expire_at);
        self.pending_flush = true;
    }

    pub fn cleanup_expired(&mut self) -> bool {
        let now = Instant::now();
        let initial_len = self.active_bans.len();
        self.active_bans.retain(|_, &mut expire_at| expire_at > now);
        let have_expired = self.active_bans.len() < initial_len;
        if have_expired {
            self.pending_flush = true;
        }
        have_expired
    }

    pub fn flush_batch(&mut self) -> std::io::Result<()> {
        if !self.pending_flush {
            return Ok(());
        }

        let now = Instant::now();
        if now.duration_since(self.last_flush) < self.flush_interval {
            return Ok(());
        }

        if self.dry_run {
            info!(
                "[DRY-RUN] Flush: {} bans seriam escritos no .htaccess (skipped).",
                self.active_bans.len()
            );
            self.pending_flush = false;
            self.last_flush = now;
            return Ok(());
        }

        let ips: Vec<String> = self.active_bans.keys().cloned().collect();
        let mut rules = Vec::new();
        for ip in ips {
            if let Ok(addr) = ip.parse() {
                rules.push(crate::types::BlockRule {
                    ip: addr,
                    reason: "analytics_ban".to_string(),
                });
            }
        }

        match self.guard.write_rules(&rules) {
            Ok(_) => {
                info!("Htaccess atualizado (Batch). Total bans: {}", rules.len());
                self.pending_flush = false;
                self.last_flush = now;
                self.restart_manager.request_restart(self.dry_run);
                Ok(())
            }
            Err(htaccess::Error::ExternalModification) => {
                // Plano §2.7: Atualizar hash e tentar no próximo ciclo
                info!("Modificação externa detectada. Atualizando hash para o próximo ciclo.");
                let _ = self.guard.refresh_hash();
                Ok(())
            }
            Err(htaccess::Error::EmergencyMode) => {
                error!("MODO EMERGÊNCIA ATIVO. Nenhuma escrita será feita.");
                Ok(())
            }
            Err(e) => {
                error!("Falha ao efetuar batch write no htaccess: {:?}", e);
                Err(std::io::Error::other(format!("{:?}", e)))
            }
        }
    }
}
