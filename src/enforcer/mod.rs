pub mod htaccess;
pub mod ols_restart;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tracing::error;

pub use htaccess::HtaccessGuard;
pub use ols_restart::OlsRestartManager;

pub struct Enforcer {
    pub guard: HtaccessGuard,
    pub active_bans: HashMap<String, Instant>,
    pub whitelist: HashSet<String>,
    pub restart_manager: OlsRestartManager,
    pub pending_flush: bool,
    pub last_flush: Instant,
}

impl Enforcer {
    pub fn new(htaccess_path: &str) -> Result<Self, htaccess::Error> {
        let path = std::path::PathBuf::from(htaccess_path);
        let backup_dir = std::path::PathBuf::from(".irongate_backups");
        let guard = HtaccessGuard::new(path, backup_dir, 1000)?;
        Ok(Self {
            guard,
            active_bans: HashMap::new(),
            whitelist: HashSet::new(),
            restart_manager: OlsRestartManager::new(),
            pending_flush: false,
            last_flush: Instant::now(),
        })
    }

    pub fn add_ban(&mut self, ip: String, duration_secs: u64) {
        if self.whitelist.contains(&ip) {
            return;
        }
        
        // TTL absoluto de expiracao
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
        // Cooldown de batching de 5 segundos pra nao arrebentar o disco
        if now.duration_since(self.last_flush) < Duration::from_secs(5) {
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
                tracing::info!("Htcaccess atualizado (Batch). Total bans: {}", rules.len());
                self.pending_flush = false;
                self.last_flush = now;
                // Exige restart gracefull do litespeed pra ele consumir as regras
                self.restart_manager.request_restart();
                Ok(())
            }
            Err(e) => {
                error!("Falha ao efeuar batch write no htaccess: {:?}", e);
                Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e)))
            }
        }
    }
}
