use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct GeneralConfig {
    pub bind_addr: String,
    pub log_level: String,
    pub state_dir: String,
    pub snapshot_interval_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LogsConfig {
    pub watch_files: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RuleConfig {
    pub enabled: bool,
    pub threshold_ratio: Option<f32>,
    pub min_requests: Option<u64>,
    pub threshold: Option<u64>,
    pub score: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DetectionRules {
    pub ajax_flood: RuleConfig,
    pub page_flood: Option<RuleConfig>,
    pub login_brute: Option<RuleConfig>,
    pub cart_abuse: Option<RuleConfig>,
    pub checkout_spam: Option<RuleConfig>,
    pub scan_404: Option<RuleConfig>,
    pub api_abuse: Option<RuleConfig>,
    pub empty_ua: Option<RuleConfig>,
    pub static_flood: Option<RuleConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DetectionConfig {
    pub window_seconds: u64,
    pub bucket_seconds: u64,
    pub block_threshold: u32,
    pub ban_escalation: Vec<u64>,
    pub strike_memory_hours: u32,
    pub rules: DetectionRules,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GracefulRestartConfig {
    pub enabled: bool,
    pub cmd: String,
    pub min_interval_secs: u64,
    pub max_pending_secs: u64,
    pub max_per_hour: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EnforcerConfig {
    pub htaccess_path: PathBuf,
    pub mode: String,
    pub header_name: String,
    pub cleanup_interval_secs: u64,
    pub flush_interval_secs: u64,
    pub dry_run: bool,
    pub max_rules: usize,
    pub max_consecutive_failures: u32,
    pub backup_before_write: bool,
    pub backup_dir: PathBuf,
    pub backup_retention: usize,
    pub graceful_restart: GracefulRestartConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WhitelistConfig {
    pub ips: Vec<String>,
    pub server_ips: Vec<String>,
    pub user_agents: Vec<String>,
    pub search_engines: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct KnownBotsConfig {
    pub user_agents: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub general: GeneralConfig,
    pub logs: LogsConfig,
    pub detection: DetectionConfig,
    pub enforcer: EnforcerConfig,
    pub whitelist: WhitelistConfig,
    pub known_bots: KnownBotsConfig,
}

impl AppConfig {
    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: AppConfig = toml::from_str(&content)?;
        Ok(config)
    }
}
