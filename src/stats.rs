use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use tracing::{error, info};

use crate::analytics::ip_tracker::IpState;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DailyStats {
    pub date: String,
    pub total_requests: u64,
    pub unique_ips: u64,
    pub total_bans: u64,
    pub top_blocked_ips: Vec<(String, u32)>,
    pub top_vhosts: HashMap<String, u64>,
    pub rule_triggers: HashMap<String, u64>,
    pub peak_active_ips: u64,
    pub peak_active_bans: u64,
}

pub struct StatsManager {
    stats_dir: PathBuf,
    current_date: String,
    current_stats: DailyStats,
}

impl StatsManager {
    pub fn new(state_dir: &str) -> std::io::Result<Self> {
        let stats_dir = PathBuf::from(state_dir).join("stats");
        if !stats_dir.exists() {
            fs::create_dir_all(&stats_dir)?;
        }

        let today = Utc::now().format("%Y-%m-%d").to_string();

        // Try to load existing stats for today
        let current_stats = Self::load_stats_file(&stats_dir, &today);

        Ok(Self {
            stats_dir,
            current_date: today,
            current_stats,
        })
    }

    /// Update stats from current engine state. Called periodically.
    pub fn update(&mut self, states: &HashMap<IpAddr, IpState>, active_bans: usize) {
        let today = Utc::now().format("%Y-%m-%d").to_string();

        // Day rollover
        if today != self.current_date {
            self.save();
            self.current_date = today.clone();
            self.current_stats = DailyStats {
                date: today,
                ..Default::default()
            };
        }

        let total_reqs: u64 = states.values().map(|s| s.total_requests).sum();
        self.current_stats.total_requests = total_reqs;
        self.current_stats.unique_ips = states.len() as u64;

        // Track peak values
        if (states.len() as u64) > self.current_stats.peak_active_ips {
            self.current_stats.peak_active_ips = states.len() as u64;
        }
        if (active_bans as u64) > self.current_stats.peak_active_bans {
            self.current_stats.peak_active_bans = active_bans as u64;
        }

        // Aggregate vhost traffic
        let mut vhost_map: HashMap<String, u64> = HashMap::new();
        for state in states.values() {
            *vhost_map.entry(state.vhost.clone()).or_insert(0) += state.total_requests;
        }
        self.current_stats.top_vhosts = vhost_map;

        // Count bans and top blocked IPs
        let mut blocked: Vec<(String, u32)> = states
            .values()
            .filter(|s| s.ban_until.is_some())
            .map(|s| (s.ip.to_string(), s.strikes))
            .collect();
        blocked.sort_by(|a, b| b.1.cmp(&a.1));
        blocked.truncate(20);
        self.current_stats.total_bans = blocked.len() as u64;
        self.current_stats.top_blocked_ips = blocked;
    }

    /// Record a rule trigger for daily stats
    pub fn record_rule_trigger(&mut self, rule_name: &str) {
        *self
            .current_stats
            .rule_triggers
            .entry(rule_name.to_string())
            .or_insert(0) += 1;
    }

    pub fn save(&self) {
        let file_name = format!("{}.json", self.current_stats.date);
        let file_path = self.stats_dir.join(&file_name);

        match serde_json::to_string_pretty(&self.current_stats) {
            Ok(json) => {
                let temp_path = file_path.with_extension("tmp");
                if let Err(e) = fs::write(&temp_path, &json) {
                    error!("Falha ao gravar stats diarias: {}", e);
                    return;
                }
                if let Err(e) = fs::rename(&temp_path, &file_path) {
                    error!("Falha ao mover stats diarias: {}", e);
                }
            }
            Err(e) => error!("Falha ao serializar stats diarias: {}", e),
        }
    }

    /// Get stats for the dashboard API
    pub fn get_current(&self) -> &DailyStats {
        &self.current_stats
    }

    fn load_stats_file(stats_dir: &std::path::Path, date: &str) -> DailyStats {
        let path = stats_dir.join(format!("{}.json", date));
        if path.exists() {
            match fs::read_to_string(&path) {
                Ok(content) => match serde_json::from_str(&content) {
                    Ok(stats) => {
                        info!("Stats do dia {} restauradas.", date);
                        return stats;
                    }
                    Err(e) => {
                        error!("Falha ao parsear stats {}: {}", date, e);
                    }
                },
                Err(e) => {
                    error!("Falha ao ler stats {}: {}", date, e);
                }
            }
        }
        DailyStats {
            date: date.to_string(),
            ..Default::default()
        }
    }
}
