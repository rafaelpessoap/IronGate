pub mod ip_tracker;
pub mod rules;

use std::collections::HashMap;
use std::net::IpAddr;
use tokio::sync::mpsc;
use crate::types::{AccessLogEntry, RequestType};
use crate::config::AppConfig;
use ip_tracker::IpState;
use tracing::warn;

pub struct AnalyticsEngine {
    pub states: HashMap<IpAddr, IpState>,
    pub config: AppConfig,
    pub block_tx: mpsc::Sender<(String, u64)>, // IP, Duration_secs
}

impl AnalyticsEngine {
    pub fn new(config: AppConfig, block_tx: mpsc::Sender<(String, u64)>) -> Self {
        Self {
            states: HashMap::new(),
            config,
            block_tx,
        }
    }

    pub fn process_entry(&mut self, entry: AccessLogEntry) -> Option<(String, u64)> {
        let ip = entry.client_ip;
        let window_secs = self.config.detection.window_seconds;

        let state = self.states.entry(ip).or_insert_with(|| {
            IpState::new(ip, entry.vhost.clone(), entry.user_agent.clone(), window_secs)
        });

        state.last_seen = entry.timestamp;
        state.total_requests += 1;
        state.window.add_request(entry.timestamp);

        match entry.request_type {
            RequestType::Ajax | RequestType::Api => state.ajax_window.add_request(entry.timestamp),
            RequestType::Page | RequestType::WpAdmin => state.page_window.add_request(entry.timestamp),
            _ => {}
        }

        // Custom Counters
        if entry.request_type == RequestType::WpLogin && entry.method == "POST" {
            *state.custom_counters.entry("login_attempts".to_string()).or_insert(0) += 1;
        }
        if entry.status == 404 {
            *state.custom_counters.entry("404_errors".to_string()).or_insert(0) += 1;
        }
        if entry.request_type == RequestType::Cart {
            *state.custom_counters.entry("cart_abuse".to_string()).or_insert(0) += 1;
        }
        if entry.request_type == RequestType::Checkout && entry.method == "POST" {
            *state.custom_counters.entry("checkout_attempts".to_string()).or_insert(0) += 1;
        }

        if rules::evaluate_rules(state) {
            warn!("IP Banned: {}", ip);
            state.ban_until = Some(chrono::Utc::now() + chrono::Duration::seconds(86400));
            state.strikes += 1;
            return Some((ip.to_string(), 86400));
        }

        None
    }
    
    // Limpeza periodica
    pub fn cleanup_expired_states(&mut self) {
        let now = chrono::Utc::now();
        let cutoff = now - chrono::Duration::seconds(self.config.detection.window_seconds as i64 * 2);
        self.states.retain(|_, state| state.last_seen > cutoff || state.ban_until.is_some_and(|b| b > now));
    }
}
