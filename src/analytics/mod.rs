pub mod ip_tracker;
pub mod rules;
pub mod woocommerce;

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
    pub block_tx: mpsc::Sender<(String, u64)>,
}

impl AnalyticsEngine {
    pub fn new(states: HashMap<IpAddr, IpState>, config: AppConfig, block_tx: mpsc::Sender<(String, u64)>) -> Self {
        Self {
            states,
            config,
            block_tx,
        }
    }


    pub fn process_entry(&mut self, entry: AccessLogEntry) -> Option<(String, u64)> {
        let ip = entry.client_ip;
        let window_secs = self.config.detection.window_seconds;
        let ban_escalation = self.config.detection.ban_escalation.clone();
        let detection_rules = self.config.detection.rules.clone();

        let state = self.states.entry(ip).or_insert_with(|| {
            IpState::new(ip, entry.vhost.clone(), entry.user_agent.clone(), window_secs)
        });

        state.last_seen = entry.timestamp;
        state.total_requests += 1;
        state.window.add_request(entry.timestamp);

        match entry.request_type {
            RequestType::Ajax => state.ajax_window.add_request(entry.timestamp),
            RequestType::Api => {
                state.ajax_window.add_request(entry.timestamp);
                *state.custom_counters.entry("api_requests".to_string()).or_insert(0) += 1;
            }
            RequestType::Page | RequestType::WpAdmin => state.page_window.add_request(entry.timestamp),
            RequestType::Static => {
                *state.custom_counters.entry("static_requests".to_string()).or_insert(0) += 1;
            }
            _ => {}
        }

        if entry.request_type == RequestType::WpLogin && entry.method == "POST" {
            *state.custom_counters.entry("login_attempts".to_string()).or_insert(0) += 1;
        }
        if entry.status == 404 {
            *state.custom_counters.entry("404_errors".to_string()).or_insert(0) += 1;
        }
        // Eventos específicos
        woocommerce::process_woo_events(state, &entry);

        if rules::evaluate_rules(state, &detection_rules) {
            let ban_secs = if ban_escalation.is_empty() {
                86400
            } else {
                let idx = (state.strikes as usize).min(ban_escalation.len() - 1);
                ban_escalation[idx]
            };
            warn!("IP Banned: {} (strike #{}, ban {}s)", ip, state.strikes + 1, ban_secs);
            state.ban_until = Some(chrono::Utc::now() + chrono::Duration::seconds(ban_secs as i64));
            state.strikes += 1;
            return Some((ip.to_string(), ban_secs));
        }

        None
    }

    pub fn cleanup_expired_states(&mut self) {
        let now = chrono::Utc::now();
        let cutoff = now - chrono::Duration::seconds(self.config.detection.window_seconds as i64 * 2);
        self.states.retain(|_, state| {
            // Limpar custom_counters junto com sliding windows expiradas
            if state.last_seen < cutoff && !state.ban_until.is_some_and(|b| b > now) {
                return false;
            }
            // Reset custom_counters se o IP expirou da janela principal
            if state.window.count() == 0 {
                state.custom_counters.clear();
            }
            true
        });
    }
}
