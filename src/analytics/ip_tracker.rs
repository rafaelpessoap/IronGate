use chrono::{DateTime, Utc};
use std::collections::VecDeque;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct SlidingWindow {
    pub window_secs: u64,
    pub request_timestamps: VecDeque<DateTime<Utc>>,
}

impl SlidingWindow {
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs,
            request_timestamps: VecDeque::new(),
        }
    }

    pub fn add_request(&mut self, ts: DateTime<Utc>) {
        self.request_timestamps.push_back(ts);
        self.cleanup(ts);
    }

    pub fn cleanup(&mut self, now: DateTime<Utc>) {
        let cutoff = now - chrono::Duration::seconds(self.window_secs as i64);
        while let Some(&oldest) = self.request_timestamps.front() {
            if oldest < cutoff {
                self.request_timestamps.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn count(&self) -> usize {
        self.request_timestamps.len()
    }
}

#[derive(Debug, Clone)]
pub struct IpState {
    pub ip: IpAddr,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub user_agent: String,
    pub vhost: String,
    pub window: SlidingWindow,
    pub ajax_window: SlidingWindow,
    pub page_window: SlidingWindow,
    pub total_requests: u64,
    pub strikes: u32,
    pub ban_until: Option<DateTime<Utc>>,
    pub is_whitelisted: bool,
    pub threat_score: f32,
}

impl IpState {
    pub fn new(ip: IpAddr, vhost: String, user_agent: String, window_secs: u64) -> Self {
        let now = Utc::now();
        Self {
            ip,
            first_seen: now,
            last_seen: now,
            user_agent,
            vhost,
            window: SlidingWindow::new(window_secs),
            ajax_window: SlidingWindow::new(window_secs),
            page_window: SlidingWindow::new(window_secs),
            total_requests: 0,
            strikes: 0,
            ban_until: None,
            is_whitelisted: false,
            threat_score: 0.0,
        }
    }
}
