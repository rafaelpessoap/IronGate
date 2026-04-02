use std::net::IpAddr;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq)]
pub enum RequestType {
    Page, Ajax, Static, Api, WpAdmin,
    WpLogin, WpCron, Checkout, Cart, Other,
}

#[derive(Debug, Clone)]
pub struct AccessLogEntry {
    pub vhost: String,
    pub client_ip: IpAddr,
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub uri: String,
    pub status: u16,
    pub size: u64,
    pub referer: String,
    pub user_agent: String,
    pub request_type: RequestType,
}

#[derive(Debug, Clone)]
pub struct BlockRule {
    pub ip: IpAddr,
    pub reason: String,
}
