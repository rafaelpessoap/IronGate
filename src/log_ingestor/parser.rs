use crate::types::{AccessLogEntry, RequestType};
use chrono::DateTime;
use regex::Regex;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::OnceLock;

static LOG_REGEX: OnceLock<Regex> = OnceLock::new();

pub fn parse_line(line: &str) -> Option<AccessLogEntry> {
    let re = LOG_REGEX.get_or_init(|| {
        Regex::new(r#"^\["(?P<vhost>[^"]+)"\]\s+(?P<ip>[^\s]+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>[^\s]+)\s+HTTP/[0-9.]+"\s+(?P<status>\d+)\s+(?P<size>\d+)\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"$"#).unwrap()
    });

    let caps = re.captures(line)?;

    let vhost = caps.name("vhost")?.as_str().to_string();
    let ip_str = caps.name("ip")?.as_str();
    let client_ip = IpAddr::from_str(ip_str).ok()?;

    let ts_str = caps.name("timestamp")?.as_str();
    let timestamp = DateTime::parse_from_str(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        .ok()?
        .with_timezone(&chrono::Utc);

    let method = caps.name("method")?.as_str().to_string();
    let uri = caps.name("uri")?.as_str().to_string();
    let status = caps.name("status")?.as_str().parse().unwrap_or(0);
    let size = caps.name("size")?.as_str().parse().unwrap_or(0);
    let referer = caps.name("referer")?.as_str().to_string();
    let user_agent = caps.name("user_agent")?.as_str().to_string();

    let request_type = determine_request_type(&uri);

    Some(AccessLogEntry {
        vhost,
        client_ip,
        timestamp,
        method,
        uri,
        status,
        size,
        referer,
        user_agent,
        request_type,
    })
}

fn determine_request_type(uri: &str) -> RequestType {
    if uri.contains("wp-admin") {
        RequestType::WpAdmin
    } else if uri.contains("wp-login.php") {
        RequestType::WpLogin
    } else if uri.contains("wp-cron.php") {
        RequestType::WpCron
    } else if uri.contains("wc-ajax=") || uri.contains("/?wc-ajax=") {
        RequestType::Ajax
    } else if uri.starts_with("/wp-json/") {
        RequestType::Api
    } else if uri.contains("/finalizar-compra/") || uri.contains("/checkout/") {
        RequestType::Checkout
    } else if uri.contains("?add-to-cart=") || uri.contains("/carrinho/") {
        RequestType::Cart
    } else if uri.ends_with(".css")
        || uri.ends_with(".js")
        || uri.ends_with(".png")
        || uri.ends_with(".jpg")
        || uri.ends_with(".woff2")
    {
        RequestType::Static
    } else {
        RequestType::Page
    }
}
