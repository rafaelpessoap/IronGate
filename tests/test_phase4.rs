use std::collections::HashMap;
use std::net::IpAddr;

// =============================================================
// Tests for CLI parsing
// =============================================================

#[test]
fn test_cli_parse_run_default() {
    use clap::Parser;
    use irongate::cli::Cli;

    let cli = Cli::parse_from(["irongate"]);
    assert!(cli.command.is_none());
    assert_eq!(cli.config, "config.toml");
}

#[test]
fn test_cli_parse_run_explicit() {
    use clap::Parser;
    use irongate::cli::Cli;

    let cli = Cli::parse_from(["irongate", "run"]);
    assert!(matches!(cli.command, Some(irongate::cli::Commands::Run)));
}

#[test]
fn test_cli_parse_status() {
    use clap::Parser;
    use irongate::cli::Cli;

    let cli = Cli::parse_from(["irongate", "status"]);
    assert!(matches!(cli.command, Some(irongate::cli::Commands::Status)));
}

#[test]
fn test_cli_parse_ban_with_defaults() {
    use clap::Parser;
    use irongate::cli::Cli;

    let cli = Cli::parse_from(["irongate", "ban", "1.2.3.4"]);
    if let Some(irongate::cli::Commands::Ban { ip, duration }) = cli.command {
        assert_eq!(ip, "1.2.3.4");
        assert_eq!(duration, 86400);
    } else {
        panic!("Expected Ban command");
    }
}

#[test]
fn test_cli_parse_ban_with_custom_duration() {
    use clap::Parser;
    use irongate::cli::Cli;

    let cli = Cli::parse_from(["irongate", "ban", "10.0.0.1", "-d", "3600"]);
    if let Some(irongate::cli::Commands::Ban { ip, duration }) = cli.command {
        assert_eq!(ip, "10.0.0.1");
        assert_eq!(duration, 3600);
    } else {
        panic!("Expected Ban command");
    }
}

#[test]
fn test_cli_parse_restore_latest() {
    use clap::Parser;
    use irongate::cli::Cli;

    let cli = Cli::parse_from(["irongate", "restore", "--latest"]);
    if let Some(irongate::cli::Commands::Restore { backup, latest }) = cli.command {
        assert!(latest);
        assert!(backup.is_none());
    } else {
        panic!("Expected Restore command");
    }
}

#[test]
fn test_cli_parse_custom_config() {
    use clap::Parser;
    use irongate::cli::Cli;

    let cli = Cli::parse_from([
        "irongate",
        "--config",
        "/etc/irongate/config.toml",
        "status",
    ]);
    assert_eq!(cli.config, "/etc/irongate/config.toml");
}

// =============================================================
// Tests for StatsManager
// =============================================================

#[test]
fn test_stats_manager_creation() {
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path().to_str().unwrap();

    let stats = irongate::stats::StatsManager::new(state_dir).unwrap();
    let current = stats.get_current();

    // Should have today's date
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    assert_eq!(current.date, today);
    assert_eq!(current.total_requests, 0);
    assert_eq!(current.unique_ips, 0);
}

#[test]
fn test_stats_update_from_engine_state() {
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path().to_str().unwrap();

    let mut stats = irongate::stats::StatsManager::new(state_dir).unwrap();

    // Build mock states
    let mut states: HashMap<IpAddr, irongate::analytics::ip_tracker::IpState> = HashMap::new();
    let ip1: IpAddr = "1.2.3.4".parse().unwrap();
    let ip2: IpAddr = "5.6.7.8".parse().unwrap();

    let mut state1 = irongate::analytics::ip_tracker::IpState::new(
        ip1,
        "arsenal.com".to_string(),
        "Mozilla".to_string(),
        300,
    );
    state1.total_requests = 150;

    let mut state2 = irongate::analytics::ip_tracker::IpState::new(
        ip2,
        "marketing.com".to_string(),
        "Bot".to_string(),
        300,
    );
    state2.total_requests = 50;
    state2.ban_until = Some(chrono::Utc::now() + chrono::Duration::hours(1));
    state2.strikes = 2;

    states.insert(ip1, state1);
    states.insert(ip2, state2);

    stats.update(&states, 1);

    let current = stats.get_current();
    assert_eq!(current.total_requests, 200);
    assert_eq!(current.unique_ips, 2);
    assert_eq!(current.peak_active_ips, 2);
    assert_eq!(current.peak_active_bans, 1);
    assert!(current.top_vhosts.contains_key("arsenal.com"));
    assert!(current.top_vhosts.contains_key("marketing.com"));
}

#[test]
fn test_stats_save_and_load() {
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path().to_str().unwrap();

    let mut stats = irongate::stats::StatsManager::new(state_dir).unwrap();

    let mut states: HashMap<IpAddr, irongate::analytics::ip_tracker::IpState> = HashMap::new();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    let mut state = irongate::analytics::ip_tracker::IpState::new(
        ip,
        "test.com".to_string(),
        "UA".to_string(),
        300,
    );
    state.total_requests = 999;
    states.insert(ip, state);

    stats.update(&states, 0);
    stats.save();

    // Check file exists
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let stats_file = tmp.path().join("stats").join(format!("{}.json", today));
    assert!(stats_file.exists());

    // Load and verify
    let content = std::fs::read_to_string(&stats_file).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["total_requests"], 999);
}

#[test]
fn test_stats_rule_trigger_tracking() {
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path().to_str().unwrap();

    let mut stats = irongate::stats::StatsManager::new(state_dir).unwrap();
    stats.record_rule_trigger("ajax_flood");
    stats.record_rule_trigger("ajax_flood");
    stats.record_rule_trigger("login_brute");

    let current = stats.get_current();
    assert_eq!(*current.rule_triggers.get("ajax_flood").unwrap(), 2);
    assert_eq!(*current.rule_triggers.get("login_brute").unwrap(), 1);
}

// =============================================================
// Tests for Notifications
// =============================================================

#[test]
fn test_notifier_disabled_by_default() {
    let config = irongate::notifications::WebhookConfig {
        enabled: false,
        urls: vec![],
    };
    let notifier = irongate::notifications::Notifier::new(config);
    assert!(!notifier.is_enabled());
}

#[test]
fn test_notifier_enabled_with_urls() {
    let config = irongate::notifications::WebhookConfig {
        enabled: true,
        urls: vec!["https://example.com/webhook".to_string()],
    };
    let notifier = irongate::notifications::Notifier::new(config);
    assert!(notifier.is_enabled());
}

#[test]
fn test_notifier_enabled_but_no_urls() {
    let config = irongate::notifications::WebhookConfig {
        enabled: true,
        urls: vec![],
    };
    let notifier = irongate::notifications::Notifier::new(config);
    assert!(!notifier.is_enabled());
}

// =============================================================
// Tests for DNS Verifier
// =============================================================

#[test]
fn test_dns_verifier_creation() {
    let domains = vec!["googlebot.com".to_string(), "search.msn.com".to_string()];
    let verifier = irongate::dns_verify::DnsVerifier::new(&domains);
    // Should create without panic
    verifier.cleanup_cache();
}

#[tokio::test]
async fn test_dns_verifier_non_bot_ip() {
    let verifier = irongate::dns_verify::DnsVerifier::new(&[]);
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    // Localhost should not be a verified bot
    let result = verifier.verify_bot(ip).await;
    assert!(result.is_none());
}

#[test]
fn test_dns_verifier_cache_cleanup() {
    let verifier = irongate::dns_verify::DnsVerifier::new(&[]);
    // Should not panic on empty cache
    verifier.cleanup_cache();
}

// =============================================================
// Tests for Config with webhooks section
// =============================================================

#[test]
fn test_config_with_webhooks() {
    let toml_str = r#"
[general]
bind_addr = "127.0.0.1:9847"
log_level = "info"
state_dir = "/tmp/irongate_test"
snapshot_interval_secs = 30

[logs]
watch_files = ["/tmp/test.log"]

[detection]
window_seconds = 300
bucket_seconds = 10
block_threshold = 50
ban_escalation = [600]
strike_memory_hours = 24

[detection.rules]
ajax_flood = { enabled = true, threshold_ratio = 10.0, min_requests = 200, score = 40 }

[enforcer]
htaccess_path = "/tmp/test_htaccess"
mode = "header"
header_name = "X-Forwarded-For"
cleanup_interval_secs = 60
flush_interval_secs = 10
dry_run = true
max_rules = 500
max_consecutive_failures = 3
backup_before_write = true
backup_dir = "/tmp/test_backups"
backup_retention = 100

[enforcer.graceful_restart]
enabled = false
cmd = "echo test"
min_interval_secs = 30
max_pending_secs = 60
max_per_hour = 20

[whitelist]
ips = []
server_ips = ["127.0.0.1"]
user_agents = []
search_engines = ["googlebot.com"]

[known_bots]
user_agents = ["zgrab"]

[webhooks]
enabled = true
urls = ["https://hooks.example.com/test"]
"#;

    let config: irongate::config::AppConfig = toml::from_str(toml_str).unwrap();
    assert!(config.webhooks.enabled);
    assert_eq!(config.webhooks.urls.len(), 1);
}

#[test]
fn test_config_without_webhooks_section() {
    let toml_str = r#"
[general]
bind_addr = "127.0.0.1:9847"
log_level = "info"
state_dir = "/tmp/irongate_test"
snapshot_interval_secs = 30

[logs]
watch_files = ["/tmp/test.log"]

[detection]
window_seconds = 300
bucket_seconds = 10
block_threshold = 50
ban_escalation = [600]
strike_memory_hours = 24

[detection.rules]
ajax_flood = { enabled = true, threshold_ratio = 10.0, min_requests = 200, score = 40 }

[enforcer]
htaccess_path = "/tmp/test_htaccess"
mode = "header"
header_name = "X-Forwarded-For"
cleanup_interval_secs = 60
flush_interval_secs = 10
dry_run = true
max_rules = 500
max_consecutive_failures = 3
backup_before_write = true
backup_dir = "/tmp/test_backups"
backup_retention = 100

[enforcer.graceful_restart]
enabled = false
cmd = "echo test"
min_interval_secs = 30
max_pending_secs = 60
max_per_hour = 20

[whitelist]
ips = []
server_ips = ["127.0.0.1"]
user_agents = []
search_engines = []

[known_bots]
user_agents = ["zgrab"]
"#;

    // Should work without [webhooks] section (defaults)
    let config: irongate::config::AppConfig = toml::from_str(toml_str).unwrap();
    assert!(!config.webhooks.enabled);
    assert!(config.webhooks.urls.is_empty());
}

// =============================================================
// Tests for multi-vhost tracking in analytics
// =============================================================

#[test]
fn test_multi_vhost_tracking() {
    use irongate::analytics::AnalyticsEngine;

    let config = make_test_config();
    let (tx, _rx) = tokio::sync::mpsc::channel(10);
    let mut engine = AnalyticsEngine::new(HashMap::new(), config, tx);

    // Entry from vhost 1
    engine.process_entry(make_entry("1.2.3.4", "arsenalcraft.com.br"));
    // Entry from vhost 2
    engine.process_entry(make_entry("5.6.7.8", "marketing.rafaelpessoap.com.br"));
    // Another entry from vhost 1, different IP
    engine.process_entry(make_entry("9.10.11.12", "arsenalcraft.com.br"));

    assert_eq!(engine.states.len(), 3);

    let ip1: IpAddr = "1.2.3.4".parse().unwrap();
    let ip2: IpAddr = "5.6.7.8".parse().unwrap();
    assert_eq!(engine.states[&ip1].vhost, "arsenalcraft.com.br");
    assert_eq!(engine.states[&ip2].vhost, "marketing.rafaelpessoap.com.br");
}

// =============================================================
// Helpers
// =============================================================

fn make_entry(ip: &str, vhost: &str) -> irongate::types::AccessLogEntry {
    irongate::types::AccessLogEntry {
        vhost: vhost.to_string(),
        client_ip: ip.parse().unwrap(),
        timestamp: chrono::Utc::now(),
        method: "GET".to_string(),
        uri: "/".to_string(),
        status: 200,
        size: 1024,
        referer: "-".to_string(),
        user_agent: "Mozilla/5.0".to_string(),
        request_type: irongate::types::RequestType::Page,
    }
}

fn make_test_config() -> irongate::config::AppConfig {
    let toml_str = r#"
[general]
bind_addr = "127.0.0.1:9847"
log_level = "info"
state_dir = "/tmp/irongate_test"
snapshot_interval_secs = 30

[logs]
watch_files = ["/tmp/test.log"]

[detection]
window_seconds = 300
bucket_seconds = 10
block_threshold = 50
ban_escalation = [600]
strike_memory_hours = 24

[detection.rules]
ajax_flood = { enabled = true, threshold_ratio = 10.0, min_requests = 200, score = 40 }

[enforcer]
htaccess_path = "/tmp/test_htaccess"
mode = "header"
header_name = "X-Forwarded-For"
cleanup_interval_secs = 60
flush_interval_secs = 10
dry_run = true
max_rules = 500
max_consecutive_failures = 3
backup_before_write = true
backup_dir = "/tmp/test_backups"
backup_retention = 100

[enforcer.graceful_restart]
enabled = false
cmd = "echo test"
min_interval_secs = 30
max_pending_secs = 60
max_per_hour = 20

[whitelist]
ips = []
server_ips = ["127.0.0.1"]
user_agents = []
search_engines = []

[known_bots]
user_agents = ["zgrab"]
"#;
    toml::from_str(toml_str).unwrap()
}
