use chrono::Utc;
use irongate::analytics::ip_tracker::{IpState, SlidingWindow};
use irongate::analytics::rules::evaluate_rules;
use irongate::config::{DetectionRules, RuleConfig};
use std::net::IpAddr;
use std::str::FromStr;

/// Cria as regras padrão do config.toml para usar nos testes
fn default_rules() -> DetectionRules {
    DetectionRules {
        ajax_flood: RuleConfig {
            enabled: true,
            threshold_ratio: Some(10.0),
            min_requests: Some(200),
            threshold: None,
            score: 50,
        },
        page_flood: Some(RuleConfig {
            enabled: true,
            threshold_ratio: None,
            min_requests: None,
            threshold: Some(300),
            score: 50,
        }),
        login_brute: Some(RuleConfig {
            enabled: true,
            threshold_ratio: None,
            min_requests: None,
            threshold: Some(10),
            score: 50,
        }),
        cart_abuse: Some(RuleConfig {
            enabled: true,
            threshold_ratio: None,
            min_requests: None,
            threshold: Some(50),
            score: 50,
        }),
        checkout_spam: Some(RuleConfig {
            enabled: true,
            threshold_ratio: None,
            min_requests: None,
            threshold: Some(20),
            score: 60,
        }),
        scan_404: Some(RuleConfig {
            enabled: true,
            threshold_ratio: None,
            min_requests: None,
            threshold: Some(50),
            score: 50,
        }),
        api_abuse: Some(RuleConfig {
            enabled: true,
            threshold_ratio: None,
            min_requests: None,
            threshold: Some(100),
            score: 50,
        }),
        empty_ua: Some(RuleConfig {
            enabled: true,
            threshold_ratio: None,
            min_requests: None,
            threshold: None,
            score: 15,
        }),
        static_flood: Some(RuleConfig {
            enabled: true,
            threshold_ratio: None,
            min_requests: None,
            threshold: Some(1000),
            score: 50,
        }),
    }
}

fn make_state() -> IpState {
    IpState::new(
        IpAddr::from_str("1.2.3.4").unwrap(),
        "example.com".to_string(),
        "Mozilla/5.0".to_string(),
        60,
    )
}

// ─── REGRA 1: AJAX FLOOD ──────────────────────────────────────────

#[test]
fn test_rule_ajax_flood_triggers() {
    let rules = default_rules();
    let mut state = make_state();
    let now = Utc::now();
    // min_requests=200, ratio > 10. Enviar 201+ ajax e 1 page
    for _ in 0..210 {
        state.ajax_window.add_request(now);
        state.window.add_request(now);
    }
    // 1 page request → ratio 210/1 = 210 > 10 ✓, total 210 > 200 ✓
    state.page_window.add_request(now);
    state.window.add_request(now);
    assert!(
        evaluate_rules(&mut state, &rules),
        "Ajax flood deveria disparar"
    );
    assert!(state.threat_score >= 40.0);
}

#[test]
fn test_rule_ajax_flood_does_not_trigger_low_count() {
    let rules = default_rules();
    let mut state = make_state();
    let now = Utc::now();
    for _ in 0..10 {
        state.ajax_window.add_request(now);
        state.window.add_request(now);
    }
    state.page_window.add_request(now);
    assert!(!evaluate_rules(&mut state, &rules));
}

// ─── REGRA 2: LOGIN BRUTE FORCE (config threshold=10) ───────────

#[test]
fn test_rule_login_brute_triggers() {
    let rules = default_rules();
    let mut state = make_state();
    state
        .custom_counters
        .insert("login_attempts".to_string(), 11);
    assert!(evaluate_rules(&mut state, &rules));
    assert!(state.threat_score >= 50.0);
}

#[test]
fn test_rule_login_brute_below_threshold() {
    let rules = default_rules();
    let mut state = make_state();
    state
        .custom_counters
        .insert("login_attempts".to_string(), 5);
    assert!(!evaluate_rules(&mut state, &rules));
}

// ─── REGRA 3: SCAN 404 (config threshold=50) ────────────────────

#[test]
fn test_rule_scan_404_triggers() {
    let rules = default_rules();
    let mut state = make_state();
    // scan_404 threshold=50, precisa >50
    state.custom_counters.insert("404_errors".to_string(), 55);
    assert!(evaluate_rules(&mut state, &rules));
}

#[test]
fn test_rule_scan_404_below_threshold() {
    let rules = default_rules();
    let mut state = make_state();
    // Abaixo do threshold de 50
    state.custom_counters.insert("404_errors".to_string(), 49);
    assert!(!evaluate_rules(&mut state, &rules));
}

// ─── REGRA 4: CART ABUSE (config threshold=50) ──────────────────

#[test]
fn test_rule_cart_abuse_triggers() {
    let rules = default_rules();
    let mut state = make_state();
    // cart_abuse threshold=50, precisa >50
    state.custom_counters.insert("cart_abuse".to_string(), 55);
    assert!(evaluate_rules(&mut state, &rules));
}

// ─── REGRA 5: CHECKOUT SPAM (config threshold=20) ───────────────

#[test]
fn test_rule_checkout_spam_triggers() {
    let rules = default_rules();
    let mut state = make_state();
    // checkout_spam threshold=20, precisa >20
    state
        .custom_counters
        .insert("checkout_attempts".to_string(), 25);
    assert!(evaluate_rules(&mut state, &rules));
}

// ─── REGRA 6: EMPTY UA (score=15, abaixo de 50 sozinho) ────────

#[test]
fn test_rule_empty_ua_adds_score_but_does_not_ban_alone() {
    let rules = default_rules();
    let mut state = make_state();
    state.user_agent = "   ".to_string();
    assert!(
        !evaluate_rules(&mut state, &rules),
        "UA vazio sozinho dá 15, não basta pra 50"
    );
    assert!(state.threat_score >= 15.0);
}

// ─── REGRA 7: PAGE FLOOD (config threshold=300) ─────────────────

#[test]
fn test_rule_page_flood_triggers() {
    let rules = default_rules();
    let mut state = make_state();
    let now = Utc::now();
    // page_flood threshold=300, precisa >300
    for _ in 0..310 {
        state.window.add_request(now);
    }
    assert!(evaluate_rules(&mut state, &rules));
    assert!(state.threat_score >= 35.0);
}

// ─── WHITELIST E BAN BYPASS ─────────────────────────────────────

#[test]
fn test_whitelisted_ip_never_triggers() {
    let rules = default_rules();
    let mut state = make_state();
    state.is_whitelisted = true;
    state
        .custom_counters
        .insert("login_attempts".to_string(), 100);
    let now = Utc::now();
    for _ in 0..500 {
        state.window.add_request(now);
    }
    assert!(!evaluate_rules(&mut state, &rules));
}

#[test]
fn test_already_banned_ip_skips() {
    let rules = default_rules();
    let mut state = make_state();
    state.ban_until = Some(Utc::now() + chrono::Duration::hours(1));
    state
        .custom_counters
        .insert("login_attempts".to_string(), 100);
    assert!(!evaluate_rules(&mut state, &rules));
}

// ─── SLIDING WINDOW ─────────────────────────────────────────────

#[test]
fn test_sliding_window_cleanup() {
    let mut window = SlidingWindow::new(10);
    let now = Utc::now();
    let old = now - chrono::Duration::seconds(20);
    window.add_request(old);
    window.add_request(now);
    assert_eq!(window.count(), 1);
}

// ─── STRIKE ESCALATION ──────────────────────────────────────────

#[test]
fn test_strikes_accumulate() {
    let rules = default_rules();
    let mut state = make_state();
    let now = Utc::now();
    // page_flood threshold=300, precisa >300
    for _ in 0..310 {
        state.window.add_request(now);
    }
    assert!(evaluate_rules(&mut state, &rules));
    state.ban_until = Some(Utc::now() + chrono::Duration::hours(1));
    state.threat_score = 0.0;
    assert!(!evaluate_rules(&mut state, &rules));
    assert_eq!(state.threat_score, 0.0);
}

// ─── REGRAS DESABILITADAS ───────────────────────────────────────

#[test]
fn test_disabled_rule_does_not_trigger() {
    let mut rules = default_rules();
    rules.login_brute = Some(RuleConfig {
        enabled: false,
        threshold_ratio: None,
        min_requests: None,
        threshold: Some(10),
        score: 50,
    });
    let mut state = make_state();
    state
        .custom_counters
        .insert("login_attempts".to_string(), 100);
    assert!(
        !evaluate_rules(&mut state, &rules),
        "Regra desabilitada não deve disparar"
    );
}
