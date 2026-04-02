use irongate::analytics::ip_tracker::{IpState, SlidingWindow};
use irongate::analytics::rules::evaluate_rules;
use chrono::Utc;
use std::net::IpAddr;
use std::str::FromStr;

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
    let mut state = make_state();
    let now = Utc::now();

    // 151+ requests na janela com ratio alto de ajax
    for _ in 0..200 {
        state.ajax_window.add_request(now);
        state.window.add_request(now);
    }
    // Apenas 1 page request → ratio altíssimo
    state.page_window.add_request(now);

    assert!(evaluate_rules(&mut state), "Ajax flood deveria disparar");
    assert!(state.threat_score >= 50.0);
}

#[test]
fn test_rule_ajax_flood_does_not_trigger_low_count() {
    let mut state = make_state();
    let now = Utc::now();

    for _ in 0..10 {
        state.ajax_window.add_request(now);
        state.window.add_request(now);
    }
    state.page_window.add_request(now);

    assert!(!evaluate_rules(&mut state), "Poucos requests não devem disparar ajax flood");
}

// ─── REGRA 2: LOGIN BRUTE FORCE ─────────────────────────────────

#[test]
fn test_rule_login_brute_triggers() {
    let mut state = make_state();
    state.custom_counters.insert("login_attempts".to_string(), 6);

    assert!(evaluate_rules(&mut state), "Login brute force deveria disparar com 6 tentativas");
    assert!(state.threat_score >= 100.0);
}

#[test]
fn test_rule_login_brute_below_threshold() {
    let mut state = make_state();
    state.custom_counters.insert("login_attempts".to_string(), 3);

    assert!(!evaluate_rules(&mut state), "3 tentativas de login não devem disparar");
}

// ─── REGRA 3: SCAN 404 ─────────────────────────────────────────

#[test]
fn test_rule_scan_404_triggers() {
    let mut state = make_state();
    state.custom_counters.insert("404_errors".to_string(), 20);

    assert!(evaluate_rules(&mut state), "Scanner 404 deveria disparar com 20 erros");
}

#[test]
fn test_rule_scan_404_below_threshold() {
    let mut state = make_state();
    state.custom_counters.insert("404_errors".to_string(), 5);

    assert!(!evaluate_rules(&mut state), "5 erros 404 não devem disparar");
}

// ─── REGRA 4: CART ABUSE ────────────────────────────────────────

#[test]
fn test_rule_cart_abuse_triggers() {
    let mut state = make_state();
    state.custom_counters.insert("cart_abuse".to_string(), 15);

    assert!(evaluate_rules(&mut state), "Cart abuse deveria disparar com 15 adições");
}

// ─── REGRA 5: CHECKOUT SPAM ────────────────────────────────────

#[test]
fn test_rule_checkout_spam_triggers() {
    let mut state = make_state();
    state.custom_counters.insert("checkout_attempts".to_string(), 5);

    assert!(evaluate_rules(&mut state), "Checkout spam deveria disparar com 5 tentativas");
}

// ─── REGRA 6: EMPTY USER AGENT ──────────────────────────────────

#[test]
fn test_rule_empty_ua_adds_score() {
    let mut state = make_state();
    state.user_agent = "   ".to_string(); // UA vazio

    // Sozinho não basta pra ban (score = 30), mas deve acumular
    evaluate_rules(&mut state);
    assert!(state.threat_score >= 30.0, "UA vazio deve pontuar pelo menos 30");
}

// ─── REGRA 7: PAGE FLOOD (DDoS Layer 7) ─────────────────────────

#[test]
fn test_rule_page_flood_triggers() {
    let mut state = make_state();
    let now = Utc::now();

    for _ in 0..250 {
        state.window.add_request(now);
    }

    assert!(evaluate_rules(&mut state), "Page flood deveria disparar com 250 requests");
    assert!(state.threat_score >= 80.0);
}

// ─── WHITELIST E BAN BYPASS ─────────────────────────────────────

#[test]
fn test_whitelisted_ip_never_triggers() {
    let mut state = make_state();
    state.is_whitelisted = true;
    state.custom_counters.insert("login_attempts".to_string(), 100);

    let now = Utc::now();
    for _ in 0..500 {
        state.window.add_request(now);
    }

    assert!(!evaluate_rules(&mut state), "IP whitelistado NUNCA deve ser bloqueado");
}

#[test]
fn test_already_banned_ip_skips() {
    let mut state = make_state();
    state.ban_until = Some(Utc::now() + chrono::Duration::hours(1));
    state.custom_counters.insert("login_attempts".to_string(), 100);

    assert!(!evaluate_rules(&mut state), "IP já banido não deve reprocessar regras");
}

// ─── SLIDING WINDOW ─────────────────────────────────────────────

#[test]
fn test_sliding_window_cleanup() {
    let mut window = SlidingWindow::new(10); // 10 segundos
    let now = Utc::now();
    let old = now - chrono::Duration::seconds(20);

    window.add_request(old);
    window.add_request(now);

    // A limpeza interna em add_request remove o timestamp antigo
    assert_eq!(window.count(), 1, "Request antigo deveria ter sido limpo");
}

// ─── STRIKE ESCALATION ──────────────────────────────────────────

#[test]
fn test_strikes_accumulate() {
    let mut state = make_state();
    let now = Utc::now();

    // Dispara page flood
    for _ in 0..250 {
        state.window.add_request(now);
    }

    // Primeira avaliação: should trigger
    assert!(evaluate_rules(&mut state));

    // Simula o que o AnalyticsEngine faria: setar ban_until
    state.ban_until = Some(Utc::now() + chrono::Duration::hours(1));

    // Reset score para testar que evaluate_rules nem roda
    state.threat_score = 0.0;
    assert!(!evaluate_rules(&mut state), "Com ban ativo, não deve re-avaliar");
    assert_eq!(state.threat_score, 0.0, "Score não deve mudar quando já banido");
}
