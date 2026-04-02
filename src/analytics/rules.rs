use crate::analytics::ip_tracker::IpState;
use tracing::warn;

pub fn evaluate_rules(state: &mut IpState) -> bool {
    if state.is_whitelisted || state.ban_until.is_some() {
        return false;
    }

    let mut score = 0.0;
    
    // 1. AJAX/Flood
    let ajax_count = state.ajax_window.count();
    let page_count = state.page_window.count().max(1);
    let total = state.window.count();

    if (ajax_count as f32 / page_count as f32) > 10.0 && total > 150 {
        warn!("[REGRA] AJAX Flood detectado. (IP: {})", state.ip);
        score += 50.0;
    }

    // 2. Login Brute Force
    if let Some(&login_attempts) = state.custom_counters.get("login_attempts") {
        if login_attempts > 5 {
            warn!("[REGRA] Login Brute Force detectado. (IP: {})", state.ip);
            score += 100.0; // Block immediato
        }
    }

    // 3. Scan 404 (Procurando brechas)
    if let Some(&err_404) = state.custom_counters.get("404_errors") {
        if err_404 > 15 {
            warn!("[REGRA] 404 Scanner detectado. (IP: {})", state.ip);
            score += 50.0;
        }
    }

    // 4. Cart Abuse
    if let Some(&cart) = state.custom_counters.get("cart_abuse") {
        if cart > 10 {
            warn!("[REGRA] Cart Spam detectado. (IP: {})", state.ip);
            score += 50.0;
        }
    }

    // 5. Checkout Spam
    if let Some(&checkout) = state.custom_counters.get("checkout_attempts") {
        if checkout > 4 {
            warn!("[REGRA] Checkout Spam detectado. (IP: {})", state.ip);
            score += 60.0;
        }
    }

    // 6. User Agent vazio ou suspeito
    if state.user_agent.trim().is_empty() {
        score += 30.0; // Pesa bastante
    }

    // 7. Page Flood Geral (DDoS)
    if total > 200 {
        warn!("[REGRA] Page Flood Geral detectado. (IP: {})", state.ip);
        score += 80.0;
    }

    state.threat_score = score;

    if state.threat_score >= 50.0 {
        return true;
    }

    false
}
