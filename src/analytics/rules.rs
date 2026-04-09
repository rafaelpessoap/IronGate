use crate::analytics::ip_tracker::IpState;
use crate::config::DetectionRules;
use tracing::warn;

/// Avalia regras usando thresholds do config.toml
pub fn evaluate_rules(state: &mut IpState, rules: &DetectionRules) -> bool {
    if state.is_whitelisted || state.ban_until.is_some() {
        return false;
    }

    let mut score: f32 = 0.0;
    let ajax_count = state.ajax_window.count();
    let page_count = state.page_window.count().max(1);
    let total = state.window.count();

    // 1. AJAX Flood (config-driven)
    if rules.ajax_flood.enabled {
        let ratio = rules.ajax_flood.threshold_ratio.unwrap_or(10.0);
        let min_req = rules.ajax_flood.min_requests.unwrap_or(200) as usize;
        if (ajax_count as f32 / page_count as f32) >= ratio && total >= min_req {
            warn!("[REGRA] AJAX Flood detectado. (IP: {})", state.ip);
            score += rules.ajax_flood.score as f32;
        }
    }

    // 2. Page Flood
    if let Some(ref rule) = rules.page_flood {
        if rule.enabled {
            let threshold = rule.threshold.unwrap_or(300) as usize;
            if total >= threshold {
                warn!("[REGRA] Page Flood detectado. (IP: {})", state.ip);
                score += rule.score as f32;
            }
        }
    }

    // 3. Login Brute Force
    if let Some(ref rule) = rules.login_brute {
        if rule.enabled {
            let threshold = rule.threshold.unwrap_or(10) as u32;
            if let Some(&attempts) = state.custom_counters.get("login_attempts") {
                if attempts >= threshold {
                    warn!("[REGRA] Login Brute Force detectado. (IP: {})", state.ip);
                    score += rule.score as f32;
                }
            }
        }
    }

    // 4. Cart Abuse
    if let Some(ref rule) = rules.cart_abuse {
        if rule.enabled {
            let threshold = rule.threshold.unwrap_or(50) as u32;
            if let Some(&count) = state.custom_counters.get("cart_abuse") {
                if count >= threshold {
                    warn!("[REGRA] Cart Spam detectado. (IP: {})", state.ip);
                    score += rule.score as f32;
                }
            }
        }
    }

    // 5. Checkout Spam
    if let Some(ref rule) = rules.checkout_spam {
        if rule.enabled {
            let threshold = rule.threshold.unwrap_or(20) as u32;
            if let Some(&count) = state.custom_counters.get("checkout_attempts") {
                if count >= threshold {
                    warn!("[REGRA] Checkout Spam detectado. (IP: {})", state.ip);
                    score += rule.score as f32;
                }
            }
        }
    }

    // 6. Scan 404
    if let Some(ref rule) = rules.scan_404 {
        if rule.enabled {
            let threshold = rule.threshold.unwrap_or(50) as u32;
            if let Some(&count) = state.custom_counters.get("404_errors") {
                if count >= threshold {
                    warn!("[REGRA] 404 Scanner detectado. (IP: {})", state.ip);
                    score += rule.score as f32;
                }
            }
        }
    }

    // 7. API Abuse
    if let Some(ref rule) = rules.api_abuse {
        if rule.enabled {
            let threshold = rule.threshold.unwrap_or(100) as u32;
            if let Some(&count) = state.custom_counters.get("api_requests") {
                if count >= threshold {
                    warn!("[REGRA] API Abuse detectado. (IP: {})", state.ip);
                    score += rule.score as f32;
                }
            }
        }
    }

    // 8. Empty User Agent
    if let Some(ref rule) = rules.empty_ua {
        if rule.enabled && state.user_agent.trim().is_empty() {
            score += rule.score as f32;
        }
    }

    // 9. Static Flood
    if let Some(ref rule) = rules.static_flood {
        if rule.enabled {
            let threshold = rule.threshold.unwrap_or(1000) as u32;
            if let Some(&count) = state.custom_counters.get("static_requests") {
                if count >= threshold {
                    warn!("[REGRA] Static Flood detectado. (IP: {})", state.ip);
                    score += rule.score as f32;
                }
            }
        }
    }

    state.threat_score = score;
    state.threat_score >= 50.0
}
