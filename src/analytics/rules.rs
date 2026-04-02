use crate::analytics::ip_tracker::IpState;
use crate::config::DetectionRules;

pub fn evaluate_rules(state: &mut IpState, rules_config: &DetectionRules) -> bool {
    if state.is_whitelisted || state.ban_until.is_some() {
        return false;
    }

    let mut score = 0.0;

    if rules_config.ajax_flood.enabled {
        let ajax_count = state.ajax_window.count();
        let page_count = state.page_window.count().max(1);
        let total = state.window.count();

        if (ajax_count as f32 / page_count as f32) > rules_config.ajax_flood.threshold_ratio.unwrap_or(10.0) 
            && (total as u64) > rules_config.ajax_flood.min_requests.unwrap_or(200) {
            score += rules_config.ajax_flood.score as f32;
        }
    }

    state.threat_score = score;

    if state.threat_score >= 50.0 {
        return true;
    }

    false
}
