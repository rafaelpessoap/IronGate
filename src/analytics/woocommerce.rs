use crate::analytics::ip_tracker::IpState;
use crate::types::{AccessLogEntry, RequestType};

/// Processador de regras específicas para eventos de E-commerce (WooCommerce)
pub fn process_woo_events(state: &mut IpState, entry: &AccessLogEntry) {
    match entry.request_type {
        RequestType::Cart => {
            // Conta requisições ao carrinho (GET, POST, etc.)
            *state.custom_counters.entry("cart_abuse".to_string()).or_insert(0) += 1;
        }
        RequestType::Checkout => {
            // Acompanha tentativas de checkout (Geralmente POST envia pedidos)
            if entry.method == "POST" {
                *state.custom_counters.entry("checkout_attempts".to_string()).or_insert(0) += 1;
            }
        }
        _ => {}
    }
}
