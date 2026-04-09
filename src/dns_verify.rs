use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use tracing::{info, warn, debug};

/// Cache entry for DNS verification results
#[derive(Clone, Debug)]
struct DnsResult {
    is_legitimate: bool,
    resolved_hostname: Option<String>,
    cached_at: Instant,
}

/// Validates search engine bots via forward-confirmed reverse DNS (FCrDNS).
/// Process: IP -> reverse DNS -> hostname -> forward DNS -> check if IP matches
pub struct DnsVerifier {
    /// Map of domain suffixes to bot names that are legitimate
    legitimate_domains: Vec<(String, String)>,
    /// Cache of resolved results (IP -> result)
    cache: Arc<RwLock<HashMap<IpAddr, DnsResult>>>,
    /// How long cached results stay valid
    cache_ttl: Duration,
}

impl DnsVerifier {
    pub fn new(search_engine_domains: &[String]) -> Self {
        let mut legitimate_domains = Vec::new();

        // Default known legitimate bot domains
        let defaults = vec![
            ("googlebot.com", "Googlebot"),
            ("google.com", "Google"),
            ("search.msn.com", "Bingbot"),
            ("applebot.apple.com", "Applebot"),
            ("crawl.yahoo.net", "Yahoo Slurp"),
            ("yandex.ru", "YandexBot"),
            ("yandex.net", "YandexBot"),
            ("yandex.com", "YandexBot"),
        ];

        for (domain, name) in defaults {
            legitimate_domains.push((domain.to_string(), name.to_string()));
        }

        // Add user-configured domains
        for domain in search_engine_domains {
            if !legitimate_domains.iter().any(|(d, _)| d == domain) {
                legitimate_domains.push((domain.clone(), domain.clone()));
            }
        }

        Self {
            legitimate_domains,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(3600), // 1 hour cache
        }
    }

    /// Check if an IP belongs to a legitimate search engine bot.
    /// Returns Some(bot_name) if verified, None otherwise.
    #[cfg(feature = "dns-verify")]
    pub async fn verify_bot(&self, ip: IpAddr) -> Option<String> {
        // Check cache first
        {
            let cache = self.cache.read();
            if let Some(result) = cache.get(&ip) {
                if result.cached_at.elapsed() < self.cache_ttl {
                    debug!("DNS cache hit para {}: legit={}", ip, result.is_legitimate);
                    return if result.is_legitimate {
                        result.resolved_hostname.clone()
                    } else {
                        None
                    };
                }
            }
        }

        let result = self.do_fcrdns_lookup(ip).await;

        // Cache the result
        {
            let mut cache = self.cache.write();
            cache.insert(ip, result.clone());
        }

        if result.is_legitimate {
            info!("Bot verificado via DNS reverso: {} -> {:?}", ip, result.resolved_hostname);
            result.resolved_hostname
        } else {
            None
        }
    }

    #[cfg(not(feature = "dns-verify"))]
    pub async fn verify_bot(&self, _ip: IpAddr) -> Option<String> {
        None
    }

    #[cfg(feature = "dns-verify")]
    async fn do_fcrdns_lookup(&self, ip: IpAddr) -> DnsResult {
        use hickory_resolver::TokioAsyncResolver;
        use hickory_resolver::config::*;

        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        // Step 1: Reverse DNS (IP -> hostname)
        let hostname = match resolver.reverse_lookup(ip).await {
            Ok(lookup) => {
                let names: Vec<String> = lookup.iter()
                    .map(|name| name.to_string().trim_end_matches('.').to_string())
                    .collect();
                if let Some(h) = names.into_iter().next() {
                    debug!("Reverse DNS: {} -> {}", ip, h);
                    h
                } else {
                    return DnsResult {
                        is_legitimate: false,
                        resolved_hostname: None,
                        cached_at: Instant::now(),
                    };
                }
            }
            Err(_) => {
                return DnsResult {
                    is_legitimate: false,
                    resolved_hostname: None,
                    cached_at: Instant::now(),
                };
            }
        };

        // Step 2: Check if hostname matches a legitimate domain
        let matched_bot = self.legitimate_domains.iter()
            .find(|(domain, _)| hostname.ends_with(domain));

        if matched_bot.is_none() {
            return DnsResult {
                is_legitimate: false,
                resolved_hostname: Some(hostname),
                cached_at: Instant::now(),
            };
        }

        // Step 3: Forward DNS (hostname -> IPs) to confirm
        match resolver.lookup_ip(&hostname).await {
            Ok(lookup) => {
                let resolved_ips: Vec<IpAddr> = lookup.iter().collect();
                let matches = resolved_ips.iter().any(|&resolved_ip| resolved_ip == ip);
                if matches {
                    DnsResult {
                        is_legitimate: true,
                        resolved_hostname: Some(hostname),
                        cached_at: Instant::now(),
                    }
                } else {
                    warn!("FCrDNS falhou para {}: reverse={} mas forward nao bate", ip, hostname);
                    DnsResult {
                        is_legitimate: false,
                        resolved_hostname: Some(hostname),
                        cached_at: Instant::now(),
                    }
                }
            }
            Err(_) => DnsResult {
                is_legitimate: false,
                resolved_hostname: Some(hostname),
                cached_at: Instant::now(),
            },
        }
    }

    /// Cleanup expired cache entries
    pub fn cleanup_cache(&self) {
        let mut cache = self.cache.write();
        cache.retain(|_, result| result.cached_at.elapsed() < self.cache_ttl);
    }
}
