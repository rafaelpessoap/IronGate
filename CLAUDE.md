# Documento de Contexto do Projeto IronGate (Para Claude)

Este arquivo contém o mapeamento e estado atual do **IronGate** — um daemon nativo Linux em Rust que protege servidores OLS contra bots maliciosos.

## Escopo do IronGate
Substitui o antigo sistema PHP (block_bots.php/APCu). Lê logs do OpenLiteSpeed em tempo real, aplica motor analítico de scores por IP, e manipula exclusivamente o bloco isolado do `.htaccess` via escrita atômica com validação SHA-256.

## Arquitetura Atual (Fases 1-4 Completas)

### Fase 1 - Core (Concluído)
- **`src/log_ingestor/`**: Parser assíncrono via `linemux` com regex OLS. Tipagem em `AccessLogEntry`.
- **`src/analytics/`**: Motor analítico com `IpState`, `SlidingWindow`, 9 regras de detecção config-driven.
- **`src/enforcer/htaccess.rs`**: HtaccessGuard — escrita atômica, SHA-256, backup, emergency mode, bloco isolado.
- **`src/enforcer/ols_restart.rs`**: Graceful restart do OLS com rate limiting.

### Fase 2 - Dashboard Axum (Concluído)
- **`src/dashboard/`**: Axum SPA com WebSocket broadcast, glassmorphism UI.
- Endpoints: `/api/status`, `/api/ips`, `/api/guard-status`, `/api/stats`, `/api/block`, `/api/unblock`, `/api/whitelist`.
- Assets embutidos via `include_str!()`.

### Fase 3 - Regras Avançadas (Concluído)
- 9 regras: ajax_flood, page_flood, login_brute, cart_abuse, checkout_spam, scan_404, api_abuse, empty_ua, static_flood.
- **`src/analytics/woocommerce.rs`**: Detecção específica WooCommerce (cart/checkout abuse).
- **`src/persistence/`**: State.json com escrita atômica e restore.

### Fase 4 - Extras e Quality-of-Life (Concluído)
- **`src/cli.rs`**: CLI com clap — subcomandos `run`, `status`, `ban`, `unblock`, `whitelist`, `restore`, `reset-emergency`.
- **`src/notifications.rs`**: Webhooks para Discord/Telegram (alertas de emergência, DDoS, falha de restart).
- **`src/dns_verify.rs`**: Validação FCrDNS de bots de busca (Googlebot, Bingbot, etc.) com cache.
- **`src/stats.rs`**: Estatísticas diárias em `stats/YYYY-MM-DD.json` com métricas agregadas.
- **Hot-reload**: SIGHUP recarrega `config.toml` sem reiniciar o daemon.
- **Multi-vhost**: Múltiplos log ingestors, tracking por vhost no analytics e dashboard.

## Estrutura de Arquivos
```
src/
├── main.rs              # Entry point, tokio::main, integração completa
├── cli.rs               # CLI com clap (Fase 4)
├── config.rs            # Parsing config.toml
├── types.rs             # AccessLogEntry, RequestType, BlockRule
├── dns_verify.rs        # FCrDNS para bots legítimos (Fase 4)
├── notifications.rs     # Webhooks Discord/Telegram (Fase 4)
├── stats.rs             # Estatísticas diárias (Fase 4)
├── lib.rs               # Exports de módulos
├── log_ingestor/
│   ├── mod.rs           # Tail com linemux
│   └── parser.rs        # Regex parser OLS
├── analytics/
│   ├── mod.rs           # Engine de análise
│   ├── ip_tracker.rs    # IpState + SlidingWindow
│   ├── rules.rs         # 9 regras de detecção
│   └── woocommerce.rs   # Detecção WooCommerce
├── enforcer/
│   ├── mod.rs           # Enforcer com batching
│   ├── htaccess.rs      # HtaccessGuard (CRITICO)
│   └── ols_restart.rs   # OLS restart manager
├── dashboard/
│   ├── mod.rs           # Axum router + endpoints
│   ├── websocket.rs     # WebSocket broadcast
│   └── static_html.rs   # HTML/CSS/JS embutido
└── persistence/
    └── mod.rs           # Snapshots JSON
```

## Testes: 56 testes passando
- `test_analytics.rs` — 15 testes (regras de detecção)
- `test_enforcer.rs` — 15 testes (batching, preservation, backup/restore)
- `test_htaccess_guard.rs` — 4 testes (segurança do .htaccess)
- `test_parser.rs` — 2 testes (parsing de logs OLS)
- `test_phase4.rs` — 20 testes (CLI, stats, webhooks, DNS, multi-vhost, config)

## Premissas de Desenvolvimento
- **Concorrência**: Tokio channels/RwLock, nunca blocking Mutex do std em pipelines ativas.
- **Segurança .htaccess**: Escrita atômica, bloco isolado, SHA-256, emergency mode após 3 falhas.
- **Zero overhead**: Event-driven, <1% CPU, 5-15MB RAM.
