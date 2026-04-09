# IronGate

**Sistema de Monitoramento e Protecao em Tempo Real para OpenLiteSpeed**

Daemon unico em Rust que monitora logs do OLS em tempo real, detecta bots e ataques via analise comportamental, e bloqueia automaticamente via regras no `.htaccess`. Serve um dashboard web via WebSocket para monitoramento ao vivo.

---

## O Que Resolve

O sistema anterior (block_bots.php + APCu) so enxergava requests PHP, perdia dados no restart do LiteSpeed, nao tinha persistencia, e adicionava overhead a cada request.

O IronGate opera **fora do nivel aplicacional**:
- Analisa 100% do trafego via logs puros `access.log` usando inotify/linemux
- Zero overhead para visitantes (background daemon)
- Bloqueio a nivel de `.htaccess` (antes do PHP processar)
- Pegada de memoria minima (~5-15MB para 10.000 IPs)
- Binario unico, zero dependencias em runtime

## Arquitetura

```
OLS Access Logs
      |
  LOG INGESTOR (linemux, multi-vhost)
      |
  ANALYTICS ENGINE (9 regras, scores por IP)
      |
  +-----------+-----------+-----------+
  |           |           |           |
ENFORCER   DASHBOARD   PERSISTENCE  NOTIFICATIONS
(htaccess)  (axum+WS)  (JSON/disk)  (webhooks)
```

### Modulos

| Modulo | Funcao |
|--------|--------|
| `log_ingestor` | Tail assincrono com linemux + regex parser OLS. Suporte multi-vhost. |
| `analytics` | Engine por IP com sliding windows, 9 regras de deteccao config-driven, deteccao WooCommerce. |
| `enforcer` | Escrita atomica no `.htaccess` com SHA-256, backup, emergency mode. Graceful restart OLS com rate limiting. |
| `dashboard` | Axum SPA com WebSocket broadcast, glassmorphism UI, REST API completa. |
| `persistence` | Snapshots de estado em JSON com escrita atomica. |
| `notifications` | Webhooks para Discord/Telegram (emergencia, DDoS, falhas). |
| `dns_verify` | Validacao FCrDNS de bots legitimos (Googlebot, Bingbot, etc.) com cache. |
| `stats` | Estatisticas diarias em `stats/YYYY-MM-DD.json`. |

## Regras de Deteccao

| Regra | Condicao | Score |
|-------|----------|-------|
| ajax_flood | ajax/page > 10 E total > 200 | +40 |
| page_flood | pages > 300/5min | +35 |
| login_brute | login > 10/5min | +50 |
| cart_abuse | cart > 50/5min | +45 |
| checkout_spam | checkout > 20/5min | +60 |
| scan_404 | 4xx > 50/5min | +30 |
| api_abuse | api > 100/5min | +35 |
| empty_ua | UA vazio | +15 |
| static_flood | static > 1000/5min | +20 |

Threshold de bloqueio: 50 pontos. Escalacao de bans: 10min, 30min, 1h, 3h, 6h, 24h.

## Seguranca do .htaccess

O `.htaccess` e o arquivo mais critico do servidor. O IronGate gerencia **exclusivamente** o bloco entre `# BEGIN IronGate` e `# END IronGate`. Tudo fora desse bloco e intocavel.

- Escrita atomica via temp file + `fsync()` + `rename()`
- Validacao SHA-256 do conteudo externo antes e depois de cada escrita
- Backup automatico antes de cada modificacao (ultimos 100)
- Emergency mode apos 3 falhas consecutivas (para todas as escritas)
- Deteccao de modificacao externa (admin editou manualmente)

## Uso

### Compilacao

```bash
cargo build --release
```

### Executar o daemon

```bash
# Com config padrao (config.toml)
irongate run

# Com config customizado
irongate --config /etc/irongate/config.toml run
```

### CLI

```bash
irongate status                    # Status do daemon (via API)
irongate ban 1.2.3.4               # Banir IP (24h padrao)
irongate ban 1.2.3.4 -d 3600      # Banir IP por 1h
irongate unblock 1.2.3.4           # Desbloquear IP
irongate whitelist 1.2.3.4         # Whitelist permanente
irongate restore --latest          # Restaurar ultimo backup do .htaccess
irongate reset-emergency           # Resetar modo emergencia
```

### Hot-reload de configuracao

```bash
kill -HUP $(pidof irongate)        # Recarrega config.toml sem reiniciar
```

### Deploy com systemd

```ini
[Unit]
Description=IronGate - Bot Protection Daemon
After=lsws.service network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/irongate --config /etc/irongate/config.toml run
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

## Dashboard

Acessivel via VPN em `http://10.8.0.1:9847/`

### Endpoints da API

| Metodo | Path | Funcao |
|--------|------|--------|
| GET | `/` | Dashboard SPA |
| GET | `/ws` | WebSocket tempo real |
| GET | `/api/status` | Estado geral (requests, IPs, bans) |
| GET | `/api/ips` | IPs ativos com score, vhost, UA |
| GET | `/api/guard-status` | Status do HtaccessGuard |
| GET | `/api/stats` | Estatisticas do dia |
| POST | `/api/block` | Banir IP manualmente |
| POST | `/api/unblock` | Desbloquear IP |
| POST | `/api/whitelist` | Whitelist permanente |

## Configuracao

Toda configuracao fica em `config.toml`:

- **`[general]`** — bind_addr, log_level, state_dir, snapshot_interval
- **`[logs]`** — watch_files (multiplos logs para multi-vhost)
- **`[detection]`** — janela, threshold, escalacao de bans
- **`[detection.rules]`** — 9 regras com thresholds e scores individuais
- **`[enforcer]`** — htaccess_path, dry_run, max_rules, flush_interval, backup
- **`[enforcer.graceful_restart]`** — cmd, min_interval, max_per_hour
- **`[whitelist]`** — IPs, server_ips, user_agents, search_engines
- **`[known_bots]`** — user_agents de bots conhecidos
- **`[webhooks]`** — urls para Discord/Telegram

## Testes

```bash
cargo test
```

56 testes cobrindo:
- Seguranca do `.htaccess` (preservacao byte-a-byte, atomicidade, emergency mode)
- Todas as 9 regras de deteccao
- Enforcer (batching, dry-run, whitelist, backup/restore)
- Parser de logs OLS
- CLI, stats, webhooks, DNS reverso, config, multi-vhost

## Dependencias

| Crate | Funcao |
|-------|--------|
| tokio | Runtime async |
| linemux | Tail em tempo real (inotify) |
| axum | HTTP + WebSocket |
| sha2 | SHA-256 para validacao .htaccess |
| chrono | Timestamps |
| regex | Parsing de logs |
| clap | CLI |
| serde/toml | Config e serializacao |
| parking_lot | RwLock de alta performance |
| reqwest | Webhooks HTTP (opcional) |
| trust-dns-resolver | Validacao DNS reverso (opcional) |
