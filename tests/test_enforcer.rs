use irongate::enforcer::htaccess::HtaccessGuard;
use irongate::enforcer::Enforcer;
use irongate::config::{EnforcerConfig, GracefulRestartConfig};
use irongate::types::BlockRule;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

const FIXTURE_CONTENT: &[u8] = b"# Site rules
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>

# BEGIN IronGate - GERENCIADO AUTOMATICAMENTE - N\xC3\x83O EDITAR
# END IronGate
";

fn test_enforcer_config(htaccess_path: &str, backup_dir: &str) -> EnforcerConfig {
    EnforcerConfig {
        htaccess_path: PathBuf::from(htaccess_path),
        mode: "header".to_string(),
        header_name: "X-Forwarded-For".to_string(),
        cleanup_interval_secs: 60,
        flush_interval_secs: 0, // sem cooldown nos testes
        dry_run: false,
        max_rules: 500,
        max_consecutive_failures: 3,
        backup_before_write: true,
        backup_dir: PathBuf::from(backup_dir),
        backup_retention: 100,
        graceful_restart: GracefulRestartConfig {
            enabled: false, // não executar OLS restart nos testes
            cmd: "echo test".to_string(),
            min_interval_secs: 30,
            max_pending_secs: 60,
            max_per_hour: 20,
        },
    }
}

fn setup_enforcer(name: &str) -> (EnforcerConfig, PathBuf) {
    let test_dir = std::env::temp_dir().join(format!("irongate_enforcer_test_{}", name));
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).unwrap();
    }
    fs::create_dir_all(&test_dir).unwrap();

    let htaccess_path = test_dir.join(".htaccess");
    let backup_dir = test_dir.join("backups");
    fs::write(&htaccess_path, FIXTURE_CONTENT).unwrap();
    fs::create_dir_all(&backup_dir).unwrap();

    let config = test_enforcer_config(
        htaccess_path.to_str().unwrap(),
        backup_dir.to_str().unwrap(),
    );

    (config, test_dir)
}

// ─── BATCHING ───────────────────────────────────────────────────

#[test]
fn test_enforcer_add_ban_marks_pending() {
    let (config, _dir) = setup_enforcer("add_ban");
    let mut enforcer = Enforcer::new(&config).unwrap();

    assert!(!enforcer.pending_flush);
    enforcer.add_ban("1.1.1.1".to_string(), 3600);
    assert!(enforcer.pending_flush);
    assert_eq!(enforcer.active_bans.len(), 1);
}

#[test]
fn test_enforcer_whitelist_blocks_ban() {
    let (config, _dir) = setup_enforcer("whitelist_block");
    let mut enforcer = Enforcer::new(&config).unwrap();

    enforcer.whitelist.insert("1.1.1.1".to_string());
    enforcer.add_ban("1.1.1.1".to_string(), 3600);

    assert_eq!(enforcer.active_bans.len(), 0);
    assert!(!enforcer.pending_flush);
}

#[test]
fn test_enforcer_cleanup_removes_expired() {
    let (config, _dir) = setup_enforcer("cleanup");
    let mut enforcer = Enforcer::new(&config).unwrap();

    enforcer.add_ban("1.1.1.1".to_string(), 0);
    std::thread::sleep(std::time::Duration::from_millis(10));

    let removed = enforcer.cleanup_expired();
    assert!(removed);
    assert_eq!(enforcer.active_bans.len(), 0);
}

#[test]
fn test_enforcer_multiple_bans_batch() {
    let (config, _dir) = setup_enforcer("multi_ban");
    let mut enforcer = Enforcer::new(&config).unwrap();

    enforcer.add_ban("1.1.1.1".to_string(), 3600);
    enforcer.add_ban("2.2.2.2".to_string(), 3600);
    enforcer.add_ban("3.3.3.3".to_string(), 3600);

    assert_eq!(enforcer.active_bans.len(), 3);
}

// ─── DRY RUN ────────────────────────────────────────────────────

#[test]
fn test_enforcer_dry_run_skips_write() {
    let (mut config, _dir) = setup_enforcer("dry_run");
    config.dry_run = true;
    let mut enforcer = Enforcer::new(&config).unwrap();

    enforcer.add_ban("1.1.1.1".to_string(), 3600);
    let result = enforcer.flush_batch();
    assert!(result.is_ok());
    // Em dry_run, pending_flush é resetado mas o htaccess NÃO é escrito
    assert!(!enforcer.pending_flush);
    assert_eq!(enforcer.guard.total_writes, 0);
}

// ─── HTACCESS GUARD: IPv6 ───────────────────────────────────────

#[test]
fn test_htaccess_ipv6_write() {
    let test_dir = std::env::temp_dir().join("irongate_test_ipv6_v2");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).unwrap();
    }
    fs::create_dir_all(&test_dir).unwrap();

    let htaccess_path = test_dir.join(".htaccess");
    let backup_dir = test_dir.join("backups");
    fs::write(&htaccess_path, FIXTURE_CONTENT).unwrap();
    fs::create_dir_all(&backup_dir).unwrap();

    let mut guard = HtaccessGuard::new(htaccess_path.clone(), backup_dir, 500).unwrap();

    let rules = vec![BlockRule {
        ip: IpAddr::from_str("2001:db8::1").unwrap(),
        reason: "test_ipv6".to_string(),
    }];

    let res = guard.write_rules(&rules);
    assert!(res.is_ok());

    let content = fs::read_to_string(&htaccess_path).unwrap();
    assert!(content.contains("2001\\:db8\\:\\:1"), "IPv6 deve ter : escapados");
}

// ─── HTACCESS GUARD: BACKUP / RESTORE ───────────────────────────

#[test]
fn test_restore_latest_fails_empty_backups() {
    let test_dir = std::env::temp_dir().join("irongate_test_restore_empty_v2");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).unwrap();
    }
    fs::create_dir_all(&test_dir).unwrap();

    let htaccess_path = test_dir.join(".htaccess");
    let backup_dir = test_dir.join("empty_backups");
    fs::write(&htaccess_path, b"empty").unwrap();
    fs::create_dir_all(&backup_dir).unwrap();

    let mut guard = HtaccessGuard::new(htaccess_path, backup_dir.clone(), 500).unwrap();

    for entry in fs::read_dir(&backup_dir).unwrap() {
        let entry = entry.unwrap();
        if entry.path().extension().map_or(false, |ext| ext == "bak") {
            fs::remove_file(entry.path()).unwrap();
        }
    }

    let result = guard.restore_latest();
    assert!(result.is_err());
}

// ─── HTACCESS: EXTERNAL MODIFICATION DETECTION ──────────────────

#[test]
fn test_detects_external_modification() {
    let test_dir = std::env::temp_dir().join("irongate_test_ext_mod_v2");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).unwrap();
    }
    fs::create_dir_all(&test_dir).unwrap();

    let htaccess_path = test_dir.join(".htaccess");
    let backup_dir = test_dir.join("backups");
    fs::write(&htaccess_path, FIXTURE_CONTENT).unwrap();
    fs::create_dir_all(&backup_dir).unwrap();

    let mut guard = HtaccessGuard::new(htaccess_path.clone(), backup_dir, 500).unwrap();

    // Simula edição externa
    let mut modified = fs::read(&htaccess_path).unwrap();
    modified.extend_from_slice(b"\n# Editado manualmente\n");
    fs::write(&htaccess_path, &modified).unwrap();

    let rules = vec![BlockRule {
        ip: IpAddr::from_str("5.5.5.5").unwrap(),
        reason: "test".to_string(),
    }];

    let result = guard.write_rules(&rules);
    assert!(matches!(result, Err(irongate::enforcer::htaccess::Error::ExternalModification)));
}

// ─── HTACCESS: RESTORE EXITS EMERGENCY ──────────────────────────

#[test]
fn test_restore_exits_emergency() {
    let test_dir = std::env::temp_dir().join("irongate_test_exit_emergency");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).unwrap();
    }
    fs::create_dir_all(&test_dir).unwrap();

    let htaccess_path = test_dir.join(".htaccess");
    let backup_dir = test_dir.join("backups");
    fs::write(&htaccess_path, FIXTURE_CONTENT).unwrap();
    fs::create_dir_all(&backup_dir).unwrap();

    let mut guard = HtaccessGuard::new(htaccess_path.clone(), backup_dir.clone(), 500).unwrap();

    guard.emergency_mode = true;
    assert!(guard.emergency_mode);

    // restore_backup deve desativar emergency_mode
    let backups: Vec<_> = fs::read_dir(&backup_dir).unwrap()
        .filter_map(|e| e.ok())
        .filter(|d| d.path().extension().map_or(false, |ext| ext == "bak"))
        .collect();
    if let Some(bak) = backups.last() {
        let _ = guard.restore_backup(&bak.path());
    }

    assert!(!guard.emergency_mode, "Emergency mode deve ser desativado após restore");
}

// ─── HTACCESS: REFUSES WRITE IN EMERGENCY ───────────────────────

#[test]
fn test_refuses_write_in_emergency() {
    let test_dir = std::env::temp_dir().join("irongate_test_refuse_emergency");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).unwrap();
    }
    fs::create_dir_all(&test_dir).unwrap();

    let htaccess_path = test_dir.join(".htaccess");
    let backup_dir = test_dir.join("backups");
    fs::write(&htaccess_path, FIXTURE_CONTENT).unwrap();
    fs::create_dir_all(&backup_dir).unwrap();

    let mut guard = HtaccessGuard::new(htaccess_path, backup_dir, 500).unwrap();
    guard.emergency_mode = true;

    let rules = vec![BlockRule {
        ip: IpAddr::from_str("1.1.1.1").unwrap(),
        reason: "test".to_string(),
    }];

    let result = guard.write_rules(&rules);
    assert!(matches!(result, Err(irongate::enforcer::htaccess::Error::EmergencyMode)));
}

// ─── HTACCESS: PRESERVES EACH BLOCK INDIVIDUALLY ────────────────

#[test]
fn test_preserves_wordpress_block() {
    let content = b"# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase /\n</IfModule>\n# END WordPress\n\n# BEGIN IronGate - GERENCIADO AUTOMATICAMENTE - N\xC3\x83O EDITAR\n# END IronGate\n";
    verify_block_preserved(content, "wordpress", b"# BEGIN WordPress", b"# END WordPress");
}

#[test]
fn test_preserves_lscache_block() {
    let content = b"# BEGIN LSCACHE\n## Complex LSCache rules here\n# END LSCACHE\n\n# BEGIN IronGate - GERENCIADO AUTOMATICAMENTE - N\xC3\x83O EDITAR\n# END IronGate\n";
    verify_block_preserved(content, "lscache", b"# BEGIN LSCACHE", b"# END LSCACHE");
}

#[test]
fn test_preserves_manual_ua_blocks() {
    let content = b"<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteCond %{HTTP_USER_AGENT} (GPTBot|CCBot) [NC]\nRewriteRule .* - [F,L]\n</IfModule>\n\n# BEGIN IronGate - GERENCIADO AUTOMATICAMENTE - N\xC3\x83O EDITAR\n# END IronGate\n";
    verify_block_preserved(content, "ua_blocks", b"GPTBot|CCBot", b"");
}

#[test]
fn test_preserves_redirects() {
    let content = b"RedirectPermanent /antigo /novo\n\n# BEGIN IronGate - GERENCIADO AUTOMATICAMENTE - N\xC3\x83O EDITAR\n# END IronGate\n";
    verify_block_preserved(content, "redirects", b"RedirectPermanent", b"");
}

#[test]
fn test_preserves_security_headers() {
    let content = b"Header set X-Frame-Options SAMEORIGIN\n\n# BEGIN IronGate - GERENCIADO AUTOMATICAMENTE - N\xC3\x83O EDITAR\n# END IronGate\n";
    verify_block_preserved(content, "sec_headers", b"X-Frame-Options", b"");
}

fn verify_block_preserved(content: &[u8], test_name: &str, marker_start: &[u8], marker_end: &[u8]) {
    let test_dir = std::env::temp_dir().join(format!("irongate_preserve_{}", test_name));
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).unwrap();
    }
    fs::create_dir_all(&test_dir).unwrap();

    let htaccess_path = test_dir.join(".htaccess");
    let backup_dir = test_dir.join("backups");
    fs::write(&htaccess_path, content).unwrap();
    fs::create_dir_all(&backup_dir).unwrap();

    let mut guard = HtaccessGuard::new(htaccess_path.clone(), backup_dir, 500).unwrap();

    let rules = vec![BlockRule {
        ip: IpAddr::from_str("9.9.9.9").unwrap(),
        reason: "test".to_string(),
    }];

    guard.write_rules(&rules).unwrap();

    let result = fs::read(&htaccess_path).unwrap();
    assert!(
        result.windows(marker_start.len()).any(|w| w == marker_start),
        "Marker {:?} deve ser preservado",
        String::from_utf8_lossy(marker_start)
    );
    if !marker_end.is_empty() {
        assert!(
            result.windows(marker_end.len()).any(|w| w == marker_end),
            "End marker {:?} deve ser preservado",
            String::from_utf8_lossy(marker_end)
        );
    }
}
