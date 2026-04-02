use irongate::enforcer::htaccess::HtaccessGuard;
use irongate::enforcer::Enforcer;
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

fn setup_enforcer(name: &str) -> (String, PathBuf) {
    let test_dir = std::env::temp_dir().join(format!("irongate_enforcer_test_{}", name));
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).unwrap();
    }
    fs::create_dir_all(&test_dir).unwrap();

    let htaccess_path = test_dir.join(".htaccess");
    fs::write(&htaccess_path, FIXTURE_CONTENT).unwrap();

    // Também criar diretório .irongate_backups no CWD do temp
    let backup_dir = test_dir.join(".irongate_backups");
    fs::create_dir_all(&backup_dir).unwrap();

    // O Enforcer cria backup em ".irongate_backups" relativo, então mudamos CWD
    (htaccess_path.to_string_lossy().to_string(), test_dir)
}

// ─── BATCHING ───────────────────────────────────────────────────

#[test]
fn test_enforcer_add_ban_marks_pending() {
    let (path, _dir) = setup_enforcer("add_ban");
    let mut enforcer = Enforcer::new(&path).unwrap();

    assert!(!enforcer.pending_flush);
    enforcer.add_ban("1.1.1.1".to_string(), 3600);
    assert!(enforcer.pending_flush, "Após add_ban, pending_flush deve ser true");
    assert_eq!(enforcer.active_bans.len(), 1);
}

#[test]
fn test_enforcer_whitelist_blocks_ban() {
    let (path, _dir) = setup_enforcer("whitelist_block");
    let mut enforcer = Enforcer::new(&path).unwrap();

    enforcer.whitelist.insert("1.1.1.1".to_string());
    enforcer.add_ban("1.1.1.1".to_string(), 3600);

    assert_eq!(enforcer.active_bans.len(), 0, "IP whitelist não deve ser banido");
    assert!(!enforcer.pending_flush);
}

#[test]
fn test_enforcer_cleanup_removes_expired() {
    let (path, _dir) = setup_enforcer("cleanup");
    let mut enforcer = Enforcer::new(&path).unwrap();

    // Ban com duração 0 = já expirou
    enforcer.add_ban("1.1.1.1".to_string(), 0);
    std::thread::sleep(std::time::Duration::from_millis(10));

    let removed = enforcer.cleanup_expired();
    assert!(removed, "Deveria detectar bans expirados");
    assert_eq!(enforcer.active_bans.len(), 0);
}

#[test]
fn test_enforcer_multiple_bans_batch() {
    let (path, _dir) = setup_enforcer("multi_ban");
    let mut enforcer = Enforcer::new(&path).unwrap();

    enforcer.add_ban("1.1.1.1".to_string(), 3600);
    enforcer.add_ban("2.2.2.2".to_string(), 3600);
    enforcer.add_ban("3.3.3.3".to_string(), 3600);

    assert_eq!(enforcer.active_bans.len(), 3);
    assert!(enforcer.pending_flush);
}

// ─── HTACCESS GUARD: IPv6 ───────────────────────────────────────

#[test]
fn test_htaccess_ipv6_write() {
    let test_dir = std::env::temp_dir().join("irongate_test_ipv6");
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
    assert!(res.is_ok(), "Write de regra IPv6 deveria funcionar");

    let content = fs::read_to_string(&htaccess_path).unwrap();
    // IPv6 com : escapado para regex do Apache
    assert!(
        content.contains("2001"),
        "Conteúdo deveria conter o endereço IPv6"
    );
}

// ─── HTACCESS GUARD: BACKUP / RESTORE ───────────────────────────

#[test]
fn test_restore_latest_fails_empty_backups() {
    let test_dir = std::env::temp_dir().join("irongate_test_restore_empty");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).unwrap();
    }
    fs::create_dir_all(&test_dir).unwrap();

    let htaccess_path = test_dir.join(".htaccess");
    let backup_dir = test_dir.join("empty_backups");
    fs::write(&htaccess_path, b"empty").unwrap();
    fs::create_dir_all(&backup_dir).unwrap();

    let mut guard = HtaccessGuard::new(htaccess_path, backup_dir.clone(), 500).unwrap();

    // Limpar todos os backups que o construtor criou
    for entry in fs::read_dir(&backup_dir).unwrap() {
        let entry = entry.unwrap();
        if entry.path().extension().map_or(false, |ext| ext == "bak") {
            fs::remove_file(entry.path()).unwrap();
        }
    }

    let result = guard.restore_latest();
    assert!(result.is_err(), "Deve falhar quando não há backups");
}

// ─── HTACCESS: EXTERNAL MODIFICATION DETECTION ──────────────────

#[test]
fn test_detects_external_modification() {
    let test_dir = std::env::temp_dir().join("irongate_test_external_mod");
    if test_dir.exists() {
        fs::remove_dir_all(&test_dir).unwrap();
    }
    fs::create_dir_all(&test_dir).unwrap();

    let htaccess_path = test_dir.join(".htaccess");
    let backup_dir = test_dir.join("backups");
    fs::write(&htaccess_path, FIXTURE_CONTENT).unwrap();
    fs::create_dir_all(&backup_dir).unwrap();

    let mut guard = HtaccessGuard::new(htaccess_path.clone(), backup_dir, 500).unwrap();

    // Simula edição externa (alguém editou o .htaccess por fora)
    let mut modified = fs::read(&htaccess_path).unwrap();
    modified.extend_from_slice(b"\n# Editado manualmente por admin\n");
    fs::write(&htaccess_path, &modified).unwrap();

    let rules = vec![BlockRule {
        ip: IpAddr::from_str("5.5.5.5").unwrap(),
        reason: "test".to_string(),
    }];

    let result = guard.write_rules(&rules);
    assert!(
        matches!(result, Err(irongate::enforcer::htaccess::Error::ExternalModification)),
        "Deveria detectar modificação externa e recusar escrita"
    );
}
