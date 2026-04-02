use crate::types::BlockRule;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use chrono::Utc;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    EmergencyMode,
    TooManyRules(usize, usize),
    ExternalModification,
    CrossFilesystem,
    CorruptAssembly,
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct WriteResult {
    pub rules_written: usize,
}

pub struct HtaccessGuard {
    path: PathBuf,
    backup_dir: PathBuf,
    external_content_hash: Option<[u8; 32]>,
    external_content_snapshot: Option<(Vec<u8>, Vec<u8>)>,
    consecutive_failures: u32,
    max_consecutive_failures: u32,
    pub emergency_mode: bool,
    max_rules: usize,
    pub total_writes: u64,
    pub total_blocked_writes: u64,
}

impl HtaccessGuard {
    pub fn new(path: PathBuf, backup_dir: PathBuf, max_rules: usize) -> Result<Self> {
        Self::verify_same_filesystem(&path, &backup_dir)?;

        if !path.exists() {
            // Se nao existe, cria vazio
            File::create(&path)?;
        }

        let mut guard = Self {
            path: path.clone(),
            backup_dir,
            external_content_hash: None,
            external_content_snapshot: None,
            consecutive_failures: 0,
            max_consecutive_failures: 3,
            emergency_mode: false,
            max_rules,
            total_writes: 0,
            total_blocked_writes: 0,
        };

        // Força a criacao do backup inicial e calc hashes
        if guard.path.exists() {
            let mut content = Vec::new();
            File::open(&guard.path)?.read_to_end(&mut content)?;
            
            let (before, _, after) = Self::split_at_delimiters(&content)?;
            guard.external_content_hash = Some(Self::hash_external_content(&before, &after));
            guard.external_content_snapshot = Some((before, after));
            
            guard.create_backup()?;
        }

        Ok(guard)
    }

    pub fn read_current_rules(&mut self) -> Result<Vec<BlockRule>> {
        let mut content = Vec::new();
        File::open(&self.path)?.read_to_end(&mut content)?;

        let (before, block, after) = Self::split_at_delimiters(&content)?;
        self.external_content_hash = Some(Self::hash_external_content(&before, &after));
        self.external_content_snapshot = Some((before, after));

        // Por enquanto não faremos o parse reverso do .htaccess para nao estender demais Phase 1
        Ok(vec![])
    }

    pub fn write_rules(&mut self, rules: &[BlockRule]) -> Result<WriteResult> {
        // G1
        if self.emergency_mode {
            self.total_blocked_writes += 1;
            return Err(Error::EmergencyMode);
        }
        // G2
        if rules.len() > self.max_rules {
            self.total_blocked_writes += 1;
            return Err(Error::TooManyRules(rules.len(), self.max_rules));
        }

        // Fase 1: Backup (I3)
        if let Err(e) = self.create_backup() {
            self.increment_failure();
            return Err(e);
        }

        // Fase 2: Leitura
        let mut content = Vec::new();
        File::open(&self.path)?.read_to_end(&mut content)?;
        let (before, _, after) = Self::split_at_delimiters(&content)?;
        let current_hash = Self::hash_external_content(&before, &after);

        // Validar hash_externo (I5)
        if let Some(expected_hash) = self.external_content_hash {
            if current_hash != expected_hash {
                self.external_content_hash = Some(current_hash);
                self.external_content_snapshot = Some((before, after));
                self.total_blocked_writes += 1;
                return Err(Error::ExternalModification);
            }
        } else {
            self.external_content_hash = Some(current_hash);
            self.external_content_snapshot = Some((before.clone(), after.clone()));
        }

        // Fase 3: Montagem (I4)
        let mut new_block = Vec::new();
        if !rules.is_empty() {
            new_block = Self::format_block(rules);
        }
        
        let mut final_content = Vec::with_capacity(before.len() + new_block.len() + after.len());
        final_content.extend_from_slice(&before);
        final_content.extend_from_slice(&new_block);
        final_content.extend_from_slice(&after);

        // I1 - Validar Montagem
        let (v_before, _, v_after) = Self::split_at_delimiters(&final_content)?;
        let v_hash = Self::hash_external_content(&v_before, &v_after);
        if v_hash != self.external_content_hash.unwrap() {
            self.total_blocked_writes += 1;
            return Err(Error::CorruptAssembly);
        }

        // Fase 4: Escrita Atômica (I2, I8)
        let tmp_path = self.path.with_extension("tmp.irongate");
        match self.write_atomic(&tmp_path, &final_content) {
            Ok(_) => {
                // Fase 5: Pós-escrita verificação
                let mut check_content = Vec::new();
                File::open(&self.path)?.read_to_end(&mut check_content)?;
                let (c_before, _, c_after) = Self::split_at_delimiters(&check_content)?;
                if Self::hash_external_content(&c_before, &c_after) != self.external_content_hash.unwrap() {
                    let _ = self.restore_latest();
                    self.increment_failure();
                    return Err(Error::CorruptAssembly);
                }

                self.consecutive_failures = 0;
                self.total_writes += 1;
                Ok(WriteResult { rules_written: rules.len() })
            }
            Err(e) => {
                self.increment_failure();
                Err(e)
            }
        }
    }

    fn write_atomic(&self, tmp_path: &Path, content: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(tmp_path)?;
        
        file.write_all(content)?;
        file.sync_all()?;
        
        // I2 - Atomic rename
        fs::rename(tmp_path, &self.path)?;
        Ok(())
    }

    pub fn restore_backup(&mut self, backup_path: &Path) -> Result<()> {
        let tmp_path = self.path.with_extension("tmp.restore");
        let mut content = Vec::new();
        File::open(backup_path)?.read_to_end(&mut content)?;
        
        self.write_atomic(&tmp_path, &content)?;
        
        let (before, _, after) = Self::split_at_delimiters(&content)?;
        self.external_content_hash = Some(Self::hash_external_content(&before, &after));
        self.external_content_snapshot = Some((before, after));
        self.emergency_mode = false;
        
        Ok(())
    }

    pub fn restore_latest(&mut self) -> Result<()> {
        let mut backups: Vec<_> = fs::read_dir(&self.backup_dir)?
            .filter_map(std::result::Result::ok)
            .filter(|d| d.path().extension().map_or(false, |ext| ext == "bak"))
            .collect();
            
        backups.sort_by_key(|dir| dir.metadata().and_then(|m| m.modified()).ok());
        if let Some(latest) = backups.last() {
            self.restore_backup(&latest.path())?;
        }
        Ok(())
    }

    pub fn clear_rules(&mut self) -> Result<()> {
        self.write_rules(&[])?;
        Ok(())
    }
    
    pub fn refresh_hash(&mut self) -> Result<()> {
        let mut content = Vec::new();
        File::open(&self.path)?.read_to_end(&mut content)?;

        let (before, _, after) = Self::split_at_delimiters(&content)?;
        self.external_content_hash = Some(Self::hash_external_content(&before, &after));
        self.external_content_snapshot = Some((before, after));
        Ok(())
    }

    fn create_backup(&self) -> Result<()> {
        let timestamp = Utc::now().format("%Y-%m-%dT%H-%M-%S").to_string();
        let backup_name = format!(".htaccess.{}.bak", timestamp);
        let backup_path = self.backup_dir.join(&backup_name);
        
        if self.path.exists() {
            fs::copy(&self.path, &backup_path)?;
        }
        
        let _ = self.rotate_backups(100);
        Ok(())
    }

    fn increment_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= self.max_consecutive_failures {
            self.emergency_mode = true;
        }
    }

    fn verify_same_filesystem(path: &Path, backup_dir: &Path) -> Result<()> {
        // Checagem simplificada de dir/filesystem. (Em sistemas Unix seria st_dev)
        // Para Fase 1, se não existir o backup_dir a gente cria
        if !backup_dir.exists() {
            fs::create_dir_all(backup_dir)?;
        }
        
        let path_parent = path.parent().unwrap_or(Path::new("/"));
        // Simplificado, vamos assumir ok se conseguimos criar
        let test_file = backup_dir.join(".fs_test");
        if File::create(&test_file).is_ok() {
            let _ = fs::remove_file(test_file);
        } else {
             return Err(Error::CrossFilesystem);
        }
        
        Ok(())
    }

    fn format_block(rules: &[BlockRule]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"# BEGIN IronGate - GERENCIADO AUTOMATICAMENTE - N\xC3\x83O EDITAR\n");
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        out.extend_from_slice(format!("# Timestamp: {} | Rules: {} | Version: 1.0.0\n", timestamp, rules.len()).as_bytes());
        out.extend_from_slice(b"<IfModule mod_rewrite.c>\n");
        out.extend_from_slice(b"RewriteEngine On\n");
        
        for (i, rule) in rules.iter().enumerate() {
            let escaped_ip = Self::sanitize_ip(&rule.ip).unwrap_or_default();
            if escaped_ip.is_empty() { continue; }
            let or_clause = if i < rules.len() - 1 { " [OR]" } else { "" };
            out.extend_from_slice(format!("RewriteCond %{{HTTP_X_FORWARDED_FOR}} ^{}${}\n", escaped_ip, or_clause).as_bytes());
        }
        
        if !rules.is_empty() {
             out.extend_from_slice(b"RewriteRule .* - [F,L]\n");
        }
        out.extend_from_slice(b"</IfModule>\n");
        out.extend_from_slice(b"# END IronGate\n");
        out
    }

    fn split_at_delimiters(content: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let begin_marker = b"# BEGIN IronGate - GERENCIADO AUTOMATICAMENTE - N\xC3\x83O EDITAR\n";
        let end_marker = b"# END IronGate\n";

        let begin_idx = content.windows(begin_marker.len()).position(|w| w == begin_marker);
        let end_idx = content.windows(end_marker.len()).position(|w| w == end_marker);

        if let (Some(b_idx), Some(e_idx)) = (begin_idx, end_idx) {
            if b_idx < e_idx {
                let e_pos = e_idx + end_marker.len();
                return Ok((
                    content[..b_idx].to_vec(),
                    content[b_idx..e_pos].to_vec(),
                    content[e_pos..].to_vec(),
                ));
            }
        }
        
        // Se a gente não tem o block, insere no topo (antes das demais regras logicas)
        Ok((Vec::new(), Vec::new(), content.to_vec()))
    }

    fn hash_external_content(before: &[u8], after: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(before);
        hasher.update(after);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    fn sanitize_ip(ip: &IpAddr) -> Result<String> {
        let str_ip = ip.to_string();
        // escapa pontos se for v4
        Ok(str_ip.replace('.', "\\."))
    }

    fn rotate_backups(&self, keep: usize) -> Result<()> {
        let mut backups: Vec<_> = fs::read_dir(&self.backup_dir)?
            .filter_map(std::result::Result::ok)
            .filter(|d| d.path().extension().map_or(false, |ext| ext == "bak"))
            .collect();

        backups.sort_by_key(|dir| dir.metadata().and_then(|m| m.modified()).ok());

        if backups.len() > keep {
            for backup in backups.iter().take(backups.len() - keep) {
                let _ = fs::remove_file(backup.path());
            }
        }
        Ok(())
    }
}
