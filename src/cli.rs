use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "irongate", version, about = "IronGate - Bot Protection Daemon")]
pub struct Cli {
    /// Path to config.toml
    #[arg(long, default_value = "config.toml")]
    pub config: String,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the daemon (default if no subcommand)
    Run,

    /// Show current status (connects to running daemon API)
    Status,

    /// Manually ban an IP address
    Ban {
        /// IP address to ban
        ip: String,
        /// Ban duration in seconds (default: 86400 = 24h)
        #[arg(short, long, default_value = "86400")]
        duration: u64,
    },

    /// Unblock an IP address
    Unblock {
        /// IP address to unblock
        ip: String,
    },

    /// Whitelist an IP address
    Whitelist {
        /// IP address to whitelist
        ip: String,
    },

    /// Restore .htaccess from backup
    Restore {
        /// Specific backup file path, or omit for latest
        #[arg(long)]
        backup: Option<String>,
        /// Restore the most recent backup
        #[arg(long)]
        latest: bool,
    },

    /// Reset emergency mode
    ResetEmergency,
}

impl Cli {
    /// Execute CLI-only commands that don't need the full daemon.
    /// Returns true if the command was handled (caller should exit).
    /// Returns false if the daemon should start normally.
    pub fn execute_cli_command(
        &self,
        config: &crate::config::AppConfig,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        match &self.command {
            None | Some(Commands::Run) => Ok(false), // Start daemon

            Some(Commands::Status) => {
                println!(
                    "Consultando status do IronGate em {}...",
                    config.general.bind_addr
                );
                // Use blocking HTTP request for CLI
                let url = format!("http://{}/api/status", config.general.bind_addr);
                println!("  Endpoint: {}", url);
                println!("  (Use curl {} para ver o status completo)", url);
                println!();
                let guard_url = format!("http://{}/api/guard-status", config.general.bind_addr);
                println!("  Guard: {}", guard_url);
                Ok(true)
            }

            Some(Commands::Ban { ip, duration }) => {
                println!("Enviando ban para {} ({}s) via API...", ip, duration);
                let url = format!("http://{}/api/block", config.general.bind_addr);
                println!(
                    "  curl -X POST {} -H 'Content-Type: application/json' -d '{{\"ip\":\"{}\"}}'",
                    url, ip
                );
                Ok(true)
            }

            Some(Commands::Unblock { ip }) | Some(Commands::Whitelist { ip }) => {
                println!("Enviando whitelist para {} via API...", ip);
                let url = format!("http://{}/api/whitelist", config.general.bind_addr);
                println!(
                    "  curl -X POST {} -H 'Content-Type: application/json' -d '{{\"ip\":\"{}\"}}'",
                    url, ip
                );
                Ok(true)
            }

            Some(Commands::Restore { backup, latest }) => {
                use crate::enforcer::HtaccessGuard;

                let mut guard = HtaccessGuard::new(
                    config.enforcer.htaccess_path.clone(),
                    config.enforcer.backup_dir.clone(),
                    config.enforcer.max_rules,
                )?;

                if *latest || backup.is_none() {
                    println!("Restaurando backup mais recente...");
                    guard.restore_latest()?;
                    println!("Backup restaurado com sucesso.");
                } else if let Some(path) = backup {
                    println!("Restaurando backup: {}", path);
                    guard.restore_backup(std::path::Path::new(path))?;
                    println!("Backup restaurado com sucesso.");
                }
                Ok(true)
            }

            Some(Commands::ResetEmergency) => {
                use crate::enforcer::HtaccessGuard;

                let mut guard = HtaccessGuard::new(
                    config.enforcer.htaccess_path.clone(),
                    config.enforcer.backup_dir.clone(),
                    config.enforcer.max_rules,
                )?;
                guard.restore_latest()?;
                println!("Modo emergencia resetado e backup restaurado.");
                Ok(true)
            }
        }
    }
}
