pub mod parser;

use linemux::MuxedLines;
use std::path::Path;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

pub use crate::types::AccessLogEntry;

pub struct LogIngestor {
    log_path: String,
    tx: mpsc::Sender<AccessLogEntry>,
}

impl LogIngestor {
    pub fn new(log_path: &str, tx: mpsc::Sender<AccessLogEntry>) -> Self {
        Self {
            log_path: log_path.to_string(),
            tx,
        }
    }

    pub async fn run(&self) -> std::io::Result<()> {
        let path = Path::new(&self.log_path);
        if !path.exists() {
            warn!(
                "Arquivo de log {} não existe ainda. Linemux aguardará a criação.",
                self.log_path
            );
        }

        let mut lines = MuxedLines::new()?;
        lines.add_file(&self.log_path).await?;

        info!(
            "Iniciando tailing assíncrono (linemux) em: {}",
            self.log_path
        );

        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(entry) = parser::parse_line(line.line()) {
                // Tenta enviar o log pro Analytics via channel. Se o buffer encher, ele aguardará assincronamente.
                if self.tx.send(entry).await.is_err() {
                    error!("Canal de log quebrado (Receiver dropado). Abortando ingestão.");
                    break;
                }
            }
        }

        Ok(())
    }
}
