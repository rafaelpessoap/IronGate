use crate::analytics::ip_tracker::{IpState, SlidingWindow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use tracing::{error, info, warn};

#[derive(Serialize, Deserialize)]
struct SlidWinState {
    window_secs: u64,
    request_timestamps: Vec<DateTime<Utc>>,
}

impl From<&SlidingWindow> for SlidWinState {
    fn from(win: &SlidingWindow) -> Self {
        Self {
            window_secs: win.window_secs,
            request_timestamps: win.request_timestamps.iter().copied().collect(),
        }
    }
}

impl From<SlidWinState> for SlidingWindow {
    fn from(val: SlidWinState) -> Self {
        SlidingWindow {
            window_secs: val.window_secs,
            request_timestamps: val.request_timestamps.into_iter().collect::<VecDeque<_>>(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct IpStateData {
    ip: IpAddr,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    user_agent: String,
    vhost: String,
    window: SlidWinState,
    ajax_window: SlidWinState,
    page_window: SlidWinState,
    total_requests: u64,
    strikes: u32,
    ban_until: Option<DateTime<Utc>>,
    is_whitelisted: bool,
    threat_score: f32,
    custom_counters: HashMap<String, u32>,
}

impl From<&IpState> for IpStateData {
    fn from(state: &IpState) -> Self {
        Self {
            ip: state.ip,
            first_seen: state.first_seen,
            last_seen: state.last_seen,
            user_agent: state.user_agent.clone(),
            vhost: state.vhost.clone(),
            window: (&state.window).into(),
            ajax_window: (&state.ajax_window).into(),
            page_window: (&state.page_window).into(),
            total_requests: state.total_requests,
            strikes: state.strikes,
            ban_until: state.ban_until,
            is_whitelisted: state.is_whitelisted,
            threat_score: state.threat_score,
            custom_counters: state.custom_counters.clone(),
        }
    }
}

impl From<IpStateData> for IpState {
    fn from(val: IpStateData) -> Self {
        IpState {
            ip: val.ip,
            first_seen: val.first_seen,
            last_seen: val.last_seen,
            user_agent: val.user_agent,
            vhost: val.vhost,
            window: val.window.into(),
            ajax_window: val.ajax_window.into(),
            page_window: val.page_window.into(),
            total_requests: val.total_requests,
            strikes: val.strikes,
            ban_until: val.ban_until,
            is_whitelisted: val.is_whitelisted,
            threat_score: val.threat_score,
            custom_counters: val.custom_counters,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct EngineState {
    states: HashMap<IpAddr, IpStateData>,
}

pub struct PersistenceManager {
    file_path: PathBuf,
}

impl PersistenceManager {
    pub fn new(state_dir: &str) -> std::io::Result<Self> {
        let dir = PathBuf::from(state_dir);
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }
        let file_path = dir.join("state.json");
        Ok(Self { file_path })
    }

    pub fn save(&self, states: &HashMap<IpAddr, IpState>) {
        let mut data = HashMap::new();
        for (ip, state) in states {
            data.insert(*ip, IpStateData::from(state));
        }
        let engine_state = EngineState { states: data };

        // Serializar de forma segura com temp file
        let temp_path = self.file_path.with_extension("tmp");
        match serde_json::to_string(&engine_state) {
            Ok(json) => {
                if let Err(e) = fs::write(&temp_path, json) {
                    error!("Erro ao gravar backup de estado no disco temporário: {}", e);
                    return;
                }
                if let Err(e) = fs::rename(&temp_path, &self.file_path) {
                    error!("Erro ao substituir o arquivo defintivo state.json: {}", e);
                }
            }
            Err(e) => {
                error!("Erro ao serializar state.json: {}", e);
            }
        }
    }

    pub fn load(&self) -> HashMap<IpAddr, IpState> {
        if !self.file_path.exists() {
            info!("Nenhum state.json antigo encontrado. Iniciando estado limpo.");
            return HashMap::new();
        }

        match fs::read_to_string(&self.file_path) {
            Ok(content) => match serde_json::from_str::<EngineState>(&content) {
                Ok(engine_state) => {
                    let mut states = HashMap::new();
                    for (ip, state_data) in engine_state.states {
                        states.insert(ip, state_data.into());
                    }
                    info!(
                        "Estado recuperado com sucesso: {} IPs salvos.",
                        states.len()
                    );
                    states
                }
                Err(e) => {
                    warn!(
                        "Aviso: Falha ao fazer parse do state.json ({}), iniciando zerado.",
                        e
                    );
                    HashMap::new()
                }
            },
            Err(e) => {
                error!("Falha grave ao ler {}: {}", self.file_path.display(), e);
                HashMap::new()
            }
        }
    }
}
