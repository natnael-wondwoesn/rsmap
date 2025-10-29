use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortState::Open => write!(f, "open"),
            PortState::Closed => write!(f, "closed"),
            PortState::Filtered => write!(f, "Filterd"),
            PortState::OpenFiltered => write!(f, "open|filterd"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub version: Option<String>,
}

impl Service {
    pub fn unknown() -> Self {
        Self {
            name: "unknown".to_string(),
            version: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub port: u16,
    pub state: PortState,
    pub service: Service,
    pub rtt: Option<Duration>,
}

impl ScanResult {
    pub fn new_open(port: u16, rrt: Duration) -> Self {
        Self {
            port,
            state: PortState::Open,
            service: Service::from_port(port),
            rtt: Some(rrt),
        }
    }
    pub fn new_closed(port: u16) -> Self {
        Self {
            port,
            state: PortState::Closed,
            service: Service::unknown(),
            rtt: None,
        }
    }

    pub fn new_filtered(port: u16) -> Self {
        Self {
            port,
            state: PortState::Filtered,
            service: Service::unknown(),
            rtt: None,
        }
    }
    pub fn new_open_filterd(port: u16) -> Self {
        Self {
            port,
            state: PortState::Filtered,
            service: Service::unknown(),
            rtt: None,
        }
    }
}

impl Service {
    fn from_port(port: u16) -> Self {
        match port {
            80 => Self {
                name: "http".to_string(),
                version: None,
            },
            443 => Self {
                name: "https".to_string(),
                version: None,
            },
            22 => Self {
                name: "ssh".to_string(),
                version: None,
            },
            21 => Self {
                name: "ftp".to_string(),
                version: None,
            },
            25 => Self {
                name: "smtp".to_string(),
                version: None,
            },
            3389 => Self {
                name: "rdp".to_string(),
                version: None,
            },
            _ => Self::unknown(),
        }
    }
}
