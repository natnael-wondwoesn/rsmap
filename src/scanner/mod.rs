// src/scanner/mod.rs
pub mod syn;
pub mod types;
pub mod util;

pub use types::ScanResult;

use std::net::IpAddr;

/// Public scanner API
pub struct Scanner {
    target: IpAddr,
    ports: Vec<u16>,
}

impl Scanner {
    pub fn new(target: IpAddr, ports: Vec<u16>) -> Self {
        Self { target, ports }
    }

    pub async fn run(&self) -> anyhow::Result<Vec<ScanResult>> {
        syn::scan(self.target, &self.ports).await
    }
}
