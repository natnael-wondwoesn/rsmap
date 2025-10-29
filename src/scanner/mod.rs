pub mod syn;
pub mod types;
use std::net::IpAddr;
pub use types::{PortState, ScanResult};
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
