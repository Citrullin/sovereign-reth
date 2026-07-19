use serde::{Deserialize, Serialize};
use sovereign_consensus::config::{StaticConfig, DynamicConfig};
use std::path::Path;
use std::fs;

/// Full node configuration containing static and dynamic configurations.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeConfig {
    /// Static protocol configurations.
    pub static_cfg: StaticConfig,
    /// Dynamic runtime configurations.
    pub dynamic_cfg: DynamicConfig,
}

impl NodeConfig {
    /// Loads a NodeConfig from a TOML file. If loading/parsing fails, returns an error.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, eyre::Report> {
        let content = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }
}
