use crate::error::{KsError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Settings {
    pub network: NetworkConfig,
    #[serde(default)]
    pub variables: HashMap<String, String>,
    pub rules: RulesConfig,
    pub detection: DetectionConfig,
    pub outputs: Vec<OutputConfig>,
    pub logging: LoggingConfig,
    #[serde(default)]
    pub performance: PerformanceConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
    pub interface: String,
    #[serde(default = "default_true")]
    pub promisc_mode: bool,
    #[serde(default = "default_snaplen")]
    pub snaplen: i32,
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
    #[serde(default)]
    pub bpf_filter: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RulesConfig {
    pub paths: Vec<PathBuf>,
    #[serde(default)]
    pub enabled_groups: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DetectionConfig {
    #[serde(default)]
    pub worker_threads: usize,
    #[serde(default = "default_packet_queue_size")]
    pub packet_queue_size: usize,
    #[serde(default = "default_alert_queue_size")]
    pub alert_queue_size: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum OutputConfig {
    Json { path: PathBuf },
    Fast { path: PathBuf },
    Syslog { facility: String, severity: String },
    Pcap { path: PathBuf, max_packets: usize },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default)]
    pub output: Option<PathBuf>,
    #[serde(default)]
    pub decode_logging: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PerformanceConfig {
    #[serde(default = "default_stats_interval")]
    pub stats_interval: u64,
    #[serde(default)]
    pub enable_profiling: bool,
}

// Default value functions
fn default_true() -> bool {
    true
}

fn default_snaplen() -> i32 {
    65535
}

fn default_buffer_size() -> usize {
    10_000_000 // 10MB
}

fn default_packet_queue_size() -> usize {
    10_000
}

fn default_alert_queue_size() -> usize {
    1_000
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

fn default_stats_interval() -> u64 {
    60
}

impl Settings {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            KsError::ConfigError(format!("Failed to read config file: {}", e))
        })?;

        let settings: Settings = serde_yaml::from_str(&content)?;
        settings.validate()?;
        Ok(settings)
    }

    pub fn validate(&self) -> Result<()> {
        // Validate network interface
        if self.network.interface.is_empty() {
            return Err(KsError::ConfigError(
                "Network interface cannot be empty".to_string(),
            ));
        }

        // Validate rule paths exist
        for path in &self.rules.paths {
            if !path.exists() {
                tracing::warn!("Rule file does not exist: {:?}", path);
            }
        }

        // Validate worker threads
        if self.detection.worker_threads > 1000 {
            return Err(KsError::ConfigError(
                "Worker threads cannot exceed 1000".to_string(),
            ));
        }

        // Validate queue sizes
        if self.detection.packet_queue_size == 0 {
            return Err(KsError::ConfigError(
                "Packet queue size must be greater than 0".to_string(),
            ));
        }

        if self.detection.alert_queue_size == 0 {
            return Err(KsError::ConfigError(
                "Alert queue size must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }

    pub fn default_config() -> Self {
        Settings {
            network: NetworkConfig {
                interface: "eth0".to_string(),
                promisc_mode: true,
                snaplen: 65535,
                buffer_size: 10_000_000,
                bpf_filter: Some("tcp or udp or icmp".to_string()),
            },
            variables: {
                let mut vars = HashMap::new();
                vars.insert("HOME_NET".to_string(), "[192.168.1.0/24]".to_string());
                vars.insert("EXTERNAL_NET".to_string(), "!$HOME_NET".to_string());
                vars.insert("HTTP_PORTS".to_string(), "[80,8080,8000-8999]".to_string());
                vars.insert("HTTPS_PORTS".to_string(), "443".to_string());
                vars
            },
            rules: RulesConfig {
                paths: vec![PathBuf::from("rules/local.rules")],
                enabled_groups: vec!["web".to_string(), "malware".to_string()],
            },
            detection: DetectionConfig {
                worker_threads: 0,
                packet_queue_size: 10_000,
                alert_queue_size: 1_000,
            },
            outputs: vec![
                OutputConfig::Json {
                    path: PathBuf::from("/var/log/ks-sniff/alerts.json"),
                },
                OutputConfig::Fast {
                    path: PathBuf::from("/var/log/ks-sniff/fast.log"),
                },
            ],
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
                output: Some(PathBuf::from("/var/log/ks-sniff/ks-sniff.log")),
                decode_logging: false,
            },
            performance: PerformanceConfig {
                stats_interval: 60,
                enable_profiling: false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Settings::default_config();
        assert!(config.validate().is_ok());
        assert_eq!(config.network.interface, "eth0");
        assert_eq!(config.detection.packet_queue_size, 10_000);
    }
}
