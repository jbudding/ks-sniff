use crate::capture::packet::RawPacket;
use crate::error::{KsError, Result};
use chrono::{TimeZone, Utc};
use crossbeam::channel::Sender;
use pcap::{Active, Capture, Device, Offline, PacketHeader};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Statistics for packet capture
#[derive(Debug, Default)]
pub struct CaptureStats {
    pub packets_captured: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub bytes_captured: AtomicU64,
}

impl CaptureStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment_packets(&self) {
        self.packets_captured.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_bytes(&self, bytes: u64) {
        self.bytes_captured.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn increment_drops(&self, drops: u64) {
        self.packets_dropped.fetch_add(drops, Ordering::Relaxed);
    }

    pub fn get_stats(&self) -> (u64, u64, u64) {
        (
            self.packets_captured.load(Ordering::Relaxed),
            self.packets_dropped.load(Ordering::Relaxed),
            self.bytes_captured.load(Ordering::Relaxed),
        )
    }
}

/// Packet capture configuration
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub interface: String,
    pub promiscuous: bool,
    pub snaplen: i32,
    pub buffer_size: i32,
    pub timeout: Duration,
    pub bpf_filter: Option<String>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: "any".to_string(),
            promiscuous: true,
            snaplen: 65535,
            buffer_size: 10_000_000, // 10MB
            timeout: Duration::from_millis(100),
            bpf_filter: Some("tcp or udp or icmp".to_string()),
        }
    }
}

/// Packet capture engine
pub struct PacketCapture {
    config: CaptureConfig,
    stats: Arc<CaptureStats>,
}

impl PacketCapture {
    pub fn new(config: CaptureConfig) -> Self {
        Self {
            config,
            stats: Arc::new(CaptureStats::new()),
        }
    }

    /// List available network interfaces
    pub fn list_devices() -> Result<Vec<Device>> {
        Device::list().map_err(|e| KsError::CaptureError(format!("Failed to list devices: {}", e)))
    }

    /// Open live capture on network interface
    pub fn open_live(&self) -> Result<Capture<Active>> {
        info!(
            "Opening live capture on interface: {}",
            self.config.interface
        );

        let mut cap = Capture::from_device(self.config.interface.as_str())
            .map_err(|e| KsError::CaptureError(format!("Failed to open device: {}", e)))?
            .promisc(self.config.promiscuous)
            .snaplen(self.config.snaplen)
            .buffer_size(self.config.buffer_size)
            .timeout(self.config.timeout.as_millis() as i32)
            .open()
            .map_err(|e| KsError::CaptureError(format!("Failed to activate capture: {}", e)))?;

        // Apply BPF filter if specified
        if let Some(ref filter) = self.config.bpf_filter {
            info!("Applying BPF filter: {}", filter);
            cap.filter(filter, true)
                .map_err(|e| KsError::CaptureError(format!("Failed to set BPF filter: {}", e)))?;
        }

        info!("Live capture opened successfully");
        Ok(cap)
    }

    /// Open capture from PCAP file
    pub fn open_file<P: AsRef<Path>>(&self, path: P) -> Result<Capture<Offline>> {
        info!("Opening PCAP file: {:?}", path.as_ref());

        let mut cap = Capture::from_file(path)
            .map_err(|e| KsError::CaptureError(format!("Failed to open PCAP file: {}", e)))?;

        // Apply BPF filter if specified
        if let Some(ref filter) = self.config.bpf_filter {
            info!("Applying BPF filter: {}", filter);
            cap.filter(filter, true)
                .map_err(|e| KsError::CaptureError(format!("Failed to set BPF filter: {}", e)))?;
        }

        info!("PCAP file opened successfully");
        Ok(cap)
    }

    /// Start live capture thread
    pub fn start_live_capture(
        &self,
        packet_tx: Sender<RawPacket>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<thread::JoinHandle<Result<()>>> {
        let config = self.config.clone();
        let stats = self.stats.clone();

        let handle = thread::Builder::new()
            .name("capture-thread".to_string())
            .spawn(move || {
                Self::capture_loop_live(config, packet_tx, shutdown, stats)
            })
            .map_err(|e| KsError::ThreadError(format!("Failed to spawn capture thread: {}", e)))?;

        Ok(handle)
    }

    /// Start file capture thread
    pub fn start_file_capture<P: AsRef<Path>>(
        &self,
        path: P,
        packet_tx: Sender<RawPacket>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<thread::JoinHandle<Result<()>>> {
        let path = path.as_ref().to_path_buf();
        let config = self.config.clone();
        let stats = self.stats.clone();

        let handle = thread::Builder::new()
            .name("capture-file-thread".to_string())
            .spawn(move || {
                Self::capture_loop_file(config, path, packet_tx, shutdown, stats)
            })
            .map_err(|e| KsError::ThreadError(format!("Failed to spawn capture thread: {}", e)))?;

        Ok(handle)
    }

    /// Main capture loop for live capture
    fn capture_loop_live(
        config: CaptureConfig,
        packet_tx: Sender<RawPacket>,
        shutdown: Arc<AtomicBool>,
        stats: Arc<CaptureStats>,
    ) -> Result<()> {
        let capture = Self::open_live_internal(&config)?;
        Self::process_packets(capture, packet_tx, shutdown, stats)
    }

    /// Main capture loop for file capture
    fn capture_loop_file(
        config: CaptureConfig,
        path: std::path::PathBuf,
        packet_tx: Sender<RawPacket>,
        shutdown: Arc<AtomicBool>,
        stats: Arc<CaptureStats>,
    ) -> Result<()> {
        let capture = Self::open_file_internal(&config, &path)?;
        Self::process_packets(capture, packet_tx, shutdown, stats)
    }

    /// Internal helper to open live capture
    fn open_live_internal(config: &CaptureConfig) -> Result<Capture<Active>> {
        let mut cap = Capture::from_device(config.interface.as_str())
            .map_err(|e| KsError::CaptureError(format!("Failed to open device: {}", e)))?
            .promisc(config.promiscuous)
            .snaplen(config.snaplen)
            .buffer_size(config.buffer_size)
            .timeout(config.timeout.as_millis() as i32)
            .open()
            .map_err(|e| KsError::CaptureError(format!("Failed to activate capture: {}", e)))?;

        if let Some(ref filter) = config.bpf_filter {
            cap.filter(filter, true)
                .map_err(|e| KsError::CaptureError(format!("Failed to set BPF filter: {}", e)))?;
        }

        Ok(cap)
    }

    /// Internal helper to open file capture
    fn open_file_internal(
        config: &CaptureConfig,
        path: &Path,
    ) -> Result<Capture<Offline>> {
        let mut cap = Capture::from_file(path)
            .map_err(|e| KsError::CaptureError(format!("Failed to open PCAP file: {}", e)))?;

        if let Some(ref filter) = config.bpf_filter {
            cap.filter(filter, true)
                .map_err(|e| KsError::CaptureError(format!("Failed to set BPF filter: {}", e)))?;
        }

        Ok(cap)
    }

    /// Process packets from capture (generic over Active and Offline)
    fn process_packets<T: pcap::Activated>(
        mut capture: Capture<T>,
        packet_tx: Sender<RawPacket>,
        shutdown: Arc<AtomicBool>,
        stats: Arc<CaptureStats>,
    ) -> Result<()> {
        info!("Starting packet processing loop");

        let mut last_stats_log = std::time::Instant::now();
        let stats_interval = Duration::from_secs(10);

        while !shutdown.load(Ordering::Relaxed) {
            match capture.next_packet() {
                Ok(packet) => {
                    // Convert pcap packet to RawPacket
                    let raw_packet = Self::convert_packet(&packet.header, packet.data);

                    // Update statistics
                    stats.increment_packets();
                    stats.increment_bytes(packet.header.len as u64);

                    // Send to processing queue
                    if let Err(e) = packet_tx.try_send(raw_packet) {
                        warn!("Failed to send packet to queue: {:?}", e);
                        stats.increment_drops(1);
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Normal timeout, continue
                    continue;
                }
                Err(pcap::Error::NoMorePackets) => {
                    // End of file for offline capture
                    info!("Reached end of PCAP file");
                    break;
                }
                Err(e) => {
                    error!("Capture error: {}", e);
                    return Err(KsError::CaptureError(format!("Capture failed: {}", e)));
                }
            }

            // Periodic stats logging
            if last_stats_log.elapsed() >= stats_interval {
                let (packets, drops, bytes) = stats.get_stats();
                info!(
                    "Capture stats: {} packets, {} drops, {} bytes",
                    packets, drops, bytes
                );
                last_stats_log = std::time::Instant::now();
            }
        }

        info!("Packet capture loop terminated");

        // Final statistics
        if let Ok(pcap_stats) = capture.stats() {
            debug!("PCAP stats: received={}, dropped={}", pcap_stats.received, pcap_stats.dropped);
            stats.increment_drops(pcap_stats.dropped as u64);
        }

        let (packets, drops, bytes) = stats.get_stats();
        info!(
            "Final capture stats: {} packets, {} drops, {} bytes",
            packets, drops, bytes
        );

        Ok(())
    }

    /// Convert pcap packet to RawPacket
    fn convert_packet(header: &PacketHeader, data: &[u8]) -> RawPacket {
        // Convert timeval to DateTime<Utc>
        let timestamp = Utc.timestamp_opt(header.ts.tv_sec, header.ts.tv_usec as u32 * 1000)
            .single()
            .unwrap_or_else(Utc::now);

        RawPacket {
            timestamp,
            data: data.to_vec().into(),
            length: header.len as usize,
            caplen: header.caplen as usize,
        }
    }

    /// Get capture statistics
    pub fn get_stats(&self) -> Arc<CaptureStats> {
        self.stats.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_config_default() {
        let config = CaptureConfig::default();
        assert_eq!(config.snaplen, 65535);
        assert!(config.promiscuous);
    }

    #[test]
    fn test_capture_stats() {
        let stats = CaptureStats::new();
        stats.increment_packets();
        stats.increment_bytes(100);
        stats.increment_drops(1);

        let (packets, drops, bytes) = stats.get_stats();
        assert_eq!(packets, 1);
        assert_eq!(drops, 1);
        assert_eq!(bytes, 100);
    }

    #[test]
    fn test_list_devices() {
        // This test may fail in restricted environments
        match PacketCapture::list_devices() {
            Ok(devices) => {
                println!("Found {} devices", devices.len());
                for device in devices {
                    println!("  - {:?}", device.name);
                }
            }
            Err(e) => {
                println!("Could not list devices (may be expected): {}", e);
            }
        }
    }
}
