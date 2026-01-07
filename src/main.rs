use anyhow::Context;
use clap::Parser;
use ks_sniff::capture::{CaptureConfig, PacketCapture};
use ks_sniff::config::Settings;
use ks_sniff::decoders::PacketDecoder;
use ks_sniff::decoders::pretty_print;
use ks_sniff::Result;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "ks-sniff")]
#[command(author = "KS-Sniff Contributors")]
#[command(version = "0.1.0")]
#[command(about = "A Rust-based multithreaded intrusion detection system", long_about = None)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Network interface to capture from
    #[arg(short, long)]
    interface: Option<String>,

    /// PCAP file to read from instead of live capture
    #[arg(short = 'r', long, value_name = "FILE")]
    pcap_file: Option<PathBuf>,

    /// BPF filter expression
    #[arg(short = 'f', long)]
    bpf_filter: Option<String>,

    /// Generate default configuration file
    #[arg(long)]
    generate_config: bool,

    /// Verbose logging (can be repeated: -v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Quiet mode (suppress most output)
    #[arg(short, long)]
    quiet: bool,

    /// Enable packet decode logging to console
    #[arg(short = 'd', long)]
    decode_logging: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Handle config generation
    if cli.generate_config {
        generate_default_config()?;
        return Ok(());
    }

    // Load configuration FIRST (before logging, so we can use config settings)
    let mut settings = load_config(&cli)?;

    // Initialize logging (CLI flag overrides config file setting)
    init_logging(&cli, &settings)?;

    info!("Starting ks-sniff v{}", env!("CARGO_PKG_VERSION"));

    // Override config with CLI arguments
    if let Some(interface) = cli.interface {
        settings.network.interface = interface;
    }
    if let Some(bpf_filter) = cli.bpf_filter {
        settings.network.bpf_filter = Some(bpf_filter);
    }

    // Validate configuration
    settings.validate().context("Invalid configuration")?;

    info!("Configuration loaded successfully");
    info!("Interface: {}", settings.network.interface);
    info!(
        "Worker threads: {}",
        if settings.detection.worker_threads == 0 {
            num_cpus::get().saturating_sub(2).max(1)
        } else {
            settings.detection.worker_threads
        }
    );

    // Set up graceful shutdown
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    ctrlc::set_handler(move || {
        warn!("Received shutdown signal");
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Failed to set Ctrl+C handler")?;

    // Run the IDS
    if let Err(e) = run_ids(settings, shutdown, cli.pcap_file) {
        error!("IDS error: {}", e);
        return Err(e.into());
    }

    info!("ks-sniff shutdown complete");
    Ok(())
}

fn init_logging(cli: &Cli, settings: &Settings) -> anyhow::Result<()> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, fmt};

    let log_level = if cli.quiet {
        "error"
    } else {
        match cli.verbose {
            0 => "info",
            1 => "debug",
            _ => "trace",
        }
    };

    // Determine if decode logging should be enabled
    // CLI flag overrides config file setting
    let decode_logging_enabled = if cli.decode_logging {
        true // CLI flag set explicitly
    } else {
        settings.logging.decode_logging // Use config file setting
    };

    // Build filter with optional decoder logging
    // When decode logging is enabled, use debug level for the entire app to show packet details
    let base_level = if decode_logging_enabled {
        "debug" // Enable debug logging throughout when decode logging is on
    } else {
        log_level
    };

    let mut filter_string = format!("ks_sniff={}", base_level);

    // Control decoder module logging separately
    if decode_logging_enabled {
        eprintln!("✓ Decode logging ENABLED (via {})",
            if cli.decode_logging { "CLI flag" } else { "config file" });
    } else {
        // Suppress decoder trace logs (only show warnings and errors)
        filter_string.push_str(",ks_sniff::decoders::decoder=warn");
    }

    // Debug: show the filter being used
    eprintln!("  Log filter: {}", filter_string);

    // Use custom filter, but allow RUST_LOG to override if explicitly set
    let filter = if std::env::var("RUST_LOG").is_ok() {
        eprintln!("  ⚠ Using RUST_LOG environment variable (overrides settings)");
        EnvFilter::try_from_default_env().unwrap()
    } else {
        EnvFilter::new(filter_string)
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(true).with_thread_ids(true))
        .init();

    Ok(())
}

fn load_config(cli: &Cli) -> anyhow::Result<Settings> {
    if let Some(config_path) = &cli.config {
        info!("Loading configuration from: {:?}", config_path);
        Settings::from_file(config_path).context("Failed to load configuration file")
    } else {
        // Try default locations
        let default_paths = vec![
            PathBuf::from("ks-sniff.yaml"),
            PathBuf::from("config/ks-sniff.yaml"),
            PathBuf::from("/etc/ks-sniff/ks-sniff.yaml"),
        ];

        for path in default_paths {
            if path.exists() {
                info!("Loading configuration from: {:?}", path);
                return Settings::from_file(&path)
                    .context(format!("Failed to load configuration from {:?}", path));
            }
        }

        warn!("No configuration file found, using defaults");
        Ok(Settings::default_config())
    }
}

fn generate_default_config() -> anyhow::Result<()> {
    let config = Settings::default_config();
    let yaml = serde_yaml::to_string(&config).context("Failed to serialize config")?;

    let output_path = PathBuf::from("ks-sniff.yaml");
    std::fs::write(&output_path, yaml).context("Failed to write config file")?;

    println!("Generated default configuration at: {:?}", output_path);
    Ok(())
}

fn run_ids(
    settings: Settings,
    shutdown: Arc<AtomicBool>,
    pcap_file: Option<PathBuf>,
) -> Result<()> {
    info!("Initializing IDS components...");

    // Phase 2: Initialize packet capture
    let capture_config = CaptureConfig {
        interface: settings.network.interface.clone(),
        promiscuous: settings.network.promisc_mode,
        snaplen: settings.network.snaplen,
        buffer_size: settings.network.buffer_size as i32,
        timeout: Duration::from_millis(100),
        bpf_filter: settings.network.bpf_filter.clone(),
    };

    let packet_capture = PacketCapture::new(capture_config);

    // Create packet channel
    let (packet_tx, packet_rx) = crossbeam::channel::bounded(settings.detection.packet_queue_size);

    info!("Starting packet capture...");

    // Start capture thread
    let capture_handle = if let Some(ref pcap_path) = pcap_file {
        info!("Reading from PCAP file: {:?}", pcap_path);
        packet_capture.start_file_capture(pcap_path, packet_tx, shutdown.clone())?
    } else {
        info!("Starting live capture on interface: {}", settings.network.interface);
        packet_capture.start_live_capture(packet_tx, shutdown.clone())?
    };

    let capture_stats = packet_capture.get_stats();

    info!("Packet capture started successfully");

    // Phase 3: Initialize protocol decoder
    let decoder = PacketDecoder::new();
    info!("Protocol decoder initialized");

    // TODO: Phase 4 - Load rules
    // TODO: Phase 5 - Initialize pattern matcher
    // TODO: Phase 6 - Start worker threads
    // TODO: Phase 7 - Initialize application layer parsers
    // TODO: Phase 8 - Start alert thread
    // TODO: Phase 9 - Start stats thread

    info!("IDS running - Decoding packets");
    info!("Press Ctrl+C to shutdown");

    let mut packet_count = 0u64;
    let mut decoded_count = 0u64;
    let mut tcp_count = 0u64;
    let mut udp_count = 0u64;
    let mut icmp_count = 0u64;
    let mut last_report = std::time::Instant::now();

    while !shutdown.load(Ordering::Relaxed) {
        match packet_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(packet) => {
                packet_count += 1;

                // Decode the packet
                match decoder.decode(packet) {
                    Ok(decoded) => {
                        decoded_count += 1;

                        // Count by transport protocol
                        if let Some(ref transport) = decoded.transport {
                            use ks_sniff::capture::packet::TransportLayer;
                            match transport {
                                TransportLayer::Tcp(_) => tcp_count += 1,
                                TransportLayer::Udp(_) => udp_count += 1,
                                TransportLayer::Icmp(_) => icmp_count += 1,
                            }
                        }

                        // Wireshark-style detailed packet output (when decode logging is enabled)
                        debug!(
                            "{}",
                            pretty_print::format_packet_detailed(&decoded, packet_count)
                        );

                        // TODO: Phase 6 - Send to worker threads for rule matching
                    }
                    Err(e) => {
                        warn!("Failed to decode packet: {}", e);
                    }
                }

                // Periodic progress report
                if last_report.elapsed() >= Duration::from_secs(5) {
                    let (captured, dropped, bytes) = capture_stats.get_stats();
                    info!(
                        "Stats: captured={}, decoded={}, TCP={}, UDP={}, ICMP={}, dropped={}, bytes={}",
                        captured, decoded_count, tcp_count, udp_count, icmp_count, dropped, bytes
                    );
                    last_report = std::time::Instant::now();
                }
            }
            Err(crossbeam::channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam::channel::RecvTimeoutError::Disconnected) => {
                info!("Capture thread disconnected");
                break;
            }
        }
    }

    info!("Shutting down IDS components...");

    // Wait for capture thread to finish
    if let Err(e) = capture_handle.join() {
        error!("Capture thread panicked: {:?}", e);
    }

    let (captured, dropped, bytes) = capture_stats.get_stats();
    info!(
        "Final stats: captured={}, decoded={}, TCP={}, UDP={}, ICMP={}, dropped={}, bytes={}",
        captured, decoded_count, tcp_count, udp_count, icmp_count, dropped, bytes
    );

    Ok(())
}
