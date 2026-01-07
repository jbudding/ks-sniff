use ks_sniff::capture::{CaptureConfig, PacketCapture};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("KS-Sniff Simple Capture Example");
    println!("================================\n");

    // List available devices
    println!("Available network interfaces:");
    match PacketCapture::list_devices() {
        Ok(devices) => {
            for (i, device) in devices.iter().enumerate() {
                println!("  {}. {} - {:?}", i + 1, device.name, device.desc);
            }
        }
        Err(e) => {
            eprintln!("Error listing devices: {}", e);
            eprintln!("Note: You may need root/administrator privileges");
            return Err(e.into());
        }
    }

    println!("\nStarting packet capture on 'any' interface...");
    println!("Press Ctrl+C to stop\n");

    // Create capture config
    let config = CaptureConfig {
        interface: "any".to_string(),
        promiscuous: true,
        snaplen: 65535,
        buffer_size: 10_000_000,
        timeout: Duration::from_millis(100),
        bpf_filter: Some("tcp or udp or icmp".to_string()),
    };

    let capture = PacketCapture::new(config);

    // Create channel for packets
    let (tx, rx) = crossbeam::channel::bounded(1000);

    // Shutdown signal
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    // Set up Ctrl+C handler
    ctrlc::set_handler(move || {
        println!("\nReceived Ctrl+C, shutting down...");
        shutdown_clone.store(true, Ordering::Relaxed);
    })?;

    // Start capture thread
    let capture_stats = capture.get_stats();
    let handle = capture.start_live_capture(tx, shutdown.clone())?;

    // Receive and count packets
    let mut count = 0u64;
    let start_time = std::time::Instant::now();
    let mut last_stats = std::time::Instant::now();

    while !shutdown.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(packet) => {
                count += 1;
                if count <= 10 {
                    println!(
                        "Packet #{}: {} bytes, timestamp: {}",
                        count,
                        packet.data.len(),
                        packet.timestamp
                    );
                }
            }
            Err(crossbeam::channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam::channel::RecvTimeoutError::Disconnected) => break,
        }

        // Print stats every 5 seconds
        if last_stats.elapsed() >= Duration::from_secs(5) {
            let (captured, dropped, bytes) = capture_stats.get_stats();
            let elapsed = start_time.elapsed().as_secs_f64();
            let pps = captured as f64 / elapsed;
            println!(
                "\nStats: {} packets captured, {} dropped, {:.2} pkt/s",
                captured, dropped, pps
            );
            last_stats = std::time::Instant::now();
        }
    }

    // Wait for capture thread
    handle.join().unwrap()?;

    // Final stats
    let (captured, dropped, bytes) = capture_stats.get_stats();
    let elapsed = start_time.elapsed().as_secs_f64();

    println!("\n=== Final Statistics ===");
    println!("Packets captured: {}", captured);
    println!("Packets dropped: {}", dropped);
    println!("Bytes captured: {}", bytes);
    println!("Runtime: {:.2}s", elapsed);
    println!("Average rate: {:.2} pkt/s", captured as f64 / elapsed);

    Ok(())
}
