use ks_sniff::capture::{CaptureConfig, PacketCapture};
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Get PCAP file from arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <pcap_file>", args[0]);
        eprintln!("\nExample: {} capture.pcap", args[0]);
        std::process::exit(1);
    }

    let pcap_file = &args[1];

    println!("KS-Sniff PCAP Reader Example");
    println!("=============================\n");
    println!("Reading from file: {}\n", pcap_file);

    // Create capture config
    let config = CaptureConfig::default();
    let capture = PacketCapture::new(config);

    // Create channel for packets
    let (tx, rx) = crossbeam::channel::bounded(10000);

    // Shutdown signal (not needed for file reading but kept for consistency)
    let shutdown = Arc::new(AtomicBool::new(false));

    // Start file capture thread
    let capture_stats = capture.get_stats();
    let handle = capture.start_file_capture(pcap_file, tx, shutdown.clone())?;

    // Process packets
    let mut count = 0u64;
    let start_time = std::time::Instant::now();

    println!("Processing packets...\n");

    while let Ok(packet) = rx.recv_timeout(Duration::from_millis(100)) {
        count += 1;

        // Print first 10 packets
        if count <= 10 {
            println!(
                "Packet #{}: {} bytes (captured: {}), timestamp: {}",
                count,
                packet.length,
                packet.caplen,
                packet.timestamp
            );

            // Show first 64 bytes in hex
            let display_len = packet.data.len().min(64);
            print!("  Data: ");
            for (i, byte) in packet.data[..display_len].iter().enumerate() {
                print!("{:02x} ", byte);
                if (i + 1) % 16 == 0 {
                    println!();
                    print!("        ");
                }
            }
            println!("\n");
        }

        // Progress indicator for large files
        if count % 10000 == 0 {
            println!("Processed {} packets...", count);
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
    println!("Processing time: {:.2}s", elapsed);
    println!("Average rate: {:.2} pkt/s", captured as f64 / elapsed);

    Ok(())
}
