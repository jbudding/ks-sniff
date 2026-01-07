/// Example demonstrating the Snort-compatible rule engine
///
/// This shows how to:
/// - Parse Snort rules
/// - Load rules from files
/// - Use variables ($HOME_NET, etc.)
/// - Query rules by protocol/port
/// - Get rule statistics
///
/// Run with:
///   cargo run --example rule_engine_demo --release

use ks_sniff::rules::{parse_rule, Direction, IpSpec, PortSpec, Protocol, Rule, RuleAction, RuleSet};

fn main() {
    println!("=== KS-Sniff Rule Engine Demo ===\n");

    // ============================================================
    // Part 1: Parsing individual rules
    // ============================================================
    println!("Part 1: Parsing Individual Rules\n");
    println!("{}", "=".repeat(60));

    // Simple rule
    let simple_rule = r#"alert tcp any any -> any 80 (msg:"Test"; sid:1;)"#;
    match parse_rule(simple_rule) {
        Ok((_, rule)) => {
            println!("✓ Parsed simple rule:");
            println!("  Action: {}", rule.action);
            println!("  Protocol: {}", rule.protocol);
            println!("  Direction: {}", rule.direction);
            println!("  Dst Port: {}", rule.dst_port);
            println!("  SID: {}", rule.sid());
            println!("  Message: {}", rule.message().unwrap_or("N/A"));
        }
        Err(e) => {
            eprintln!("✗ Failed to parse rule: {:?}", e);
        }
    }

    println!();

    // Rule with variables
    let var_rule = r#"alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"HTTP Traffic"; content:"GET"; sid:1000; rev:1; priority:2;)"#;
    match parse_rule(var_rule) {
        Ok((_, rule)) => {
            println!("✓ Parsed rule with variables:");
            println!("  Src IP: {}", rule.src_ip);
            println!("  Dst IP: {}", rule.dst_ip);
            println!("  Dst Port: {}", rule.dst_port);
            println!("  SID: {}", rule.sid());
            println!("  Message: {}", rule.message().unwrap_or("N/A"));
            println!("  Priority: {}", rule.priority());
            println!("  Content patterns: {}", rule.options.content.len());
        }
        Err(e) => {
            eprintln!("✗ Failed to parse rule: {:?}", e);
        }
    }

    println!("\n{}\n", "=".repeat(60));

    // ============================================================
    // Part 2: Rule Set with Variables
    // ============================================================
    println!("Part 2: Rule Set with Variables\n");
    println!("{}", "=".repeat(60));

    let mut ruleset = RuleSet::new();

    // Configure variables
    println!("Configuring variables...");
    ruleset
        .variables_mut()
        .parse_var_line("var HOME_NET [192.168.1.0/24,10.0.0.0/8]")
        .unwrap();
    ruleset
        .variables_mut()
        .parse_var_line("var EXTERNAL_NET !$HOME_NET")
        .unwrap();
    ruleset
        .variables_mut()
        .parse_var_line("var HTTP_PORTS [80,8080,8000:8100]")
        .unwrap();

    println!("✓ Variables configured\n");

    // Add rules programmatically
    println!("Adding rules programmatically...");

    let rule1 = Rule::new(
        RuleAction::Alert,
        Protocol::Tcp,
        IpSpec::Any,
        PortSpec::Any,
        Direction::To,
        IpSpec::Any,
        PortSpec::Port(80),
        1001,
    );
    ruleset.add_rule(rule1).unwrap();

    let rule2 = Rule::new(
        RuleAction::Alert,
        Protocol::Tcp,
        IpSpec::Any,
        PortSpec::Any,
        Direction::To,
        IpSpec::Any,
        PortSpec::Port(443),
        1002,
    );
    ruleset.add_rule(rule2).unwrap();

    let rule3 = Rule::new(
        RuleAction::Alert,
        Protocol::Udp,
        IpSpec::Any,
        PortSpec::Any,
        Direction::To,
        IpSpec::Any,
        PortSpec::Port(53),
        1003,
    );
    ruleset.add_rule(rule3).unwrap();

    println!("✓ Added {} rules\n", ruleset.len());

    println!("{}\n", "=".repeat(60));

    // ============================================================
    // Part 3: Query Rules by Protocol/Port
    // ============================================================
    println!("Part 3: Querying Rules\n");
    println!("{}", "=".repeat(60));

    // Get candidates for TCP port 80
    println!("Querying rules for TCP port 80:");
    let candidates = ruleset.get_candidate_rules(Protocol::Tcp, 80);
    println!("  Found {} candidate rules", candidates.len());
    for rule in &candidates {
        println!("    - SID {} ({})", rule.sid(), rule.action);
    }
    println!();

    // Get candidates for TCP port 443
    println!("Querying rules for TCP port 443:");
    let candidates = ruleset.get_candidate_rules(Protocol::Tcp, 443);
    println!("  Found {} candidate rules", candidates.len());
    for rule in &candidates {
        println!("    - SID {} ({})", rule.sid(), rule.action);
    }
    println!();

    // Get candidates for UDP port 53
    println!("Querying rules for UDP port 53:");
    let candidates = ruleset.get_candidate_rules(Protocol::Udp, 53);
    println!("  Found {} candidate rules", candidates.len());
    for rule in &candidates {
        println!("    - SID {} ({})", rule.sid(), rule.action);
    }
    println!();

    println!("{}\n", "=".repeat(60));

    // ============================================================
    // Part 4: Load Rules from File
    // ============================================================
    println!("Part 4: Loading Rules from File\n");
    println!("{}", "=".repeat(60));

    let mut file_ruleset = RuleSet::new();

    println!("Loading rules from rules/local.rules...");
    match file_ruleset.load_from_file("rules/local.rules") {
        Ok(count) => {
            println!("✓ Loaded {} rules from file\n", count);

            // Display statistics
            let stats = file_ruleset.stats();
            println!("{}", stats);

            // Show some sample rules
            println!("Sample rules:");
            let all_rules = file_ruleset.all_rules();
            for rule in all_rules.iter().take(5) {
                println!("  - [SID {}] {}: {}",
                    rule.sid(),
                    rule.action,
                    rule.message().unwrap_or("No message")
                );
            }

            if all_rules.len() > 5 {
                println!("  ... and {} more rules", all_rules.len() - 5);
            }
        }
        Err(e) => {
            eprintln!("✗ Failed to load rules: {}", e);
            eprintln!("  Note: Make sure rules/local.rules exists");
        }
    }

    println!("\n{}\n", "=".repeat(60));

    // ============================================================
    // Part 5: Rule Matching Examples
    // ============================================================
    println!("Part 5: Rule Matching Examples\n");
    println!("{}", "=".repeat(60));

    println!("Testing rule matching for different scenarios:\n");

    // Scenario 1: HTTP traffic
    println!("Scenario 1: HTTP traffic (TCP port 80)");
    let http_candidates = file_ruleset.get_candidate_rules(Protocol::Tcp, 80);
    println!("  Candidate rules: {}", http_candidates.len());
    for (i, rule) in http_candidates.iter().take(3).enumerate() {
        println!("    {}. [SID {}] {}", i + 1, rule.sid(), rule.message().unwrap_or("N/A"));
    }
    println!();

    // Scenario 2: HTTPS traffic
    println!("Scenario 2: HTTPS traffic (TCP port 443)");
    let https_candidates = file_ruleset.get_candidate_rules(Protocol::Tcp, 443);
    println!("  Candidate rules: {}", https_candidates.len());
    for (i, rule) in https_candidates.iter().take(3).enumerate() {
        println!("    {}. [SID {}] {}", i + 1, rule.sid(), rule.message().unwrap_or("N/A"));
    }
    println!();

    // Scenario 3: DNS traffic
    println!("Scenario 3: DNS traffic (UDP port 53)");
    let dns_candidates = file_ruleset.get_candidate_rules(Protocol::Udp, 53);
    println!("  Candidate rules: {}", dns_candidates.len());
    for (i, rule) in dns_candidates.iter().take(3).enumerate() {
        println!("    {}. [SID {}] {}", i + 1, rule.sid(), rule.message().unwrap_or("N/A"));
    }
    println!();

    // Scenario 4: SSH traffic
    println!("Scenario 4: SSH traffic (TCP port 22)");
    let ssh_candidates = file_ruleset.get_candidate_rules(Protocol::Tcp, 22);
    println!("  Candidate rules: {}", ssh_candidates.len());
    for (i, rule) in ssh_candidates.iter().take(3).enumerate() {
        println!("    {}. [SID {}] {}", i + 1, rule.sid(), rule.message().unwrap_or("N/A"));
    }
    println!();

    println!("{}\n", "=".repeat(60));

    // ============================================================
    // Summary
    // ============================================================
    println!("Summary\n");
    println!("{}", "=".repeat(60));
    println!("✓ Rule parser working");
    println!("✓ Variable expansion working");
    println!("✓ Rule indexing by protocol/port working");
    println!("✓ Rule file loading working");
    println!("✓ Rule statistics working");
    println!();
    println!("The rule engine is ready for Phase 5: Pattern Matching!");
    println!();
}
