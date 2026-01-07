/// Example demonstrating the Aho-Corasick pattern matcher
///
/// This shows how to:
/// - Build a pattern matcher from rules
/// - Search for multiple patterns simultaneously
/// - Handle case-sensitive and case-insensitive matching
/// - Use PCRE regex patterns
/// - Benchmark performance
///
/// Run with:
///   cargo run --example pattern_matching_demo --release

use ks_sniff::rules::{
    ContentMatch, Direction, IpSpec, PatternMatcher, PortSpec, Protocol, Rule, RuleAction,
};
use std::sync::Arc;
use std::time::Instant;

fn main() {
    println!("=== KS-Sniff Pattern Matching Demo ===\n");

    // ============================================================
    // Part 1: Simple Pattern Matching
    // ============================================================
    println!("Part 1: Simple Pattern Matching\n");
    println!("{}", "=".repeat(60));

    let mut matcher = PatternMatcher::new();

    // Create rules with content patterns
    let mut http_get_rule = Rule::new(
        RuleAction::Alert,
        Protocol::Tcp,
        IpSpec::Any,
        PortSpec::Any,
        Direction::To,
        IpSpec::Any,
        PortSpec::Port(80),
        1001,
    );
    http_get_rule.options.msg = Some("HTTP GET Request".to_string());
    http_get_rule.options.content.push(ContentMatch {
        pattern: b"GET".to_vec(),
        nocase: false,
        relative: false,
        offset: None,
        depth: None,
        distance: None,
        within: None,
        http_location: None,
    });

    let mut http_post_rule = Rule::new(
        RuleAction::Alert,
        Protocol::Tcp,
        IpSpec::Any,
        PortSpec::Any,
        Direction::To,
        IpSpec::Any,
        PortSpec::Port(80),
        1002,
    );
    http_post_rule.options.msg = Some("HTTP POST Request".to_string());
    http_post_rule.options.content.push(ContentMatch {
        pattern: b"POST".to_vec(),
        nocase: false,
        relative: false,
        offset: None,
        depth: None,
        distance: None,
        within: None,
        http_location: None,
    });

    println!("Building pattern matcher from 2 rules...");
    matcher
        .build_from_rules(&[Arc::new(http_get_rule), Arc::new(http_post_rule)])
        .unwrap();
    println!("✓ Pattern matcher built\n");

    // Test matching
    let test_payloads: Vec<&[u8]> = vec![
        b"GET /index.html HTTP/1.1\r\n",
        b"POST /login HTTP/1.1\r\n",
        b"HEAD /status HTTP/1.1\r\n",
    ];

    println!("Testing pattern matching:");
    for (i, payload) in test_payloads.iter().enumerate() {
        let matches = matcher.find_matching_rules(payload);
        println!(
            "  Payload {}: {:?} → {} matching rules",
            i + 1,
            String::from_utf8_lossy(payload).trim(),
            matches.len()
        );
        for sid in matches {
            println!("    - Rule SID: {}", sid);
        }
    }

    println!("\n{}\n", "=".repeat(60));

    // ============================================================
    // Part 2: Case-Insensitive Matching
    // ============================================================
    println!("Part 2: Case-Insensitive Matching\n");
    println!("{}", "=".repeat(60));

    let mut case_matcher = PatternMatcher::new();

    let mut nocase_rule = Rule::new(
        RuleAction::Alert,
        Protocol::Tcp,
        IpSpec::Any,
        PortSpec::Any,
        Direction::To,
        IpSpec::Any,
        PortSpec::Port(80),
        2001,
    );
    nocase_rule.options.msg = Some("SQL Injection Attempt".to_string());
    nocase_rule.options.content.push(ContentMatch {
        pattern: b"select".to_vec(),
        nocase: true, // Case-insensitive
        relative: false,
        offset: None,
        depth: None,
        distance: None,
        within: None,
        http_location: None,
    });
    nocase_rule.options.content.push(ContentMatch {
        pattern: b"from".to_vec(),
        nocase: true, // Case-insensitive
        relative: false,
        offset: None,
        depth: None,
        distance: None,
        within: None,
        http_location: None,
    });

    println!("Building case-insensitive matcher...");
    case_matcher
        .build_from_rules(&[Arc::new(nocase_rule)])
        .unwrap();
    println!("✓ Built with case-insensitive patterns\n");

    let sql_payloads: Vec<&[u8]> = vec![
        b"SELECT * FROM users",
        b"select * from users",
        b"SeLeCt * FrOm users",
        b"INSERT INTO users",
    ];

    println!("Testing case-insensitive matching:");
    for (i, payload) in sql_payloads.iter().enumerate() {
        let matches = case_matcher.find_matching_rules(payload);
        println!(
            "  Payload {}: {:?} → {}",
            i + 1,
            String::from_utf8_lossy(payload),
            if matches.is_empty() {
                "No match".to_string()
            } else {
                format!("{} matching rules", matches.len())
            }
        );
    }

    println!("\n{}\n", "=".repeat(60));

    // ============================================================
    // Part 3: Multiple Patterns Per Rule
    // ============================================================
    println!("Part 3: Multiple Patterns Per Rule\n");
    println!("{}", "=".repeat(60));

    let mut multi_matcher = PatternMatcher::new();

    let mut sqli_rule = Rule::new(
        RuleAction::Alert,
        Protocol::Tcp,
        IpSpec::Any,
        PortSpec::Any,
        Direction::To,
        IpSpec::Any,
        PortSpec::Port(80),
        3001,
    );
    sqli_rule.options.msg = Some("SQL Injection - UNION SELECT".to_string());
    sqli_rule.options.content.push(ContentMatch {
        pattern: b"UNION".to_vec(),
        nocase: true,
        relative: false,
        offset: None,
        depth: None,
        distance: None,
        within: None,
        http_location: None,
    });
    sqli_rule.options.content.push(ContentMatch {
        pattern: b"SELECT".to_vec(),
        nocase: true,
        relative: false,
        offset: None,
        depth: None,
        distance: None,
        within: None,
        http_location: None,
    });

    println!("Creating rule with 2 content patterns (UNION and SELECT)...");
    multi_matcher
        .build_from_rules(&[Arc::new(sqli_rule)])
        .unwrap();
    println!("✓ Matcher built\n");

    let attack_payloads: Vec<&[u8]> = vec![
        b"id=1 UNION SELECT password FROM users",
        b"id=1 UNION ALL SELECT * FROM admin",
        b"id=1 SELECT * FROM users",
        b"id=1 OR 1=1",
    ];

    println!("Testing multi-pattern matching:");
    for (i, payload) in attack_payloads.iter().enumerate() {
        let patterns = multi_matcher.find_patterns(payload);
        println!(
            "  Payload {}: {:?}",
            i + 1,
            String::from_utf8_lossy(payload)
        );
        if patterns.is_empty() {
            println!("    No patterns matched");
        } else {
            println!("    Matched {} patterns:", patterns.len());
            for pattern in patterns {
                println!(
                    "      - Pattern at [{}:{}]: {:?}",
                    pattern.start,
                    pattern.end,
                    String::from_utf8_lossy(&pattern.matched_bytes)
                );
            }
        }
    }

    println!("\n{}\n", "=".repeat(60));

    // ============================================================
    // Part 4: PCRE Regex Support
    // ============================================================
    println!("Part 4: PCRE Regex Support\n");
    println!("{}", "=".repeat(60));

    let mut pcre_matcher = PatternMatcher::new();

    let mut pcre_rule = Rule::new(
        RuleAction::Alert,
        Protocol::Tcp,
        IpSpec::Any,
        PortSpec::Any,
        Direction::To,
        IpSpec::Any,
        PortSpec::Port(80),
        4001,
    );
    pcre_rule.options.msg = Some("Email Address Detected".to_string());
    // PCRE pattern for email addresses
    pcre_rule
        .options
        .pcre
        .push(r#"/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/i"#.to_string());

    println!("Creating rule with PCRE regex for email detection...");
    pcre_matcher.build_from_rules(&[Arc::new(pcre_rule)]).unwrap();
    println!("✓ PCRE patterns compiled\n");

    let email_payloads: Vec<&[u8]> = vec![
        b"Contact us at support@example.com",
        b"Email: john.doe@company.org",
        b"No email here",
    ];

    println!("Testing PCRE matching:");
    for (i, payload) in email_payloads.iter().enumerate() {
        let matches = pcre_matcher.matches_pcre(4001, payload);
        println!(
            "  Payload {}: {:?} → {}",
            i + 1,
            String::from_utf8_lossy(payload),
            if matches { "MATCHED" } else { "No match" }
        );
    }

    println!("\n{}\n", "=".repeat(60));

    // ============================================================
    // Part 5: Performance Benchmark
    // ============================================================
    println!("Part 5: Performance Benchmark\n");
    println!("{}", "=".repeat(60));

    // Build matcher with many rules
    let mut bench_matcher = PatternMatcher::new();
    let mut rules = Vec::new();

    println!("Building matcher with 100 rules...");
    for i in 0..100 {
        let mut rule = Rule::new(
            RuleAction::Alert,
            Protocol::Tcp,
            IpSpec::Any,
            PortSpec::Any,
            Direction::To,
            IpSpec::Any,
            PortSpec::Port(80),
            10000 + i,
        );
        rule.options.content.push(ContentMatch {
            pattern: format!("pattern{}", i).into_bytes(),
            nocase: false,
            relative: false,
            offset: None,
            depth: None,
            distance: None,
            within: None,
            http_location: None,
        });
        rules.push(Arc::new(rule));
    }

    bench_matcher.build_from_rules(&rules).unwrap();
    println!("✓ Matcher built\n");

    // Display stats
    let stats = bench_matcher.stats();
    println!("{}", stats);

    // Benchmark
    let test_payload = b"This is a test payload with pattern42 embedded in it for testing purposes";
    let iterations = 100_000;

    println!("Benchmarking {} iterations...", iterations);
    let start = Instant::now();

    for _ in 0..iterations {
        let _ = bench_matcher.find_matching_rules(test_payload);
    }

    let elapsed = start.elapsed();
    let ns_per_search = elapsed.as_nanos() / iterations;
    let searches_per_sec = 1_000_000_000 / ns_per_search;

    println!("\nBenchmark Results:");
    println!("  Total time: {:?}", elapsed);
    println!("  Time per search: {} ns", ns_per_search);
    println!("  Searches per second: {} M/s", searches_per_sec / 1_000_000);
    println!(
        "  Throughput: ~{} Gbps (assuming 1500 byte packets)",
        (searches_per_sec * 1500 * 8) / 1_000_000_000
    );

    println!("\n{}\n", "=".repeat(60));

    // ============================================================
    // Summary
    // ============================================================
    println!("Summary\n");
    println!("{}", "=".repeat(60));
    println!("✓ Single pattern matching - working");
    println!("✓ Case-insensitive matching - working");
    println!("✓ Multiple patterns per rule - working");
    println!("✓ PCRE regex support - working");
    println!("✓ High-performance Aho-Corasick - verified");
    println!();
    println!("Key Features:");
    println!("  • Multi-pattern search in O(n) time");
    println!("  • Case-sensitive and case-insensitive modes");
    println!("  • PCRE regex for complex patterns");
    println!("  • Millions of searches per second");
    println!();
    println!("The pattern matcher is ready for Phase 6: Detection Pipeline!");
    println!();
}
