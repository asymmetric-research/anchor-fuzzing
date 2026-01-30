use std::{env::current_dir, fs::create_dir_all, path::Path};

use anyhow::{bail, Context, Result};
use serde::{Serialize, Deserialize};

/// Crash metadata from .meta.json files
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrashMetadata {
    pub test_name: String,
    pub timestamp: String,
    pub iteration: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    pub actions: Vec<ActionRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionRecord {
    pub name: String,
    pub params: serde_json::Value,
    pub success: bool,
}

pub fn fuzz_init(program_name: &str) -> Result<()> {
    // Create fuzz harness - no check for programs/ directory
    // Works for Anchor, Pinochio, native Solana, or any other program
    let cwd = current_dir()?;
    let fuzz_dir = cwd.join("fuzz");
    configure_workspace_for_fuzzing(&fuzz_dir)?;
    initialize_program_fuzzer(&fuzz_dir, program_name)?;
    Ok(())
}

/// One-time function used to configure the workspace for fuzzing:
/// 1. Create `fuzz` and `fuzz/.gitignore`
///
/// NOTE: Fuzz harnesses are standalone workspaces to avoid Solana version conflicts.
/// We do NOT modify the parent Cargo.toml - each fuzz harness is independent.
fn configure_workspace_for_fuzzing(fuzz_dir: &Path) -> Result<()> {
    if !fuzz_dir.exists() {
        create_dir_all(&fuzz_dir)?;
        std::fs::write(fuzz_dir.join(".gitignore"), "*/target/\n*/crashes/\n")
            .context("Failed to create .gitignore")?;
    }
    Ok(())
}

/// Create standalone fuzz package for a program.
///
/// Creates:
/// - `fuzz/<program_name>/Cargo.toml` (with `[workspace]` for isolation)
/// - `fuzz/<program_name>/rust-toolchain.toml` (stable Rust)
/// - `fuzz/<program_name>/src/main.rs` (harness using anchor-fuzz-gen)
/// - `fuzz/<program_name>/idls/` (directory for IDL files)
fn initialize_program_fuzzer(fuzz_dir: &Path, program_name: &str) -> Result<()> {
    let fuzz_program_path = fuzz_dir.join(program_name);
    if fuzz_program_path.exists() {
        bail!("{} already exists", fuzz_program_path.display());
    }

    // Create src directory
    let src_dir = fuzz_program_path.join("src");
    create_dir_all(&src_dir)
        .with_context(|| format!("Failed to create {}", src_dir.display()))?;

    // Create idls directory
    let idls_dir = fuzz_program_path.join("idls");
    create_dir_all(&idls_dir)
        .with_context(|| format!("Failed to create {}", idls_dir.display()))?;

    // Write Cargo.toml (standalone workspace)
    std::fs::write(
        fuzz_program_path.join("Cargo.toml"),
        fuzz_target_manifest(program_name),
    )
    .context("Failed to write fuzz Cargo.toml")?;

    // Write rust-toolchain.toml
    std::fs::write(
        fuzz_program_path.join("rust-toolchain.toml"),
        fuzz_rust_toolchain(),
    )
    .context("Failed to write rust-toolchain.toml")?;

    // Write main.rs
    std::fs::write(
        src_dir.join("main.rs"),
        &generate_program_fuzz_harness(program_name),
    )
    .context("Failed to write fuzz harness")?;

    // Write IDL README
    std::fs::write(
        idls_dir.join("README.md"),
        fuzz_idls_readme(program_name),
    )
    .context("Failed to write IDL README")?;

    println!("\nCreated fuzz harness at: fuzz/{}/", program_name);
    println!("\nNext steps:");
    println!("  1. Copy your IDL to: fuzz/{}/idls/{}.json", program_name, program_name);
    println!("     (Run `anchor idl convert` if using legacy IDL format)");
    println!("  2. Ensure program binary exists at: target/deploy/{}.so", program_name);
    println!("  3. Implement action_* methods in: fuzz/{}/src/main.rs", program_name);
    println!("  4. Run: anchor fuzz run {} invariant_test", program_name);

    Ok(())
}

/// Rust toolchain configuration for fuzz harnesses.
/// Uses stable Rust to ensure compatibility with latest libafl.
fn fuzz_rust_toolchain() -> &'static str {
    r#"[toolchain]
channel = "stable"
# Fuzz harnesses require stable Rust for libafl compatibility
"#
}

/// README for the idls directory
fn fuzz_idls_readme(program_name: &str) -> String {
    format!(r#"# IDL Files

Place your program's IDL JSON file here as `{program_name}.json`.

## Generating IDL

If you have the legacy (v0.29) IDL format:
```bash
anchor idl convert target/idl/{program_name}.json -o fuzz/{program_name}/idls/{program_name}.json
```

If you have the new IDL format (v0.30+), copy it directly.

## Required Format

The IDL must have an `address` field at the root level:
```json
{{
  "address": "YourProgramIdHere...",
  "metadata": {{ ... }},
  "instructions": [ ... ],
  ...
}}
```

If your IDL only has the address in `metadata.address`, run `anchor idl convert` to fix it.
"#)
}

fn generate_program_fuzz_harness(program_name: &str) -> String {
    format!(
        r#"use anchor_test::*;
use anchor_lang::prelude::*;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_pubkey::Pubkey;
use anchor_lang::system_program;
use std::rc::Rc;

// Generate types from IDL (no crate dependency - avoids version conflicts)
anchor_fuzz_gen::declare_fuzz_program!("idls/{program_name}.json");

use {program_name}::instruction;
use {program_name}::accounts;

#[derive(Clone)]
struct {fixture_name} {{
    ctx: TestContext,
    program_id: Pubkey,
    admin: Rc<Keypair>,
    // TODO: Add your state here (users, accounts, etc.)
}}

#[fuzz_fixture]
impl {fixture_name} {{
    /// Called ONCE to setup initial state (programs + accounts)
    pub fn setup() -> Self {{
        let mut ctx = TestContext::new();
        let program_id = {program_name}::ID;

        // Load program binary (built separately from fuzz harness)
        ctx.add_program(&program_id, "../../target/deploy/{program_name}.so").unwrap();

        // Create admin account
        let admin = Rc::new(Keypair::new());
        ctx.create_account()
            .pubkey(admin.pubkey())
            .lamports(100_000_000_000)
            .owner(system_program::ID)
            .create()
            .unwrap();

        // TODO: Initialize your program state here

        Self {{ ctx, program_id, admin }}
    }}

    /// ACTIONS - Define actions that the fuzzer can call
    /// Must have at least one action_* method for the fuzzer to work

    pub fn action_noop(&mut self) {{
        // Placeholder - replace with real actions
    }}

    // TODO: Add your actions here
    // Example action:
    // pub fn action_do_something(&mut self, amount: u64) {{
    //     let _ = self.ctx.program(self.program_id)
    //         .call(instruction::DoSomething {{ amount }})
    //         .accounts(accounts::DoSomething {{ /* ... */ }})
    //         .signers(&[&self.admin])
    //         .send();
    // }}
}}

#[invariant_test]
fn invariant_test(fixture: &mut {fixture_name}) {{
    // TODO: Add invariant checks that should hold after every action
    // Example:
    // let total_balance = /* calculate total balance */;
    // assert!(total_balance <= INITIAL_BALANCE, "Balance invariant violated");
}}
"#,
        program_name = program_name,
        fixture_name = to_pascal_case(program_name)
    )
}

fn fuzz_target_manifest(program_name: &str) -> String {
    // Use GitHub repo for dependencies - no local ANCHOR_DIR needed
    let repo = "https://github.com/asymmetric-research/anchor-fuzzing";
    let branch = "feature/fuzzing";

    format!(
        r#"[package]
name = "{program_name}_fuzz"
version = "0.1.0"
edition = "2021"

[workspace]
# Standalone workspace - isolated from parent project to avoid Solana version conflicts

[dependencies]
# Fuzzing framework (from GitHub)
anchor-test = {{ git = "{repo}", branch = "{branch}", package = "anchor-test" }}
anchor-test-context = {{ git = "{repo}", branch = "{branch}", package = "anchor-test-context" }}
anchor-fuzz-gen = {{ git = "{repo}", branch = "{branch}", package = "anchor-fuzz-gen" }}

# Anchor (from GitHub - v3-compatible)
anchor-lang = {{ git = "{repo}", branch = "{branch}", package = "anchor-lang" }}

# Solana v3.x (required for litesvm 0.9.0)
solana-pubkey = "3.0"
solana-keypair = "3.1"
solana-signer = "3.0"
solana-program = "3.0"
solana-message = "3.0"
solana-signature = "3.1"
solana-instruction = "3.1"

# Fuzzing
libafl = {{ version = "0.15.1", features = ["std", "cli", "prelude"] }}
libafl_bolts = {{ version = "0.15.1", features = ["std"] }}
arbitrary = {{ version = "1", features = ["derive"] }}

# Utilities
anyhow = "1.0"
bytemuck = "1.14"

[features]
fuzz_single = []
invariant_test = []
"#
    )
}

fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect()
}

pub fn fuzz_run(
    program_name: &str,
    test_name: &str,
    release: bool,
    coverage: bool,
    timeout: Option<u64>,
    corpus_in: Option<std::path::PathBuf>,
    corpus_out: Option<std::path::PathBuf>,
    crashes_dir: Option<std::path::PathBuf>,
    input: Option<std::path::PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let cwd = current_dir()?;
    let fuzz_dir = cwd.join("fuzz").join(program_name);

    if !fuzz_dir.exists() {
        bail!(
            "Fuzz directory for {} does not exist. Run `anchor fuzz init {}` first.",
            program_name,
            program_name
        );
    }

    let mut args = vec!["run".to_string()];

    if release {
        args.push("--release".to_string());
    }

    args.extend(["--features".to_string(), test_name.to_string()]);

    // Use `--` to pass arguments to the binary
    if coverage {
        args.push("--".to_string());
        args.push("--coverage".to_string());
    }

    // Build the command
    let mut cmd = std::process::Command::new("cargo");
    cmd.current_dir(&fuzz_dir)
        .env("RUSTUP_TOOLCHAIN", "stable")
        .args(&args);

    // Set timeout environment variable if specified
    if let Some(timeout_secs) = timeout {
        cmd.env("FUZZ_TIMEOUT_SECS", timeout_secs.to_string());
        println!("[FUZZ] Running with {}s timeout", timeout_secs);
    }

    // Set corpus input directory
    if let Some(ref corpus_in_path) = corpus_in {
        // Convert to absolute path relative to cwd (not fuzz_dir)
        let abs_path = if corpus_in_path.is_absolute() {
            corpus_in_path.clone()
        } else {
            cwd.join(corpus_in_path)
        };
        cmd.env("FUZZ_CORPUS_IN", abs_path);
        println!("[FUZZ] Loading corpus from: {}", corpus_in_path.display());
    }

    // Set corpus output directory
    if let Some(ref corpus_out_path) = corpus_out {
        let abs_path = if corpus_out_path.is_absolute() {
            corpus_out_path.clone()
        } else {
            cwd.join(corpus_out_path)
        };
        cmd.env("FUZZ_CORPUS_OUT", abs_path);
        println!("[FUZZ] Writing corpus to: {}", corpus_out_path.display());
    }

    // Set crashes directory
    if let Some(ref crashes_path) = crashes_dir {
        let abs_path = if crashes_path.is_absolute() {
            crashes_path.clone()
        } else {
            cwd.join(crashes_path)
        };
        cmd.env("FUZZ_CRASHES_DIR", abs_path);
        println!("[FUZZ] Writing crashes to: {}", crashes_path.display());
    }

    // Set single input file for replay
    if let Some(ref input_path) = input {
        let abs_path = if input_path.is_absolute() {
            input_path.clone()
        } else {
            cwd.join(input_path)
        };
        cmd.env("FUZZ_INPUT_FILE", abs_path);
        println!("[FUZZ] Replaying input: {}", input_path.display());
    }

    // Set dry-run mode
    if dry_run {
        cmd.env("FUZZ_DRY_RUN", "1");
        println!("[FUZZ] Dry-run mode: validating setup");
    }

    // Coverage-only mode: when --coverage and --corpus-in are set but no fuzzing is implied
    // (no timeout means run coverage on corpus and exit)
    if coverage && corpus_in.is_some() && timeout.is_none() && !dry_run && input.is_none() {
        cmd.env("FUZZ_COVERAGE_ONLY", "1");
        println!("[FUZZ] Coverage-only mode: generating coverage from corpus");
    }

    // Run cargo from the fuzz directory (standalone workspace)
    // This ensures artifacts go to fuzz/<program>/target/ instead of root target/
    // Set RUSTUP_TOOLCHAIN=stable to ensure modern Rust is used (libafl requires edition 2024)
    let status = cmd.status().context("Failed to run cargo")?;

    if !status.success() {
        bail!("Fuzz command failed");
    }

    Ok(())
}

/// List available fuzz tests for a program by parsing Cargo.toml features.
///
/// If program_name is None, lists all fuzz harnesses in fuzz/ directory.
pub fn fuzz_list(program_name: Option<&str>) -> Result<()> {
    let cwd = current_dir()?;
    let fuzz_root = cwd.join("fuzz");

    match program_name {
        Some(name) => {
            // List tests for a specific program
            let fuzz_dir = fuzz_root.join(name);
            if !fuzz_dir.exists() {
                bail!(
                    "Fuzz directory for {} does not exist. Run `anchor fuzz init {}` first.",
                    name, name
                );
            }
            list_program_tests(&fuzz_dir, name)?;
        }
        None => {
            // List all fuzz harnesses
            if !fuzz_root.exists() {
                println!("No fuzz/ directory found. Run `anchor fuzz init <program>` to create one.");
                return Ok(());
            }

            let mut found = false;
            for entry in std::fs::read_dir(&fuzz_root)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() && path.join("Cargo.toml").exists() {
                    let name = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");
                    found = true;
                    list_program_tests(&path, name)?;
                }
            }

            if !found {
                println!("No fuzz harnesses found in fuzz/ directory.");
            }
        }
    }

    Ok(())
}

/// List available fuzz tests for a single program by parsing its Cargo.toml features.
fn list_program_tests(fuzz_dir: &Path, program_name: &str) -> Result<()> {
    let cargo_toml_path = fuzz_dir.join("Cargo.toml");

    if !cargo_toml_path.exists() {
        bail!("Cargo.toml not found at {}", cargo_toml_path.display());
    }

    let content = std::fs::read_to_string(&cargo_toml_path)
        .context("Failed to read Cargo.toml")?;

    // Parse features from Cargo.toml
    // Look for [features] section and extract feature names
    let mut in_features = false;
    let mut tests = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "[features]" {
            in_features = true;
            continue;
        }

        // Exit features section when we hit another section
        if in_features && trimmed.starts_with('[') && !trimmed.starts_with("[features") {
            break;
        }

        if in_features && !trimmed.is_empty() && !trimmed.starts_with('#') {
            // Parse feature definition: feature_name = [...]
            if let Some(eq_pos) = trimmed.find('=') {
                let feature_name = trimmed[..eq_pos].trim();
                // Filter out common non-test features
                if !feature_name.is_empty()
                    && feature_name != "default"
                    && feature_name != "fuzz_single"
                {
                    tests.push(feature_name.to_string());
                }
            }
        }
    }

    println!("\n=== {} ===", program_name);
    if tests.is_empty() {
        println!("  No fuzz tests found (add features to Cargo.toml)");
    } else {
        for test in &tests {
            println!("  - {}", test);
        }
        println!();
        println!("Run with: anchor fuzz run {} <test_name> --release", program_name);
    }

    Ok(())
}

/// Show crash information.
///
/// - No crash_file: List all crashes with metadata
/// - crash_file without --replay: Display crash metadata from .meta.json
/// - crash_file with --replay: Actually replay the crash (requires binary)
pub fn fuzz_show(program_name: &str, crash_file: Option<&str>, replay: bool, _original_cwd: Option<&Path>) -> Result<()> {
    let cwd = current_dir()?;

    // Detect fuzz directory - support running from:
    // 1. Inside fuzz harness dir: crashes/ exists in current directory
    // 2. Project root: fuzz/<program>/ exists
    // 3. "." as program_name: auto-detect from current directory
    let (fuzz_dir, display_name) = if program_name == "." {
        // Auto-detect from current directory
        if cwd.join("crashes").exists() || (cwd.join("Cargo.toml").exists() && cwd.join("src").exists()) {
            let name = cwd.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            (cwd.clone(), name)
        } else {
            bail!("Cannot auto-detect fuzz harness. Run from within fuzz harness directory or specify program name.");
        }
    } else if cwd.join("crashes").exists() {
        // Already in a fuzz harness directory
        (cwd.clone(), program_name.to_string())
    } else {
        // Try project root layout: fuzz/<program>/
        let fuzz_path = cwd.join("fuzz").join(program_name);
        if fuzz_path.exists() {
            (fuzz_path, program_name.to_string())
        } else {
            bail!(
                "Fuzz directory not found. Either:\n  \
                 - Run from project root (where fuzz/{0}/ exists)\n  \
                 - Run from inside the fuzz harness directory\n  \
                 - Use '.' as program name to auto-detect",
                program_name
            );
        }
    };

    match crash_file {
        None => {
            // List all crashes
            list_crashes(&fuzz_dir, &display_name)?;
        }
        Some(crash_name) if !replay => {
            // Show metadata from .meta.json (no compilation needed)
            show_crash_metadata(&fuzz_dir, &display_name, crash_name)?;
        }
        Some(crash_name) => {
            // Replay the crash (needs binary)
            replay_crash(&fuzz_dir, &display_name, crash_name)?;
        }
    }

    Ok(())
}

/// List all crashes found in crashes/ directory
fn list_crashes(fuzz_dir: &Path, program_name: &str) -> Result<()> {
    let crashes_dir = fuzz_dir.join("crashes");

    if !crashes_dir.exists() {
        println!("No crashes directory found. Run the fuzzer first.");
        return Ok(());
    }

    // Find all .meta.json files in crashes/*/
    let mut crashes = Vec::new();

    for entry in std::fs::read_dir(&crashes_dir)? {
        let entry = entry?;
        let test_dir = entry.path();
        if !test_dir.is_dir() {
            continue;
        }

        let test_name = test_dir.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        for file_entry in std::fs::read_dir(&test_dir)? {
            let file_entry = file_entry?;
            let file_path = file_entry.path();
            // Look for .meta.json files
            let filename = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if filename.ends_with(".meta.json") {
                if let Ok(content) = std::fs::read_to_string(&file_path) {
                    if let Ok(meta) = serde_json::from_str::<CrashMetadata>(&content) {
                        // Extract crash_id by removing .meta.json suffix
                        let crash_id = filename.strip_suffix(".meta.json").unwrap_or(filename).to_string();
                        crashes.push((crash_id, test_name.clone(), meta));
                    }
                }
            }
        }
    }

    if crashes.is_empty() {
        println!("No crashes found for {}.", program_name);
        return Ok(());
    }

    // Sort by timestamp (newest first)
    crashes.sort_by(|a, b| b.2.timestamp.cmp(&a.2.timestamp));

    println!("\n=== Crashes for {} ({} total) ===\n", program_name, crashes.len());
    for (i, (crash_id, test_name, meta)) in crashes.iter().enumerate() {
        println!(
            "  {}. {} ({}, test: {}, {} actions)",
            i + 1,
            crash_id,
            meta.timestamp,
            test_name,
            meta.actions.len()
        );
    }
    println!();
    println!("To view a crash: anchor fuzz show {} <crash_id>", program_name);
    println!("To replay a crash: anchor fuzz show {} <crash_id> --replay", program_name);

    Ok(())
}

/// Show crash metadata from .meta.json (no compilation needed)
fn show_crash_metadata(fuzz_dir: &Path, program_name: &str, crash_name: &str) -> Result<()> {
    // Find the .meta.json file
    let crashes_dir = fuzz_dir.join("crashes");

    // Search in all test directories
    let mut meta_path = None;
    for entry in std::fs::read_dir(&crashes_dir).unwrap_or_else(|_| {
        std::fs::read_dir(".").unwrap() // Fallback to avoid panic
    }) {
        if let Ok(entry) = entry {
            let test_dir = entry.path();
            if !test_dir.is_dir() {
                continue;
            }

            let candidate = test_dir.join(format!("{}.meta.json", crash_name));
            if candidate.exists() {
                meta_path = Some(candidate);
                break;
            }
        }
    }

    let meta_path = meta_path.ok_or_else(|| {
        anyhow::anyhow!(
            "Crash metadata not found: {}.meta.json\n\
             Looking in: {}/crashes/*/\n\
             Use `anchor fuzz show {}` to list available crashes.",
            crash_name,
            fuzz_dir.display(),
            program_name
        )
    })?;

    let content = std::fs::read_to_string(&meta_path)
        .context("Failed to read crash metadata")?;
    let meta: CrashMetadata = serde_json::from_str(&content)
        .context("Failed to parse crash metadata")?;

    println!("\n=== Crash: {} ===", crash_name);
    println!("Test: {}", meta.test_name);
    println!("Timestamp: {}", meta.timestamp);
    println!("Iteration: {}", meta.iteration);
    if let Some(seed) = meta.seed {
        println!("Seed: {}", seed);
    }

    println!("\n=== Action Sequence ({} actions) ===", meta.actions.len());
    for (i, action) in meta.actions.iter().enumerate() {
        // Format params as key=value pairs
        let params_str = if let serde_json::Value::Object(map) = &action.params {
            map.iter()
                .map(|(k, v)| format!("{}={}", k, format_json_value_compact(v)))
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            String::new()
        };

        let status = if action.success { "OK" } else { "FAIL" };
        if params_str.is_empty() {
            println!("  {}. {} -> {}", i + 1, action.name, status);
        } else {
            println!("  {}. {}({}) -> {}", i + 1, action.name, params_str, status);
        }
    }
    println!("================================\n");

    println!("To replay this crash: anchor fuzz show {} {} --replay", program_name, crash_name);

    Ok(())
}

/// Format a JSON value compactly for display
fn format_json_value_compact(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => format!("\"{}\"", s),
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(format_json_value_compact).collect();
            format!("[{}]", items.join(", "))
        }
        serde_json::Value::Object(obj) => {
            let items: Vec<String> = obj.iter()
                .map(|(k, v)| format!("{}: {}", k, format_json_value_compact(v)))
                .collect();
            format!("{{{}}}", items.join(", "))
        }
    }
}

/// Replay a crash by running the binary with SHOW_CRASH=1
fn replay_crash(fuzz_dir: &Path, program_name: &str, crash_name: &str) -> Result<()> {
    // Find the crash file (binary data)
    let crashes_dir = fuzz_dir.join("crashes");

    // Search for the crash binary file in all test directories
    let mut crash_path = None;
    let mut found_metadata_only = false;
    let mut available_inputs: Vec<String> = Vec::new();

    for entry in std::fs::read_dir(&crashes_dir).unwrap_or_else(|_| {
        std::fs::read_dir(".").unwrap()
    }) {
        if let Ok(entry) = entry {
            let test_dir = entry.path();
            if !test_dir.is_dir() {
                continue;
            }

            // Try exact match first (new format: crash_<hash>)
            let candidate = test_dir.join(crash_name);
            if candidate.exists() && candidate.is_file() {
                crash_path = Some(candidate);
                break;
            }

            // Try with common extensions
            for ext in &["", ".bin"] {
                let candidate = test_dir.join(format!("{}{}", crash_name, ext));
                if candidate.exists() && candidate.is_file() {
                    crash_path = Some(candidate);
                    break;
                }
            }

            // Check if we have metadata but no input file (legacy crash)
            let meta_path = test_dir.join(format!("{}.meta.json", crash_name));
            if meta_path.exists() && crash_path.is_none() {
                found_metadata_only = true;

                // Collect available input files in this directory for the error message
                if let Ok(dir_entries) = std::fs::read_dir(&test_dir) {
                    for dir_entry in dir_entries.filter_map(|e| e.ok()) {
                        let path = dir_entry.path();
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            // Skip hidden files, metadata files
                            if !name.starts_with('.')
                                && !name.ends_with(".meta.json")
                                && !name.ends_with(".metadata")
                                && path.is_file()
                            {
                                available_inputs.push(name.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    let crash_path = crash_path.ok_or_else(|| {
        if found_metadata_only {
            let mut msg = format!(
                "Crash metadata found for '{}', but input bytes file is missing.\n\
                 This crash was created before input bytes were saved alongside metadata.\n\n",
                crash_name
            );
            if !available_inputs.is_empty() {
                msg.push_str("Available crash input files that can be replayed:\n");
                for (i, input) in available_inputs.iter().take(5).enumerate() {
                    msg.push_str(&format!("  {}. {}\n", i + 1, input));
                }
                if available_inputs.len() > 5 {
                    msg.push_str(&format!("  ... and {} more\n", available_inputs.len() - 5));
                }
                msg.push_str(&format!("\nTry: anchor fuzz show {} <input_name> --replay", program_name));
            }
            anyhow::anyhow!(msg)
        } else {
            anyhow::anyhow!(
                "Crash file not found: {}\n\
                 Looking in: {}/crashes/*/\n\
                 Use `anchor fuzz show {}` to list available crashes.",
                crash_name,
                fuzz_dir.display(),
                program_name
            )
        }
    })?;

    // Find the fuzz binary
    let package_name = format!("{}_fuzz", program_name);
    let release_binary = fuzz_dir
        .join("target")
        .join("release")
        .join(&package_name);
    let debug_binary = fuzz_dir
        .join("target")
        .join("debug")
        .join(&package_name);

    let binary_path = if release_binary.exists() {
        release_binary
    } else if debug_binary.exists() {
        debug_binary
    } else {
        bail!(
            "Fuzz binary not found at {} or {}.\n\
             Build it first with: anchor fuzz run {} <test_name>",
            release_binary.display(),
            debug_binary.display(),
            program_name
        );
    };

    println!("Replaying crash: {}", crash_path.display());
    println!("Using binary: {}\n", binary_path.display());

    // Run with FUZZ_INPUT_FILE to actually replay the crash (not just show the input)
    // Run from fuzz_dir so relative paths (like program.so) work correctly
    let status = std::process::Command::new(&binary_path)
        .current_dir(fuzz_dir)
        .env("FUZZ_INPUT_FILE", &crash_path)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .context("Failed to run replay")?;

    if !status.success() {
        // Exit code 1 means crash was reproduced (expected)
        if status.code() == Some(1) {
            println!("\nCrash successfully reproduced!");
        } else {
            bail!("Replay failed with exit code: {:?}", status.code());
        }
    } else {
        println!("\nReplay completed without crash.");
        println!("Note: If you expected a crash, the input may be from a different harness version.");
    }

    Ok(())
}
