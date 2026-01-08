use std::{env::current_dir, fs::create_dir_all, path::Path, io::Write};

use anyhow::{bail, Context, Result};

pub fn fuzz_init(program_name: &str) -> Result<()> {
    // Check program exists
    let cwd = current_dir()?;
    let program_path = cwd.join("programs").join(program_name);
    if !program_path.exists() {
        bail!("{} does not exist", program_path.display());
    }
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
    let anchor_dir = std::env::var("ANCHOR_DIR").expect("set `ANCHOR_DIR` to Anchor source path");
    format!(
        r#"[package]
name = "{program_name}_fuzz"
version = "0.1.0"
edition = "2021"

[workspace]
# Standalone workspace - isolated from parent project to avoid Solana version conflicts

[dependencies]
# Fuzzing framework
anchor-test = {{ path = "{anchor_dir}/fuzz/anchor-test" }}
anchor-test-context = {{ path = "{anchor_dir}/fuzz/anchor-test/anchor-test-context" }}
anchor-fuzz-gen = {{ path = "{anchor_dir}/fuzz/anchor-test/anchor-fuzz-gen" }}

# Anchor (local v3-compatible)
anchor-lang = {{ path = "{anchor_dir}/lang" }}

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

pub fn fuzz_run(program_name: &str, test_name: &str, release: bool) -> Result<()> {
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

    // Run cargo from the fuzz directory (standalone workspace)
    // This ensures artifacts go to fuzz/<program>/target/ instead of root target/
    // Set RUSTUP_TOOLCHAIN=stable to ensure modern Rust is used (libafl requires edition 2024)
    let status = std::process::Command::new("cargo")
        .current_dir(&fuzz_dir)
        .env("RUSTUP_TOOLCHAIN", "stable")
        .args(&args)
        .status()
        .context("Failed to run cargo")?;

    if !status.success() {
        bail!("Fuzz command failed");
    }

    Ok(())
}

pub fn fuzz_show(program_name: &str, crash_file: &str) -> Result<()> {
    let cwd = current_dir()?;
    let fuzz_dir = cwd.join("fuzz").join(program_name);

    if !fuzz_dir.exists() {
        bail!(
            "Fuzz directory for {} does not exist. Run `anchor fuzz init {}` first.",
            program_name,
            program_name
        );
    }

    // Treat crash_file as a path (absolute or relative to cwd)
    let crash_path = Path::new(crash_file);
    let crash_path = if crash_path.is_absolute() {
        crash_path.to_path_buf()
    } else {
        cwd.join(crash_path)
    };

    if !crash_path.exists() {
        bail!("Crash file {} does not exist", crash_path.display());
    }

    let crash_bytes =
        std::fs::read(&crash_path).context("Failed to read crash file")?;

    // Find the fuzz binary in standalone workspace target directory
    // Binary is in fuzz/<program>/target/ (not root target/)
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

    // Run with SHOW_CRASH=1
    let mut child = std::process::Command::new(binary_path)
        .env("SHOW_CRASH", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .context("Failed to spawn show process")?;

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&crash_bytes)
        .context("Failed to write crash data to stdin")?;

    let status = child.wait().context("Failed to wait for show process")?;

    if !status.success() {
        bail!("Show command failed");
    }

    Ok(())
}
