use std::{env::current_dir, fs::create_dir, path::Path, io::Write};

use anyhow::{bail, Context, Result};
use toml_edit::DocumentMut;

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
/// 2. Add `fuzz/*` to `workspace.members``
/// Does nothing if already configured
fn configure_workspace_for_fuzzing(fuzz_dir: &Path) -> Result<()> {
    use toml_edit::{Item, Value};
    if !fuzz_dir.exists() {
        create_dir(&fuzz_dir)?;
        std::fs::write(fuzz_dir.join(".gitignore"), "/target\n/crashes\n")
            .context("Failed to create .gitignore")?;
        let toml_str =
            std::fs::read_to_string("Cargo.toml").context("Failed to read workspace Cargo.toml")?;
        let mut toml: DocumentMut = toml_str
            .parse()
            .context("Failed to parse workspace Cargo.toml")?;
        let Item::Table(workspace) = toml
            .entry("workspace")
            .or_insert(Item::Table(Default::default()))
        else {
            bail!("`workspace` is not a table")
        };
        let Item::Value(Value::Array(members)) = workspace
            .entry("members")
            .or_insert(Item::Value(Value::Array(Default::default())))
        else {
            bail!("`workspace.members` is not an array")
        };
        if !members.iter().any(|m| m.as_str() == Some("fuzz/*")) {
            members.push("fuzz/*");
        }
        std::fs::write("Cargo.toml", toml.to_string()).context("Failed to write new Cargo.toml")?;
    }
    Ok(())
}

/// Create `<program_name>/fuzz` package
fn initialize_program_fuzzer(fuzz_dir: &Path, program_name: &str) -> Result<()> {
    let fuzz_program_path = fuzz_dir.join(program_name);
    if fuzz_program_path.exists() {
        bail!("{} already exists", fuzz_program_path.display());
    }
    create_dir(&fuzz_program_path)
        .with_context(|| format!("Failed to create {}", fuzz_program_path.display()))?;
    std::fs::write(
        fuzz_program_path.join("Cargo.toml"),
        fuzz_target_manifest(program_name),
    )
    .context("Failed to write fuzz Cargo.toml")?;

    let src_dir = fuzz_program_path.join("src");
    create_dir(&src_dir).with_context(|| format!("Failed to create {}", src_dir.display()))?;
    std::fs::write(
        src_dir.join("main.rs"),
        &generate_program_fuzz_harness(program_name),
    )
    .context("Failed to write fuzz harness")?;
    Ok(())
}

fn generate_program_fuzz_harness(program_name: &str) -> String {
    format!(
        r#"use {program_name}::*;
use anchor_test::*;
use solana_sdk::{{signature::Keypair, system_program, pubkey::Pubkey, signature::Signer}};
use std::rc::Rc;

#[derive(Clone)]
struct {fixture_name} {{
    ctx: TestContext,
    program_id: Pubkey,
    // TODO: Add your state here (users, accounts, etc.)
}}

#[fuzz_fixture]
impl {fixture_name} {{
    /// Called ONCE to setup initial state (programs + accounts)
    pub fn setup() -> Self {{
        let mut ctx = TestContext::new();
        let program_id = Pubkey::new_from_array(ID.to_bytes());
        
        // Load program
        ctx.add_program(&program_id, "target/deploy/{program_name}.so").unwrap();
        
        // TODO: Initialize your program state here
        // Example:
        // let user = Rc::new(Keypair::new());
        // ctx.create_account()
        //     .pubkey(user.pubkey())
        //     .lamports(1_000_000_000)
        //     .owner(system_program::id())
        //     .create()
        //     .unwrap();
        
        Self {{ ctx, program_id }}
    }}

    /// ACTIONS - Define actions that the fuzzer can call
    
    // TODO: Add your actions here
    // Example action:
    // pub fn action_do_something(&mut self, amount: u64) {{
    //     let _ = self.ctx.program(self.program_id)
    //         .call(instruction::DoSomething {{ amount }})
    //         .accounts(accounts::DoSomething {{ /* ... */ }})
    //         .signers(&[/* ... */])
    //         .send();
    // }}
}}

#[test]
fn test_basic() {{
    let fixture = {fixture_name}::setup();
    // TODO: Add basic test assertions
}}

// Simple single-input fuzz test
#[anchor_fuzz]
fn fuzz_single(fixture: &mut {fixture_name}, amount: u64) {{
    // TODO: Call your actions with the fuzzed input
    // Example: fixture.action_do_something(amount);
}}

// Stateful invariant test - fuzzer generates random action sequences
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

[dependencies]
anchor-test = {{ path = "{anchor_dir}/fuzz/anchor-test" }}
anchor-test-context = {{ path = "{anchor_dir}/fuzz/anchor-test/anchor-test-context" }}
anchor-lang = {{ path = "{anchor_dir}/lang" }}
arbitrary = {{ version = "1", features = ["derive"] }}
libafl = {{ version = "0.15.1", features = ["std", "cli", "prelude", "tui_monitor"] }}
libafl_bolts = {{ version = "0.15.1", features = ["std"] }}
solana-message = "2.3"
solana-sdk = "2.3"

{program_name} = {{ path = "../../programs/{program_name}", features = ["no-entrypoint"] }}

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
        bail!("Fuzz directory for {} does not exist. Run `anchor fuzz init {}` first.", program_name, program_name);
    }
    
    let mut args = vec![
        "run".to_string(),
        "--manifest-path".to_string(),
        fuzz_dir.join("Cargo.toml").to_string_lossy().to_string(),
        "--features".to_string(),
        test_name.to_string(),
    ];
    
    if release {
        args.insert(1, "--release".to_string());
    }
    
    let status = std::process::Command::new("cargo")
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
        bail!("Fuzz directory for {} does not exist. Run `anchor fuzz init {}` first.", program_name, program_name);
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
    
    let crash_bytes = std::fs::read(&crash_path)
        .context("Failed to read crash file")?;
    
    // Find the fuzz binary (check both debug and release)
    let package_name = format!("{}_fuzz", program_name);
    let binary_path = cwd
        .join("target")
        .join("release")
        .join(&package_name);
    
    let binary_path = if binary_path.exists() {
        binary_path
    } else {
        cwd.join("target").join("debug").join(&package_name)
    };
    
    if !binary_path.exists() {
        bail!(
            "Fuzz binary not found. Build it first with: anchor fuzz run {} <test_name>",
            program_name
        );
    }
    
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
