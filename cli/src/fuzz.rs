use std::{env::current_dir, fs::create_dir, path::Path};

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
    let fuzzer = format!(
        r#"use anchor_test::anchor_fuzz;
use anchor_test_context::*;
use {program_name}::*;
use arbitrary::Arbitrary;
use solana_sdk::{{signature::Keypair, system_program, pubkey::Pubkey}};

struct Fixture<'a> {{
    ctx: &'a mut TestContext,
    program_id: Pubkey,
}}

impl<'a> Fixture<'a> {{
    pub fn setup(ctx: &'a mut TestContext) -> Self {{
        let program_id = Pubkey::new_from_array(program_name::ID.to_bytes());
        ctx.add_program(&program_id, "../../target/deploy/{program_name}.so").unwrap();

        // TODO: Initialize your program

        Self {{ ctx, program_id }}
    }}
}}

#[test]
fn test_basic() {{
    let mut ctx = TestContext::new();
    let fixture = Fixture::setup(&mut ctx);
}}

// TODO: Implement your fuzz test
#[anchor_fuzz]
fn fuzz_{program_name}(ctx: &mut TestContext, _data: Vec<u8>) {{
    let fixture = Fixture::setup(ctx);
}}"#
    );
    fuzzer
}

fn fuzz_target_manifest(program_name: &str) -> String {
    // TODO: Remove the below when our packages are upstreamed
    let anchor_dir = std::env::var("ANCHOR_DIR").expect("set `ANCHOR_DIR` to Anchor source path");
    format!(
        r#"[package]
name = "{program_name}_fuzz"
version = "0.1.0"
edition = "2021"

[dependencies]
solana-program = "2"
solana-sdk = "2"
anchor-test = {{ path = "{anchor_dir}/fuzz/anchor-test" }}
anchor-test-context = {{ path = "{anchor_dir}/fuzz/anchor-test/anchor-test-context" }}
anchor-lang = {{ path = "{anchor_dir}/lang" }}
arbitrary = {{ version = "1", features = ["derive"] }}
once_cell = "1"
libafl = {{ version = "0.13", features = ["std", "cli", "prelude"] }}
libafl_bolts = {{ version = "0.13", features = ["std"] }}
solana-message = "2"

{program_name} = {{ path = "../../programs/{program_name}", features = ["no-entrypoint"] }}
"#
    )
}
