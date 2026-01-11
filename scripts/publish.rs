//! Helper script to publish wsc crates to crates.io
//!
//! * `./publish verify` - verify crates can be published to crates.io
//! * `./publish publish` - actually publish crates to crates.io

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

// List of crates to publish in dependency order
const CRATES_TO_PUBLISH: &[&str] = &["wsc", "wsc-cli"];

struct Workspace {
    version: String,
}

struct Crate {
    manifest: PathBuf,
    name: String,
    version: String,
    publish: bool,
}

fn main() {
    let mut crates = Vec::new();

    // Read workspace version from root Cargo.toml
    let ws_version = std::fs::read_to_string("./Cargo.toml")
        .expect("failed to read workspace Cargo.toml")
        .lines()
        .find(|line| line.trim().starts_with("version ="))
        .expect("failed to find workspace version")
        .split('=')
        .nth(1)
        .expect("failed to parse workspace version")
        .trim()
        .trim_matches('"')
        .to_string();

    let ws = Workspace {
        version: ws_version,
    };

    // Add main library crate
    let lib_crate = read_crate(Some(&ws), "./src/lib/Cargo.toml".as_ref());
    crates.push(lib_crate);

    // Add CLI crate
    let cli_crate = read_crate(Some(&ws), "./src/cli/Cargo.toml".as_ref());
    crates.push(cli_crate);

    match &env::args().nth(1).expect("must have one argument")[..] {
        "publish" => {
            // Publish with retries for rate limiting/index propagation
            for _ in 0..10 {
                crates.retain(|krate| !publish(krate));

                if crates.is_empty() {
                    break;
                }

                println!(
                    "{} crates failed to publish, waiting to retry",
                    crates.len(),
                );
                thread::sleep(Duration::from_secs(40));
            }

            assert!(crates.is_empty(), "failed to publish all crates");

            println!("");
            println!("===================================================================");
            println!("");
            println!("Don't forget to push a git tag for this release!");
            println!("");
            println!("    $ git tag vX.Y.Z");
            println!("    $ git push origin vX.Y.Z");
        }

        "verify" => {
            verify(&crates);
        }

        s => panic!("unknown command: {}", s),
    }
}

fn read_crate(ws: Option<&Workspace>, manifest: &Path) -> Crate {
    let mut name = None;
    let mut version = None;
    let mut publish = true;

    let content = fs::read_to_string(manifest).expect("failed to read Cargo.toml");

    for line in content.lines() {
        let line = line.trim();

        // Parse name
        if name.is_none() && line.starts_with("name =") {
            if let Some(value) = line.split('=').nth(1) {
                let value = value.trim().trim_matches('"');
                name = Some(value.to_string());
            }
        }

        // Parse version
        if version.is_none() && line.starts_with("version =") {
            if let Some(value) = line.split('=').nth(1) {
                let value = value.trim();
                if value.starts_with('"') && value.ends_with('"') {
                    version = Some(value.trim_matches('"').to_string());
                }
            }
        } else if version.is_none() && line.trim() == "version.workspace = true" {
            if let Some(ws) = ws {
                version = Some(ws.version.clone());
            }
        }

        if line.starts_with("publish = false") {
            publish = false;
        }
    }

    let name = name.expect("failed to find crate name");
    let version = version.expect("failed to find crate version");

    Crate {
        manifest: manifest.to_path_buf(),
        name,
        version,
        publish,
    }
}

fn publish(krate: &Crate) -> bool {
    if !CRATES_TO_PUBLISH.iter().any(|s| *s == krate.name) {
        return true;
    }

    // Check if already published at this version
    let output = Command::new("curl")
        .arg(&format!("https://crates.io/api/v1/crates/{}", krate.name))
        .output()
        .expect("failed to invoke `curl`");

    if output.status.success()
        && String::from_utf8_lossy(&output.stdout)
            .contains(&format!("\"newest_version\":\"{}\"", krate.version))
    {
        println!(
            "skip publish {} because {} is latest version",
            krate.name, krate.version,
        );
        return true;
    }

    let status = Command::new("cargo")
        .arg("publish")
        .current_dir(krate.manifest.parent().unwrap())
        .arg("--no-verify")
        .status()
        .expect("failed to run cargo");

    if !status.success() {
        println!("FAIL: failed to publish `{}`: {}", krate.name, status);
        return false;
    }

    println!("✅ Successfully published {}@{}", krate.name, krate.version);
    true
}

// Verify the current tree is publish-able to crates.io
fn verify(crates: &[Crate]) {
    // Clean up any existing vendor directory
    let _ = fs::remove_dir_all("vendor");

    // Vendor dependencies for offline verification
    let vendor = Command::new("cargo")
        .arg("vendor")
        .stderr(Stdio::inherit())
        .output()
        .unwrap();

    if !vendor.status.success() {
        println!("Warning: cargo vendor failed, proceeding anyway");
    }

    for krate in crates {
        if !krate.publish {
            continue;
        }
        verify_crate(&krate);
    }
}

fn verify_crate(krate: &Crate) {
    let mut cmd = Command::new("cargo");
    cmd.arg("package")
        .arg("--allow-dirty")
        .arg("--manifest-path")
        .arg(&krate.manifest)
        .env("CARGO_TARGET_DIR", "./target");

    let status = cmd.status().unwrap();
    assert!(status.success(), "failed to verify {:?}", &krate.manifest);

    println!("✅ Verified {} can be packaged", krate.name);
}
