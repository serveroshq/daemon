//! `serveros-release`: the CI side of signed releases.
//!
//! ```text
//! serveros-release keygen --out release.key          # once; keep the private half in CI secrets
//! serveros-release sign --key release.key --file serverosd-1.2.0-linux-amd64
//! serveros-release manifest --version 1.2.0 --channel stable --min-from 1.0.0 \
//!     --url https://releases.serveros.com/1.2.0/serverosd-1.2.0-linux-amd64 \
//!     --file serverosd-1.2.0-linux-amd64 --key release.key > manifest-amd64.json
//! ```
//!
//! The public half is baked into the daemon at build time via
//! `SERVEROS_RELEASE_PUBKEY` (hex), so a daemon only ever installs what
//! this key signed.

use std::path::PathBuf;

use base64::Engine;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(name = "serveros-release")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a signing keypair. Prints the public key (hex) to embed.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a binary; prints the base64 signature.
    Sign {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        file: PathBuf,
    },
    /// Print the public key (hex) for a private key file.
    Pubkey {
        #[arg(long)]
        key: PathBuf,
    },
    /// Write the release manifest the daemon's update check consumes.
    Manifest {
        #[arg(long)]
        version: String,
        #[arg(long, default_value = "stable")]
        channel: String,
        #[arg(long)]
        min_from: Option<String>,
        #[arg(long)]
        url: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        notes_url: Option<String>,
    },
}

fn load_key(path: &PathBuf) -> anyhow::Result<SigningKey> {
    let hex_key = std::fs::read_to_string(path)?;
    let bytes: [u8; 32] = hex::decode(hex_key.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("key file must hold 32 hex-encoded bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Keygen { out } => {
            let key = SigningKey::generate(&mut rand::rngs::OsRng);
            std::fs::write(&out, hex::encode(key.to_bytes()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600))?;
            }
            println!(
                "private key written to {} (keep it in CI secrets, never in the repo)",
                out.display()
            );
            println!(
                "public key (SERVEROS_RELEASE_PUBKEY): {}",
                hex::encode(key.verifying_key().to_bytes())
            );
        }
        Command::Pubkey { key } => println!(
            "{}",
            hex::encode(load_key(&key)?.verifying_key().to_bytes())
        ),
        Command::Sign { key, file } => {
            let bytes = std::fs::read(&file)?;
            let signature = load_key(&key)?.sign(&bytes);
            println!(
                "{}",
                base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
            );
        }
        Command::Manifest {
            version,
            channel,
            min_from,
            url,
            file,
            key,
            notes_url,
        } => {
            let bytes = std::fs::read(&file)?;
            let signature = load_key(&key)?.sign(&bytes);
            let manifest = serde_json::json!({
                "version": version,
                "channel": channel,
                "min_from": min_from,
                "url": url,
                "sha256": hex::encode(Sha256::digest(&bytes)),
                "signature": base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
                "notes_url": notes_url,
            });
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
    }

    Ok(())
}
