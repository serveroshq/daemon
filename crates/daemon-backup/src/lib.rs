use std::io::BufReader;
use std::path::Path;

use sha2::{Digest, Sha256};

pub mod remote;
pub mod retention;
pub mod snapshot;
pub mod strategy;

pub use snapshot::{Manifest, Snapshotter};
pub use strategy::Strategy;

pub const DEFAULT_RETENTION: usize = 7;

/// The reason a deploy's snapshot is taken with. They're kept apart from
/// backups, so deploying often doesn't push those out.
pub const PRE_DEPLOY: &str = "pre-deploy";

/// Pre-deploy snapshots kept per service.
pub const PRE_DEPLOY_RETENTION: usize = 3;

/// How much of a file is hashed at a time.
const HASH_CHUNK: usize = 256 * 1024;

/// A file's size and SHA-256 (hex), read a piece at a time on a blocking
/// thread. Backups are often far bigger than the daemon's memory ceiling,
/// so they must never be read whole.
pub async fn sha256_file(path: &Path) -> std::io::Result<(u64, String)> {
    let path = path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(&path)?;
        let mut reader = BufReader::with_capacity(HASH_CHUNK, file);
        let mut hasher = Sha256::new();
        let bytes = std::io::copy(&mut reader, &mut hasher)?;

        Ok((bytes, hex::encode(hasher.finalize())))
    })
    .await
    .map_err(std::io::Error::other)?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hashes_a_file_in_pieces_the_same_as_whole() {
        let body: Vec<u8> = (0..HASH_CHUNK * 3 + 5).map(|i| (i % 253) as u8).collect();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &body).unwrap();

        let (bytes, sha) = sha256_file(file.path()).await.unwrap();

        assert_eq!(bytes, body.len() as u64);
        assert_eq!(sha, hex::encode(Sha256::digest(&body)));
    }

    #[tokio::test]
    async fn a_missing_file_is_an_error() {
        assert!(sha256_file(Path::new("/nonexistent/backup.tar.gz"))
            .await
            .is_err());
    }
}
