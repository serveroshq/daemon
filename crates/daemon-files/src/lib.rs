//! Files, within the roots the broker permits. The broker decides whether
//! a path is allowed; this crate makes sure the path that is opened is the
//! path that was checked, which symlinks would otherwise defeat.
//!
//! Every operation resolves the real path first (`canonicalize` of the
//! parent plus the final component, without following a final symlink)
//! and re-checks it against the roots. Writes are atomic (temp + rename),
//! preceded by a disk-space check and, for existing files, a backup.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use daemon_capability::PermittedRoots;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FileError {
    #[error("{0} is outside the directories ServerOS may reach")]
    OutsideRoots(PathBuf),
    #[error("{0} resolves through a symlink to outside the permitted directories")]
    SymlinkEscape(PathBuf),
    #[error("{0} does not exist")]
    NotFound(PathBuf),
    #[error("{path} is {size} bytes, over the {limit} byte limit for this operation")]
    TooLarge {
        path: PathBuf,
        size: u64,
        limit: u64,
    },
    #[error("not enough free space on {mount}: {needed} bytes needed, {free} free")]
    DiskFull {
        mount: PathBuf,
        needed: u64,
        free: u64,
    },
    #[error("{0} is a directory; only files can be read")]
    IsDirectory(PathBuf),
    #[error("unknown user {0}")]
    UnknownUser(String),
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

pub type Result<T> = std::result::Result<T, FileError>;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: EntryKind,
    pub size: u64,
    pub mode: u32,
    pub modified_ts: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

pub struct Files {
    roots: PermittedRoots,
    /// Largest file the read operation will return inline.
    pub max_read: u64,
    pub max_write: u64,
    /// Keep this much headroom on the filesystem after a write.
    pub min_free_bytes: u64,
}

impl Files {
    pub fn new(roots: PermittedRoots) -> Self {
        Self {
            roots,
            max_read: 8 * 1024 * 1024,
            max_write: 64 * 1024 * 1024,
            min_free_bytes: 256 * 1024 * 1024,
        }
    }

    pub fn roots(&self) -> &PermittedRoots {
        &self.roots
    }

    /// The real path for `requested`, which must exist except for its
    /// final component. Refuses anything that lands outside the roots
    /// after symlinks are resolved.
    pub fn resolve(&self, requested: &Path) -> Result<PathBuf> {
        if !self.roots.permits(requested) {
            return Err(FileError::OutsideRoots(requested.into()));
        }

        let normalized = daemon_capability::roots::normalize(requested);
        let parent = normalized
            .parent()
            .ok_or_else(|| FileError::OutsideRoots(requested.into()))?;
        let name = normalized
            .file_name()
            .ok_or_else(|| FileError::OutsideRoots(requested.into()))?;

        let real_parent =
            fs::canonicalize(parent).map_err(|_| FileError::NotFound(parent.into()))?;
        let real = real_parent.join(name);

        if !self.roots.permits(&real) {
            return Err(FileError::SymlinkEscape(requested.into()));
        }

        // A final-component symlink pointing out of the roots is refused
        // too; one pointing inside is followed like any other path.
        if let Ok(meta) = fs::symlink_metadata(&real) {
            if meta.file_type().is_symlink() {
                let target =
                    fs::canonicalize(&real).map_err(|_| FileError::NotFound(real.clone()))?;
                if !self.roots.permits(&target) {
                    return Err(FileError::SymlinkEscape(requested.into()));
                }
                return Ok(target);
            }
        }

        Ok(real)
    }

    pub fn list(&self, dir: &Path) -> Result<Vec<Entry>> {
        let real = self.resolve(dir)?;
        let entries = fs::read_dir(&real).map_err(|source| FileError::Io {
            path: real.clone(),
            source,
        })?;
        let mut out = Vec::new();

        for entry in entries.flatten() {
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let symlink_meta = fs::symlink_metadata(entry.path()).ok();
            let is_symlink = symlink_meta
                .as_ref()
                .is_some_and(|m| m.file_type().is_symlink());

            out.push(Entry {
                name: entry.file_name().to_string_lossy().into_owned(),
                kind: if is_symlink {
                    EntryKind::Symlink
                } else if meta.is_dir() {
                    EntryKind::Directory
                } else if meta.is_file() {
                    EntryKind::File
                } else {
                    EntryKind::Other
                },
                size: meta.len(),
                mode: mode_of(&meta),
                modified_ts: meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
                symlink_target: is_symlink
                    .then(|| {
                        fs::read_link(entry.path())
                            .ok()
                            .map(|p| p.to_string_lossy().into_owned())
                    })
                    .flatten(),
            });
        }

        out.sort_by(|a, b| {
            (a.kind != EntryKind::Directory)
                .cmp(&(b.kind != EntryKind::Directory))
                .then(a.name.cmp(&b.name))
        });

        Ok(out)
    }

    pub fn read(&self, path: &Path) -> Result<Vec<u8>> {
        let real = self.resolve(path)?;
        let meta = fs::metadata(&real).map_err(|_| FileError::NotFound(path.into()))?;

        if meta.is_dir() {
            return Err(FileError::IsDirectory(path.into()));
        }

        if meta.len() > self.max_read {
            return Err(FileError::TooLarge {
                path: path.into(),
                size: meta.len(),
                limit: self.max_read,
            });
        }

        let file = fs::File::open(&real).map_err(|source| FileError::Io {
            path: real.clone(),
            source,
        })?;
        let mut buf = Vec::with_capacity(meta.len() as usize);
        file.take(self.max_read)
            .read_to_end(&mut buf)
            .map_err(|source| FileError::Io { path: real, source })?;

        Ok(buf)
    }

    /// Write atomically. An existing file is copied to
    /// `<name>.serveros-backup-<ts>` first and the backup path returned.
    pub fn write(&self, path: &Path, content: &[u8], mode: Option<u32>) -> Result<Option<PathBuf>> {
        if content.len() as u64 > self.max_write {
            return Err(FileError::TooLarge {
                path: path.into(),
                size: content.len() as u64,
                limit: self.max_write,
            });
        }

        let real = self.resolve(path)?;
        let parent = real
            .parent()
            .ok_or_else(|| FileError::OutsideRoots(path.into()))?;

        self.ensure_space(parent, content.len() as u64)?;

        let backup = if real.is_file() {
            let stamp = time::OffsetDateTime::now_utc().unix_timestamp();
            let backup_path = real.with_file_name(format!(
                "{}.serveros-backup-{stamp}",
                real.file_name().unwrap_or_default().to_string_lossy()
            ));
            fs::copy(&real, &backup_path).map_err(|source| FileError::Io {
                path: backup_path.clone(),
                source,
            })?;
            Some(backup_path)
        } else {
            None
        };

        let existing_mode = fs::metadata(&real).ok().map(|m| mode_of(&m));
        let temp = parent.join(format!(
            ".{}.serveros-tmp",
            real.file_name().unwrap_or_default().to_string_lossy()
        ));

        {
            let mut file = fs::File::create(&temp).map_err(|source| FileError::Io {
                path: temp.clone(),
                source,
            })?;
            file.write_all(content).map_err(|source| FileError::Io {
                path: temp.clone(),
                source,
            })?;
            file.sync_all().map_err(|source| FileError::Io {
                path: temp.clone(),
                source,
            })?;
        }

        if let Some(mode) = mode.or(existing_mode) {
            set_mode(&temp, mode)?;
        }

        // Keep the owner of the file being replaced.
        if let Ok(meta) = fs::metadata(&real) {
            let _ = set_owner(&temp, uid_of(&meta), gid_of(&meta));
        }

        fs::rename(&temp, &real).map_err(|source| FileError::Io { path: real, source })?;

        Ok(backup)
    }

    /// Delete a file or an empty directory. Non-empty directories are
    /// refused: bulk deletion is a preview-and-confirm operation the panel
    /// runs file by file.
    pub fn delete(&self, path: &Path) -> Result<()> {
        let real = self.resolve(path)?;
        let meta = fs::symlink_metadata(&real).map_err(|_| FileError::NotFound(path.into()))?;

        if meta.is_dir() {
            fs::remove_dir(&real).map_err(|source| FileError::Io { path: real, source })
        } else {
            fs::remove_file(&real).map_err(|source| FileError::Io { path: real, source })
        }
    }

    pub fn chmod(&self, path: &Path, mode: u32) -> Result<()> {
        let real = self.resolve(path)?;
        set_mode(&real, mode & 0o7777)
    }

    pub fn chown(&self, path: &Path, user: &str, group: Option<&str>) -> Result<()> {
        let real = self.resolve(path)?;
        let (uid, primary_gid) =
            lookup_user(user).ok_or_else(|| FileError::UnknownUser(user.into()))?;
        let gid = match group {
            Some(g) => lookup_group(g).ok_or_else(|| FileError::UnknownUser(g.into()))?,
            None => primary_gid,
        };

        set_owner(&real, uid, gid).map_err(|source| FileError::Io { path: real, source })
    }

    fn ensure_space(&self, dir: &Path, needed: u64) -> Result<()> {
        let Some(free) = free_bytes(dir) else {
            return Ok(());
        };

        if free.saturating_sub(needed) < self.min_free_bytes {
            return Err(FileError::DiskFull {
                mount: dir.into(),
                needed,
                free,
            });
        }

        Ok(())
    }
}

// ------------------------------------------------------------- unix helpers

#[cfg(unix)]
fn mode_of(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn mode_of(_meta: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn uid_of(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.uid()
}

#[cfg(unix)]
fn gid_of(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.gid()
}

#[cfg(not(unix))]
fn uid_of(_: &fs::Metadata) -> u32 {
    0
}

#[cfg(not(unix))]
fn gid_of(_: &fs::Metadata) -> u32 {
    0
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| {
            FileError::Io {
                path: path.into(),
                source,
            }
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

#[cfg(unix)]
fn set_owner(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    std::os::unix::fs::chown(path, Some(uid), Some(gid))
}

#[cfg(not(unix))]
fn set_owner(_: &Path, _: u32, _: u32) -> std::io::Result<()> {
    Ok(())
}

/// `/etc/passwd` lookup without libc's getpwnam, so behaviour is the same
/// under musl and glibc and there is no NSS surprise.
pub fn lookup_user(name: &str) -> Option<(u32, u32)> {
    let text = fs::read_to_string("/etc/passwd").ok()?;

    text.lines().find_map(|line| {
        let mut parts = line.split(':');
        (parts.next()? == name).then(|| {
            parts.next();
            let uid = parts.next()?.parse().ok()?;
            let gid = parts.next()?.parse().ok()?;
            Some((uid, gid))
        })?
    })
}

pub fn lookup_group(name: &str) -> Option<u32> {
    let text = fs::read_to_string("/etc/group").ok()?;

    text.lines().find_map(|line| {
        let mut parts = line.split(':');
        (parts.next()? == name).then(|| {
            parts.next();
            parts.next()?.parse().ok()
        })?
    })
}

#[cfg(unix)]
fn free_bytes(dir: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };

    (unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } == 0)
        .then(|| stat.f_bavail as u64 * stat.f_frsize as u64)
}

#[cfg(not(unix))]
fn free_bytes(_: &Path) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox() -> (tempfile::TempDir, Files, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path())
            .unwrap()
            .join("srv")
            .join("app");
        fs::create_dir_all(&root).unwrap();
        let mut files = Files::new(PermittedRoots::new([root.clone()]));
        files.min_free_bytes = 0;

        (dir, files, root)
    }

    #[test]
    fn reads_and_lists_inside_the_root() {
        let (_dir, files, root) = sandbox();
        fs::write(root.join("a.txt"), b"hello").unwrap();
        fs::create_dir(root.join("logs")).unwrap();

        assert_eq!(files.read(&root.join("a.txt")).unwrap(), b"hello");

        let listing = files.list(&root).unwrap();
        assert_eq!(
            listing.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec!["logs", "a.txt"]
        );
        assert_eq!(listing[0].kind, EntryKind::Directory);
    }

    #[test]
    fn refuses_paths_outside_and_symlinks_that_escape() {
        let (dir, files, root) = sandbox();
        let outside = fs::canonicalize(dir.path()).unwrap().join("secret.txt");
        fs::write(&outside, b"nope").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link.txt")).unwrap();
        std::os::unix::fs::symlink(root.join("a.txt"), root.join("inside.txt")).unwrap();
        fs::write(root.join("a.txt"), b"yes").unwrap();

        assert!(matches!(
            files.read(&outside),
            Err(FileError::OutsideRoots(_))
        ));
        assert!(matches!(
            files.read(&root.join("link.txt")),
            Err(FileError::SymlinkEscape(_))
        ));
        assert!(matches!(
            files.read(&root.join("../../secret.txt")),
            Err(FileError::OutsideRoots(_))
        ));
        assert_eq!(files.read(&root.join("inside.txt")).unwrap(), b"yes");
    }

    #[test]
    fn writes_atomically_with_a_backup_and_preserved_mode() {
        let (_dir, files, root) = sandbox();
        let path = root.join("config.yml");
        fs::write(&path, b"old").unwrap();
        files.chmod(&path, 0o640).unwrap();

        let backup = files.write(&path, b"new", None).unwrap().unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(fs::read(&backup).unwrap(), b"old");
        assert!(backup.to_string_lossy().contains(".serveros-backup-"));
        assert_eq!(mode_of(&fs::metadata(&path).unwrap()), 0o640);
        assert!(!root.join(".config.yml.serveros-tmp").exists());

        assert!(files
            .write(&root.join("fresh.txt"), b"x", Some(0o600))
            .unwrap()
            .is_none());
    }

    #[test]
    fn oversized_reads_are_refused_with_the_limit() {
        let (_dir, mut files, root) = sandbox();
        files.max_read = 4;
        fs::write(root.join("big.bin"), b"123456").unwrap();

        assert!(matches!(
            files.read(&root.join("big.bin")),
            Err(FileError::TooLarge {
                size: 6,
                limit: 4,
                ..
            })
        ));
    }

    #[test]
    fn delete_refuses_non_empty_directories() {
        let (_dir, files, root) = sandbox();
        fs::create_dir(root.join("d")).unwrap();
        fs::write(root.join("d/x"), b"").unwrap();

        assert!(files.delete(&root.join("d")).is_err());
        files.delete(&root.join("d/x")).unwrap();
        files.delete(&root.join("d")).unwrap();
        assert!(!root.join("d").exists());
    }
}
