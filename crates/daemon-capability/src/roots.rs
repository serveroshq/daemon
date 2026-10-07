use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PermittedRoots {
    roots: Vec<PathBuf>,
}

impl PermittedRoots {
    pub fn new(roots: impl IntoIterator<Item = PathBuf>) -> Self {
        let mut permitted = Self::default();

        for root in roots {
            permitted.add(root);
        }

        permitted
    }

    pub fn add(&mut self, root: PathBuf) {
        let root = normalize(&root);

        if root == Path::new("/") || !root.is_absolute() {
            return;
        }

        if !self.roots.contains(&root) {
            self.roots.push(root);
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Path> {
        self.roots.iter().map(PathBuf::as_path)
    }

    pub fn permits(&self, path: &Path) -> bool {
        let candidate = normalize(path);

        candidate.is_absolute() && self.roots.iter().any(|root| candidate.starts_with(root))
    }
}

/// System locations that are never opened as a whole, even when a container
/// mounts them: the machine's config, kernel and device trees, the runtime
/// directory (which holds the Docker socket), boot files and root's home.
const SYSTEM_ROOTS: &[&str] = &[
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/var/run",
    "/boot",
    "/root",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/usr",
    "/var/lib/docker/containers",
];

/// Whether a folder a container mounts may become a place ServerOS opens:
/// not the root, not a system location or anything inside one, and not a
/// parent of one (mounting /var would otherwise open /var/run).
pub fn mountable_root(path: &Path) -> bool {
    let path = normalize(path);
    if !path.is_absolute() || path == Path::new("/") {
        return false;
    }

    !SYSTEM_ROOTS.iter().any(|system| {
        let system = Path::new(system);
        path.starts_with(system) || system.starts_with(&path)
    })
}

pub fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();

    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }

    if path.is_absolute() && !out.is_absolute() {
        PathBuf::from("/")
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_mounts_can_be_opened_but_never_system_locations() {
        assert!(mountable_root(Path::new("/var/lib/serveros/volumes/8f2c")));
        assert!(mountable_root(Path::new(
            "/var/lib/docker/volumes/shop_data/_data"
        )));
        assert!(mountable_root(Path::new("/srv/app/storage")));
        assert!(!mountable_root(Path::new("/")));
        assert!(!mountable_root(Path::new("/etc/nginx")));
        assert!(!mountable_root(Path::new("/var/run/docker.sock")));
        assert!(!mountable_root(Path::new("/var")));
        assert!(!mountable_root(Path::new("/proc/1")));
        assert!(!mountable_root(Path::new("/srv/../etc")));
    }

    #[test]
    fn root_slash_is_never_permitted() {
        let roots = PermittedRoots::new([PathBuf::from("/")]);

        assert!(!roots.permits(Path::new("/etc/passwd")));
        assert_eq!(roots.iter().count(), 0);
    }

    #[test]
    fn traversal_is_collapsed_before_checking() {
        let roots = PermittedRoots::new([PathBuf::from("/srv/app")]);

        assert!(roots.permits(Path::new("/srv/app/storage/logs/app.log")));
        assert!(!roots.permits(Path::new("/srv/app/../../etc/shadow")));
        assert!(!roots.permits(Path::new("/srv/application")));
        assert!(!roots.permits(Path::new("relative/path")));
    }

    #[test]
    fn climbing_above_root_lands_on_root() {
        assert_eq!(normalize(Path::new("/../../x")), PathBuf::from("/x"));
    }
}
