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
