//! Which language packages are on the machine, and where: every project's
//! lockfile under the usual places apps live, packages installed into
//! node_modules or a virtualenv without one, and the global npm and pip
//! folders. The panel matches each (ecosystem, name, version) against the
//! OSV vulnerability database.
//!
//! System packages from apt and dnf aren't listed: the package manager
//! already says which of them have security updates, and distributions
//! patch without changing upstream version numbers, so matching them here
//! would mostly be wrong. For the same reason Python's dist-packages
//! (which apt installs) are left out; pip's site-packages aren't.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::lockfiles::{self, Locked};
use crate::util::{self, clip};
use crate::{Deadline, Options};

/// Where apps usually live. Searched to MAX_DEPTH.
pub const ROOTS: &[&str] = &[
    "/var/www",
    "/srv",
    "/opt",
    "/home",
    "/root",
    "/app",
    "/usr/src/app",
];
/// Global installs, read as installed packages.
const GLOBAL_NODE: &[&str] = &["/usr/lib/node_modules", "/usr/local/lib/node_modules"];
const GLOBAL_PYTHON: &[&str] = &["/usr/local/lib"];

const MAX_DEPTH: usize = 7;
const MAX_ENTRIES: usize = 400_000;
const MAX_PROJECTS: usize = 500;
const MAX_PACKAGES: usize = 40_000;
/// Where one package is used, at most: the rest only count.
const MAX_PATHS: usize = 8;

/// Folders that are never a project, or hold far too much to walk.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    ".hg",
    ".svn",
    ".cache",
    ".npm",
    ".yarn",
    ".pnpm-store",
    ".nvm",
    ".cargo",
    ".rustup",
    ".local",
    ".m2",
    ".gradle",
    "__pycache__",
    "site-packages",
    "dist-packages",
    "vendor",
    "target",
    "snap",
    "proc",
    "sys",
    ".Trash",
    "go",
];

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Pypi,
    Packagist,
    Rubygems,
    Go,
    Cargo,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Package {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    /// Only a development dependency everywhere it's used.
    pub dev: bool,
    /// The lockfiles or install folders it's in (MAX_PATHS of them).
    pub paths: Vec<String>,
    /// How many places in all.
    pub uses: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Project {
    pub path: String,
    pub ecosystem: Ecosystem,
    /// What the versions were read from: `package-lock.json`, `site-packages`.
    pub source: String,
    pub packages: u32,
}

#[derive(Debug, Default)]
pub struct Found {
    pub packages: Vec<Package>,
    pub projects: Vec<Project>,
    pub truncated: bool,
    /// Folders of Laravel apps, for their debug setting.
    pub laravel: Vec<PathBuf>,
}

struct Walk<'a> {
    options: &'a Options,
    deadline: &'a Deadline,
    entries: usize,
    truncated: bool,
    seen: BTreeSet<PathBuf>,
    packages: BTreeMap<(Ecosystem, String, String), Package>,
    projects: Vec<Project>,
    laravel: Vec<PathBuf>,
}

pub fn gather(options: &Options, deadline: &Deadline) -> Found {
    let mut walk = Walk {
        options,
        deadline,
        entries: 0,
        truncated: false,
        seen: BTreeSet::new(),
        packages: BTreeMap::new(),
        projects: Vec::new(),
        laravel: Vec::new(),
    };

    let mut roots: Vec<PathBuf> = ROOTS.iter().map(|r| options.path(r)).collect();
    if let Some(apps) = &options.apps_dir {
        roots.push(options.path(&apps.to_string_lossy()));
    }
    for root in roots {
        walk.dir(&root, 0);
    }
    for global in GLOBAL_NODE {
        let dir = options.path(global);
        if dir.is_dir() {
            walk.node_modules(&dir, &dir);
        }
    }
    for lib in GLOBAL_PYTHON {
        for site in python_dirs(&options.path(lib)) {
            walk.site_packages(&site);
        }
    }

    let truncated = walk.truncated || walk.packages.len() > MAX_PACKAGES;
    Found {
        packages: walk.packages.into_values().take(MAX_PACKAGES).collect(),
        projects: walk.projects,
        truncated,
        laravel: walk.laravel,
    }
}

impl Walk<'_> {
    fn spent(&mut self) -> bool {
        if self.entries >= MAX_ENTRIES
            || self.projects.len() >= MAX_PROJECTS
            || self.deadline.passed()
        {
            self.truncated = true;
        }
        self.truncated
    }

    fn dir(&mut self, dir: &Path, depth: usize) {
        if depth > MAX_DEPTH || self.spent() {
            return;
        }
        // Symlinked folders are followed once, by where they really are.
        let Ok(real) = dir.canonicalize() else {
            return;
        };
        if !self.seen.insert(real) {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut files = BTreeSet::new();
        let mut dirs = Vec::new();
        for entry in entries.flatten() {
            self.entries += 1;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() || (kind.is_symlink() && entry.path().is_dir()) {
                dirs.push(name);
            } else {
                files.insert(name);
            }
        }

        self.project(dir, &files, &dirs);

        dirs.sort();
        for name in dirs {
            if SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            let path = dir.join(&name);
            if path.join("pyvenv.cfg").is_file() {
                for site in python_dirs(&path.join("lib")) {
                    self.site_packages(&site);
                }
                continue;
            }
            self.dir(&path, depth + 1);
        }
    }

    /// One folder's lockfiles, the best one per ecosystem.
    fn project(&mut self, dir: &Path, files: &BTreeSet<String>, dirs: &[String]) {
        let has = |name: &str| files.contains(name);

        // npm: a lockfile says exactly what's installed; without one,
        // whatever is in node_modules.
        let npm = [
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml",
        ]
        .into_iter()
        .find(|f| has(f));
        match npm {
            Some(file) => {
                let parse = match file {
                    "yarn.lock" => lockfiles::yarn_lock,
                    "pnpm-lock.yaml" => lockfiles::pnpm_lock,
                    _ => lockfiles::npm_lock,
                };
                self.lockfile(dir, file, Ecosystem::Npm, parse);
            }
            None if dirs.iter().any(|d| d == "node_modules") && has("package.json") => {
                self.node_modules(&dir.join("node_modules"), dir);
            }
            None => {}
        }

        let python = [
            (
                "poetry.lock",
                lockfiles::toml_packages_local as fn(&str) -> Vec<Locked>,
            ),
            ("uv.lock", lockfiles::toml_packages_local),
            ("Pipfile.lock", lockfiles::pipfile_lock),
            ("requirements.txt", lockfiles::requirements),
        ];
        if let Some((file, parse)) = python.into_iter().find(|(f, _)| has(f)) {
            self.lockfile(dir, file, Ecosystem::Pypi, parse);
        }

        if has("composer.lock") {
            self.lockfile(
                dir,
                "composer.lock",
                Ecosystem::Packagist,
                lockfiles::composer,
            );
        } else if dir.join("vendor/composer/installed.json").is_file() {
            self.lockfile(
                dir,
                "vendor/composer/installed.json",
                Ecosystem::Packagist,
                lockfiles::composer,
            );
        }
        if has("artisan") && has("composer.json") {
            self.laravel.push(dir.to_path_buf());
        }

        if has("Gemfile.lock") {
            self.lockfile(
                dir,
                "Gemfile.lock",
                Ecosystem::Rubygems,
                lockfiles::gemfile_lock,
            );
        }
        if has("go.mod") {
            self.lockfile(dir, "go.mod", Ecosystem::Go, lockfiles::go_mod);
        }
        if has("Cargo.lock") {
            self.lockfile(dir, "Cargo.lock", Ecosystem::Cargo, lockfiles::cargo_lock);
        }
    }

    fn lockfile(
        &mut self,
        dir: &Path,
        file: &str,
        ecosystem: Ecosystem,
        parse: fn(&str) -> Vec<Locked>,
    ) {
        let path = dir.join(file);
        let Some(text) = util::read(&path) else {
            return;
        };
        let found = parse(&text);
        if found.is_empty() {
            return;
        }
        let shown = self.options.display(&path);
        self.projects.push(Project {
            path: clip(&self.options.display(dir), 300),
            ecosystem,
            source: file.to_string(),
            packages: found.len() as u32,
        });
        for locked in found {
            self.add(ecosystem, locked, &shown);
        }
    }

    /// Installed packages in a node_modules folder (and their own nested
    /// node_modules), read from each one's package.json.
    fn node_modules(&mut self, modules: &Path, project: &Path) {
        let mut found = Vec::new();
        let mut stack = vec![(modules.to_path_buf(), 0usize)];
        while let Some((dir, depth)) = stack.pop() {
            if depth > 6 || self.spent() {
                break;
            }
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                self.entries += 1;
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') {
                    continue;
                }
                let path = entry.path();
                if name.starts_with('@') {
                    for scoped in std::fs::read_dir(&path).into_iter().flatten().flatten() {
                        self.entries += 1;
                        Self::installed_node(&scoped.path(), &mut found, &mut stack, depth);
                    }
                    continue;
                }
                Self::installed_node(&path, &mut found, &mut stack, depth);
            }
        }
        if found.is_empty() {
            return;
        }
        let shown = self.options.display(modules);
        self.projects.push(Project {
            path: clip(&self.options.display(project), 300),
            ecosystem: Ecosystem::Npm,
            source: "node_modules".into(),
            packages: found.len() as u32,
        });
        for locked in found {
            self.add(Ecosystem::Npm, locked, &shown);
        }
    }

    fn installed_node(
        path: &Path,
        found: &mut Vec<Locked>,
        stack: &mut Vec<(PathBuf, usize)>,
        depth: usize,
    ) {
        if let Some(locked) = util::read_limited(&path.join("package.json"), 1024 * 1024)
            .and_then(|t| lockfiles::package_json(&t))
        {
            found.push(locked);
        }
        let nested = path.join("node_modules");
        if nested.is_dir() {
            stack.push((nested, depth + 1));
        }
    }

    /// A Python environment's installed packages, from their metadata.
    fn site_packages(&mut self, site: &Path) {
        let Ok(entries) = std::fs::read_dir(site) else {
            return;
        };
        let mut found = Vec::new();
        for entry in entries.flatten() {
            self.entries += 1;
            let name = entry.file_name().to_string_lossy().into_owned();
            let meta = if name.ends_with(".dist-info") {
                entry.path().join("METADATA")
            } else if name.ends_with(".egg-info") {
                let path = entry.path();
                if path.is_dir() {
                    path.join("PKG-INFO")
                } else {
                    path
                }
            } else {
                continue;
            };
            if let Some(locked) =
                util::read_limited(&meta, 512 * 1024).and_then(|t| lockfiles::python_metadata(&t))
            {
                found.push(locked);
            }
        }
        if found.is_empty() {
            return;
        }
        let shown = self.options.display(site);
        self.projects.push(Project {
            path: clip(&shown, 300),
            ecosystem: Ecosystem::Pypi,
            source: "site-packages".into(),
            packages: found.len() as u32,
        });
        for locked in found {
            self.add(Ecosystem::Pypi, locked, &shown);
        }
    }

    fn add(&mut self, ecosystem: Ecosystem, locked: Locked, path: &str) {
        let key = (ecosystem, locked.name.clone(), locked.version.clone());
        let package = self.packages.entry(key).or_insert_with(|| Package {
            ecosystem,
            name: locked.name,
            version: locked.version,
            dev: true,
            paths: Vec::new(),
            uses: 0,
        });
        package.dev &= locked.dev;
        package.uses += 1;
        if package.paths.len() < MAX_PATHS && !package.paths.iter().any(|p| p == path) {
            package.paths.push(clip(path, 300));
        }
    }
}

/// `lib/python3.*/site-packages` folders under a lib folder, and the
/// `dist-packages` Debian's pip installs to under /usr/local (apt's own are
/// under /usr/lib, which isn't searched).
fn python_dirs(lib: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(lib)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("python"))
        .flat_map(|e| {
            [
                e.path().join("site-packages"),
                e.path().join("dist-packages"),
            ]
        })
        .filter(|p| p.is_dir())
        .collect();
    out.sort();

    out
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn write(root: &Path, path: &str, text: &str) {
        let full = root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, text).unwrap();
    }

    fn options(root: &Path) -> Options {
        Options {
            root: root.to_path_buf(),
            proc: root.join("proc"),
            docker_socket: None,
            apps_dir: Some("/var/lib/serveros/apps".into()),
            commands: false,
            budget: Duration::from_secs(30),
        }
    }

    #[test]
    fn finds_projects_installs_and_globals() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "/var/www/shop/package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/lodash":{"version":"4.17.15"},"node_modules/jest":{"version":"29.0.0","dev":true}}}"#,
        );
        // What's under node_modules isn't walked when there's a lockfile.
        write(
            root,
            "/var/www/shop/node_modules/evil/package-lock.json",
            r#"{"packages":{"node_modules/x":{"version":"1.0.0"}}}"#,
        );
        write(root, "/srv/api/package.json", "{}");
        write(
            root,
            "/srv/api/node_modules/express/package.json",
            r#"{"name":"express","version":"4.16.0"}"#,
        );
        write(
            root,
            "/srv/api/node_modules/@types/node/package.json",
            r#"{"name":"@types/node","version":"20.0.0"}"#,
        );
        write(
            root,
            "/srv/api/node_modules/express/node_modules/qs/package.json",
            r#"{"name":"qs","version":"6.5.1"}"#,
        );
        write(
            root,
            "/home/deploy/blog/composer.lock",
            r#"{"packages":[{"name":"laravel/framework","version":"v8.0.0"}]}"#,
        );
        write(root, "/home/deploy/blog/composer.json", "{}");
        write(root, "/home/deploy/blog/artisan", "");
        write(root, "/opt/bot/requirements.txt", "requests==2.19.0\n");
        write(root, "/opt/bot/venv/pyvenv.cfg", "home = /usr/bin\n");
        write(
            root,
            "/opt/bot/venv/lib/python3.11/site-packages/Django-3.2.dist-info/METADATA",
            "Name: Django\nVersion: 3.2\n",
        );
        write(
            root,
            "/usr/local/lib/node_modules/pm2/package.json",
            r#"{"name":"pm2","version":"5.3.0"}"#,
        );
        write(
            root,
            "/usr/local/lib/python3.11/site-packages/urllib3-1.26.0.dist-info/METADATA",
            "Name: urllib3\nVersion: 1.26.0\n",
        );
        write(
            root,
            "/usr/lib/python3/dist-packages/apt_pkg-2.0.dist-info/METADATA",
            "Name: apt\nVersion: 2.0\n",
        );
        write(
            root,
            "/var/lib/serveros/apps/shop/abc/Gemfile.lock",
            "GEM\n  specs:\n    rack (2.0.7)\n",
        );

        let found = gather(&options(root), &Deadline::after(Duration::from_secs(30)));
        let mut seen: Vec<String> = found
            .packages
            .iter()
            .map(|p| {
                format!(
                    "{:?} {}@{}{}",
                    p.ecosystem,
                    p.name,
                    p.version,
                    if p.dev { " dev" } else { "" }
                )
            })
            .collect();
        seen.sort();
        assert_eq!(
            seen,
            vec![
                "Npm @types/node@20.0.0",
                "Npm express@4.16.0",
                "Npm jest@29.0.0 dev",
                "Npm lodash@4.17.15",
                "Npm pm2@5.3.0",
                "Npm qs@6.5.1",
                "Packagist laravel/framework@8.0.0",
                "Pypi django@3.2",
                "Pypi requests@2.19.0",
                "Pypi urllib3@1.26.0",
                "Rubygems rack@2.0.7",
            ]
        );
        let lodash = found.packages.iter().find(|p| p.name == "lodash").unwrap();
        assert_eq!(lodash.paths, vec!["/var/www/shop/package-lock.json"]);
        assert!(found
            .projects
            .iter()
            .any(|p| p.path == "/srv/api" && p.source == "node_modules"));
        assert_eq!(found.laravel, vec![root.join("home/deploy/blog")]);
        assert!(!found.truncated);
    }

    #[test]
    fn the_same_package_in_two_projects_is_one_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let lock = r#"{"packages":{"node_modules/lodash":{"version":"4.17.15"}}}"#;
        write(root, "/var/www/a/package-lock.json", lock);
        write(root, "/var/www/b/package-lock.json", lock);

        let found = gather(&options(root), &Deadline::after(Duration::from_secs(30)));
        assert_eq!(found.packages.len(), 1);
        assert_eq!(found.packages[0].uses, 2);
        assert_eq!(found.packages[0].paths.len(), 2);
    }

    #[test]
    fn a_spent_budget_says_so() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "/var/www/a/package-lock.json", "{}");
        let found = gather(&options(tmp.path()), &Deadline::after(Duration::ZERO));
        assert!(found.truncated);
    }
}
