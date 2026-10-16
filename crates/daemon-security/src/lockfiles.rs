//! Parsers for the files that say exactly which package versions a project
//! uses: lockfiles, pinned requirements, and installed packages' own
//! metadata. Each returns (name, version, dev) and skips anything it can't
//! read rather than failing the whole file.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locked {
    pub name: String,
    pub version: String,
    /// Only used while developing (devDependencies, packages-dev).
    pub dev: bool,
}

impl Locked {
    fn new(name: &str, version: &str, dev: bool) -> Option<Self> {
        let name = name.trim();
        let version = version.trim();
        let ok = !name.is_empty()
            && !version.is_empty()
            && name.len() <= 214
            && version.len() <= 64
            && version
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric());

        ok.then(|| Self {
            name: name.to_string(),
            version: version.to_string(),
            dev,
        })
    }
}

/// package-lock.json and npm-shrinkwrap.json, lockfile versions 1 to 3.
pub fn npm_lock(text: &str) -> Vec<Locked> {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();

    if let Some(packages) = json.get("packages").and_then(Value::as_object) {
        for (path, entry) in packages {
            let Some(at) = path.rfind("node_modules/") else {
                continue;
            };
            if entry.get("link").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(&path[at + "node_modules/".len()..]);
            let version = entry.get("version").and_then(Value::as_str).unwrap_or("");
            let dev = entry.get("dev").and_then(Value::as_bool).unwrap_or(false);
            out.extend(Locked::new(name, version, dev));
        }

        return out;
    }

    fn walk(deps: &serde_json::Map<String, Value>, out: &mut Vec<Locked>, depth: u8) {
        if depth > 64 {
            return;
        }
        for (name, entry) in deps {
            let version = entry.get("version").and_then(Value::as_str).unwrap_or("");
            // v1 writes linked and git dependencies as their source.
            if !version.contains(':') {
                let dev = entry.get("dev").and_then(Value::as_bool).unwrap_or(false);
                out.extend(Locked::new(name, version, dev));
            }
            if let Some(nested) = entry.get("dependencies").and_then(Value::as_object) {
                walk(nested, out, depth + 1);
            }
        }
    }
    if let Some(deps) = json.get("dependencies").and_then(Value::as_object) {
        walk(deps, &mut out, 0);
    }

    out
}

/// yarn.lock, classic (v1) and Berry. Workspaces and linked folders aren't
/// packages from a registry, so they're left out.
pub fn yarn_lock(text: &str) -> Vec<Locked> {
    let mut out = Vec::new();
    let mut name: Option<String> = None;

    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            // `"@babel/core@^7.0.0", "@babel/core@^7.1.0":` or `lodash@^4:`
            let first = line
                .trim_end_matches(':')
                .split(", ")
                .next()
                .unwrap_or("")
                .trim_matches('"');
            name = (!first.starts_with("__metadata")
                && !first.contains("@workspace:")
                && !first.contains("@link:")
                && !first.contains("@portal:")
                && !first.contains("@file:"))
            .then(|| spec_name(first))
            .flatten();
            continue;
        }
        let trimmed = line.trim();
        let version = trimmed
            .strip_prefix("version \"")
            .map(|v| v.trim_end_matches('"'))
            .or_else(|| trimmed.strip_prefix("version: "))
            .map(|v| v.trim_matches('"'));
        if let (Some(version), Some(n)) = (version, name.take()) {
            out.extend(Locked::new(&n, version, false));
        }
    }

    out.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    out.dedup();

    out
}

/// The package name in a yarn spec: everything before the last `@` that
/// isn't the scope's.
fn spec_name(spec: &str) -> Option<String> {
    let at = spec[1..].find('@').map(|i| i + 1)?;
    let name = &spec[..at];
    // Berry's patches name the package inside: `pkg@patch:pkg@npm%3A1.0.0#…`.
    (!name.is_empty()).then(|| name.to_string())
}

/// pnpm-lock.yaml, versions 5 to 9, read line by line: the keys under
/// `packages:` name each package and version.
pub fn pnpm_lock(text: &str) -> Vec<Locked> {
    let mut out = Vec::new();
    let mut in_packages = false;
    // v5 keys are `/name/version`, later ones `/name@version`.
    let mut v5 = false;

    for line in text.lines() {
        if let Some(version) = line.strip_prefix("lockfileVersion:") {
            v5 = version.trim().trim_matches('\'').starts_with('5');
        }
        if !line.starts_with(' ') && !line.trim().is_empty() {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        if !in_packages || !line.starts_with("  ") || line.starts_with("   ") {
            continue;
        }
        let key = line
            .trim()
            .trim_end_matches(':')
            .trim_matches(|c| c == '\'' || c == '"')
            .trim_start_matches('/');
        // Peer suffixes: `/react-dom@18.2.0(react@18.2.0)` or, in v5,
        // `/react-dom/18.2.0_react@18.2.0` (a scoped peer's `/` is a `+`).
        let key = key.split('(').next().unwrap_or(key);
        let split = if v5 {
            key.rfind('/').map(|i| (i, 1))
        } else {
            key.get(1..).and_then(|k| k.find('@')).map(|i| (i + 1, 1))
        };
        let Some((at, skip)) = split else {
            continue;
        };
        let (name, version) = (&key[..at], &key[at + skip..]);
        let version = version.split('_').next().unwrap_or(version);
        if version.contains(':') {
            continue;
        }
        out.extend(Locked::new(name, version, false));
    }

    out
}

/// A package.json in node_modules: an installed package's name and version.
pub fn package_json(text: &str) -> Option<Locked> {
    let json: Value = serde_json::from_str(text).ok()?;

    Locked::new(
        json.get("name")?.as_str()?,
        json.get("version")?.as_str()?,
        false,
    )
}

/// requirements.txt: only exact pins (`name==1.2.3`) say what's installed.
pub fn requirements(text: &str) -> Vec<Locked> {
    text.lines()
        .filter_map(|line| {
            let line = line.split(" #").next()?.trim();
            if line.starts_with('#') || line.starts_with('-') {
                return None;
            }
            let line = line.split(';').next()?.trim();
            let (name, version) = line.split_once("==")?;
            let name = name.split('[').next()?.trim();
            let version = version.split_whitespace().next()?.trim_end_matches('\\');
            if version.contains('*') {
                return None;
            }
            Locked::new(&normalise_python(name), version, false)
        })
        .collect()
}

/// poetry.lock and uv.lock are both TOML with `[[package]]` tables.
pub fn toml_packages(text: &str, skip_local: bool) -> Vec<Locked> {
    let Ok(doc) = text.parse::<toml::Table>() else {
        return Vec::new();
    };
    let Some(packages) = doc.get("package").and_then(|p| p.as_array()) else {
        return Vec::new();
    };

    packages
        .iter()
        .filter_map(|p| {
            let table = p.as_table()?;
            if skip_local {
                if let Some(source) = table.get("source") {
                    let local = match source {
                        toml::Value::Table(t) => {
                            t.contains_key("virtual")
                                || t.contains_key("editable")
                                || t.contains_key("directory")
                                || t.contains_key("path")
                        }
                        _ => false,
                    };
                    if local {
                        return None;
                    }
                }
            }
            let dev = table
                .get("category")
                .and_then(|c| c.as_str())
                .is_some_and(|c| c == "dev");
            Locked::new(
                &normalise_python(table.get("name")?.as_str()?),
                table.get("version")?.as_str()?,
                dev,
            )
        })
        .collect()
}

/// poetry.lock and uv.lock without the project itself.
pub fn toml_packages_local(text: &str) -> Vec<Locked> {
    toml_packages(text, true)
}

/// Cargo.lock: only crates from a registry; the project's own have no source.
pub fn cargo_lock(text: &str) -> Vec<Locked> {
    let Ok(doc) = text.parse::<toml::Table>() else {
        return Vec::new();
    };
    let Some(packages) = doc.get("package").and_then(|p| p.as_array()) else {
        return Vec::new();
    };

    packages
        .iter()
        .filter_map(|p| {
            let table = p.as_table()?;
            let source = table.get("source")?.as_str()?;
            if !source.starts_with("registry+") && !source.starts_with("sparse+") {
                return None;
            }
            Locked::new(
                table.get("name")?.as_str()?,
                table.get("version")?.as_str()?,
                false,
            )
        })
        .collect()
}

/// Pipfile.lock: JSON, versions written as `==1.2.3`.
pub fn pipfile_lock(text: &str) -> Vec<Locked> {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (section, dev) in [("default", false), ("develop", true)] {
        let Some(deps) = json.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (name, entry) in deps {
            if let Some(version) = entry
                .get("version")
                .and_then(Value::as_str)
                .and_then(|v| v.strip_prefix("=="))
            {
                out.extend(Locked::new(&normalise_python(name), version, dev));
            }
        }
    }

    out
}

/// An installed Python package's METADATA (or PKG-INFO).
pub fn python_metadata(text: &str) -> Option<Locked> {
    let mut name = None;
    let mut version = None;
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if let Some(n) = line.strip_prefix("Name: ") {
            name.get_or_insert(n.trim());
        } else if let Some(v) = line.strip_prefix("Version: ") {
            version.get_or_insert(v.trim());
        }
    }

    Locked::new(&normalise_python(name?), version?, false)
}

/// PyPI names compare case-insensitively with `-`, `_` and `.` the same.
pub fn normalise_python(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_dash = false;
    for c in name.trim().chars() {
        if matches!(c, '-' | '_' | '.') {
            if !last_dash {
                out.push('-');
            }
            last_dash = true;
        } else {
            out.push(c.to_ascii_lowercase());
            last_dash = false;
        }
    }

    out
}

/// composer.lock, or vendor/composer/installed.json (v1 list or v2 object).
pub fn composer(text: &str) -> Vec<Locked> {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut add = |list: Option<&Value>, dev: bool| {
        for p in list.and_then(Value::as_array).into_iter().flatten() {
            let (Some(name), Some(version)) = (
                p.get("name").and_then(Value::as_str),
                p.get("version").and_then(Value::as_str),
            ) else {
                continue;
            };
            if version.starts_with("dev-") {
                continue;
            }
            out.extend(Locked::new(name, version.trim_start_matches('v'), dev));
        }
    };
    add(json.get("packages"), false);
    add(json.get("packages-dev"), true);
    if json.is_array() {
        add(Some(&json), false);
    }

    out
}

/// Gemfile.lock: the `specs:` of each source, four spaces in.
pub fn gemfile_lock(text: &str) -> Vec<Locked> {
    let mut out = Vec::new();
    let mut in_specs = false;
    let mut in_gem = false;

    for line in text.lines() {
        if !line.starts_with(' ') {
            in_gem = matches!(line.trim(), "GEM");
            in_specs = false;
            continue;
        }
        if line.trim() == "specs:" {
            in_specs = in_gem;
            continue;
        }
        if !in_specs || !line.starts_with("    ") || line.starts_with("     ") {
            continue;
        }
        let Some((name, rest)) = line.trim().split_once(" (") else {
            continue;
        };
        let version = rest.trim_end_matches(')');
        // Native gems carry their platform: `nokogiri (1.15.4-x86_64-linux)`.
        let version = match version.split_once('-') {
            Some((v, platform)) if platform.chars().any(|c| c.is_ascii_alphabetic()) => v,
            _ => version,
        };
        out.extend(Locked::new(name, version, false));
    }

    out
}

/// go.mod's requirements: since Go 1.17 every module the build uses.
pub fn go_mod(text: &str) -> Vec<Locked> {
    let mut out = Vec::new();
    let mut in_block = false;

    for line in text.lines() {
        let line = line.split("//").next().unwrap_or("").trim();
        if line.starts_with("require (") {
            in_block = true;
            continue;
        }
        if in_block && line == ")" {
            in_block = false;
            continue;
        }
        let spec = if in_block {
            line
        } else if let Some(rest) = line.strip_prefix("require ") {
            rest.trim()
        } else {
            continue;
        };
        let mut words = spec.split_whitespace();
        if let (Some(module), Some(version)) = (words.next(), words.next()) {
            out.extend(Locked::new(module, version, false));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(found: &[Locked]) -> Vec<String> {
        found
            .iter()
            .map(|l| {
                format!(
                    "{}@{}{}",
                    l.name,
                    l.version,
                    if l.dev { " dev" } else { "" }
                )
            })
            .collect()
    }

    #[test]
    fn npm_lock_v3() {
        let text = r#"{
          "name": "shop", "lockfileVersion": 3,
          "packages": {
            "": {"name": "shop", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.15"},
            "node_modules/express/node_modules/qs": {"version": "6.7.0"},
            "node_modules/@babel/core": {"version": "7.0.0", "dev": true},
            "node_modules/local": {"resolved": "../local", "link": true},
            "packages/ui": {"version": "0.0.1"}
          }
        }"#;
        let mut found = names(&npm_lock(text));
        found.sort();
        assert_eq!(
            found,
            vec!["@babel/core@7.0.0 dev", "lodash@4.17.15", "qs@6.7.0"]
        );
    }

    #[test]
    fn npm_lock_v1_nested() {
        let text = r#"{"lockfileVersion": 1, "dependencies": {
            "minimist": {"version": "0.0.8", "dependencies": {"x": {"version": "1.0.0", "dev": true}}},
            "git-dep": {"version": "github:me/thing#abc"}
        }}"#;
        assert_eq!(
            names(&npm_lock(text)),
            vec!["minimist@0.0.8", "x@1.0.0 dev"]
        );
    }

    #[test]
    fn yarn_classic_and_berry() {
        let classic = "# yarn lockfile v1\n\n\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n  version \"7.1.2\"\n  resolved \"https://…\"\n\nlodash@^4.17.0:\n  version \"4.17.11\"\n";
        assert_eq!(
            names(&yarn_lock(classic)),
            vec!["@babel/core@7.1.2", "lodash@4.17.11"]
        );

        let berry = "__metadata:\n  version: 6\n\n\"lodash@npm:^4.17.0\":\n  version: 4.17.20\n  resolution: \"lodash@npm:4.17.20\"\n\n\"app@workspace:.\":\n  version: 0.0.0-use.local\n";
        assert_eq!(names(&yarn_lock(berry)), vec!["lodash@4.17.20"]);
    }

    #[test]
    fn pnpm_versions() {
        let v6 = "lockfileVersion: '6.0'\n\npackages:\n\n  /lodash@4.17.21:\n    resolution: {integrity: x}\n\n  /@babel/core@7.0.0(supports-color@5.5.0):\n    dev: true\n";
        assert_eq!(
            names(&pnpm_lock(v6)),
            vec!["lodash@4.17.21", "@babel/core@7.0.0"]
        );
        let v5 = "lockfileVersion: 5.4\npackages:\n  /lodash/4.17.21:\n    resolution: x\n  /@babel/core/7.0.0_supports-color@5.5.0:\n    dev: true\n";
        assert_eq!(
            names(&pnpm_lock(v5)),
            vec!["lodash@4.17.21", "@babel/core@7.0.0"]
        );
        let v9 = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies: {}\npackages:\n  'lodash@4.17.21':\n    resolution: x\nsnapshots:\n  lodash@4.17.21: {}\n";
        assert_eq!(names(&pnpm_lock(v9)), vec!["lodash@4.17.21"]);
    }

    #[test]
    fn requirements_pins_only() {
        let text = "# comment\nDjango==3.2.0\nrequests>=2\nPyYAML[extra]==5.3 ; python_version < \"3.9\"\n-r other.txt\nflask==2.0.* \nurllib3==1.26.4 \\\n    --hash=sha256:abc\n";
        assert_eq!(
            names(&requirements(text)),
            vec!["django@3.2.0", "pyyaml@5.3", "urllib3@1.26.4"]
        );
    }

    #[test]
    fn poetry_and_uv() {
        let poetry = "[[package]]\nname = \"Jinja2\"\nversion = \"2.10\"\ncategory = \"main\"\n\n[[package]]\nname = \"pytest\"\nversion = \"7.0.0\"\ncategory = \"dev\"\n";
        assert_eq!(
            names(&toml_packages(poetry, true)),
            vec!["jinja2@2.10", "pytest@7.0.0 dev"]
        );
        let uv = "version = 1\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n\n[[package]]\nname = \"urllib3\"\nversion = \"2.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n";
        assert_eq!(names(&toml_packages(uv, true)), vec!["urllib3@2.0.0"]);
    }

    #[test]
    fn pipfile_lock_sections() {
        let text = r#"{"default": {"requests": {"version": "==2.19.0"}, "local": {"path": "."}}, "develop": {"black": {"version": "==22.1.0"}}}"#;
        assert_eq!(
            names(&pipfile_lock(text)),
            vec!["requests@2.19.0", "black@22.1.0 dev"]
        );
    }

    #[test]
    fn python_metadata_header() {
        let text = "Metadata-Version: 2.1\nName: Flask_Cors\nVersion: 3.0.8\nSummary: x\n\nName: not this\n";
        assert_eq!(
            names(&[python_metadata(text).unwrap()]),
            vec!["flask-cors@3.0.8"]
        );
    }

    #[test]
    fn composer_lock_and_installed() {
        let lock = r#"{"packages": [{"name": "laravel/framework", "version": "v8.0.0"}, {"name": "x/y", "version": "dev-main"}], "packages-dev": [{"name": "phpunit/phpunit", "version": "9.5.0"}]}"#;
        assert_eq!(
            names(&composer(lock)),
            vec!["laravel/framework@8.0.0", "phpunit/phpunit@9.5.0 dev"]
        );
        let installed_v1 = r#"[{"name": "guzzlehttp/guzzle", "version": "6.5.0"}]"#;
        assert_eq!(
            names(&composer(installed_v1)),
            vec!["guzzlehttp/guzzle@6.5.0"]
        );
    }

    #[test]
    fn gemfile_lock_specs() {
        let text = "GEM\n  remote: https://rubygems.org/\n  specs:\n    actionpack (6.0.0)\n      rack (~> 2.0)\n    nokogiri (1.15.4-x86_64-linux)\n    rack (2.0.7)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails\n";
        assert_eq!(
            names(&gemfile_lock(text)),
            vec!["actionpack@6.0.0", "nokogiri@1.15.4", "rack@2.0.7"]
        );
    }

    #[test]
    fn go_mod_requires() {
        let text = "module example.com/app\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.6.0\n\nrequire (\n\tgolang.org/x/net v0.7.0 // indirect\n\tgopkg.in/yaml.v2 v2.2.2\n)\n";
        assert_eq!(
            names(&go_mod(text)),
            vec![
                "github.com/gin-gonic/gin@v1.6.0",
                "golang.org/x/net@v0.7.0",
                "gopkg.in/yaml.v2@v2.2.2"
            ]
        );
    }

    #[test]
    fn cargo_lock_registry_only() {
        let text = "version = 3\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"time\"\nversion = \"0.1.43\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        assert_eq!(names(&cargo_lock(text)), vec!["time@0.1.43"]);
    }

    #[test]
    fn rubbish_reads_as_nothing() {
        assert!(npm_lock("not json").is_empty());
        assert!(toml_packages("[[[", true).is_empty());
        assert!(composer("{").is_empty());
        assert!(package_json("{}").is_none());
    }
}
