//! Planning a copy of a running container from its `docker inspect`: what
//! each of its mounts becomes, which port it's published on, and the create
//! request. Pure, so it can be tested; the work happens in serverosd.

use serde_json::{json, Value};

/// What happens to one of the original's mounts in the copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountPlan {
    /// A named or anonymous volume: the copy gets a new volume of its own,
    /// filled from the original's when data is copied.
    Volume {
        from: String,
        to: String,
        destination: String,
    },
    /// A folder or file on the machine: the copy gets its own under the
    /// clones folder. Files (usually config) are always copied; folders
    /// only when data is.
    Bind {
        from: String,
        destination: String,
        file: bool,
    },
    /// Read-only, or part of the machine (the Docker socket, /etc/localtime):
    /// shared as it is, which can't change anything.
    Shared {
        source: String,
        destination: String,
        read_only: bool,
    },
}

/// Paths a copy shares rather than copies: the machine's own, not the
/// service's data.
fn is_system_path(path: &str) -> bool {
    path == "/var/run/docker.sock"
        || path == "/run/docker.sock"
        || [
            "/proc",
            "/sys",
            "/dev",
            "/run",
            "/var/run",
            "/etc/localtime",
            "/etc/timezone",
            "/etc/hosts",
            "/etc/resolv.conf",
        ]
        .iter()
        .any(|p| path == *p || path.starts_with(&format!("{p}/")))
}

/// The copy's name for one of the original's volumes.
pub fn volume_name(clone: &str, volume: &str) -> String {
    let short: String = volume
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .take(40)
        .collect();
    format!("{clone}-{short}")
}

/// What each of the original's mounts becomes. `is_file` says whether a
/// bind source is a file (asked of the machine).
pub fn mount_plan(inspect: &Value, clone: &str, is_file: impl Fn(&str) -> bool) -> Vec<MountPlan> {
    let mounts = inspect
        .get("Mounts")
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();
    mounts
        .iter()
        .filter_map(|m| {
            let kind = m.get("Type")?.as_str()?;
            let destination = m.get("Destination")?.as_str()?.to_string();
            let source = m
                .get("Source")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let read_only = !m.get("RW").and_then(|r| r.as_bool()).unwrap_or(true);
            match kind {
                "volume" => {
                    let name = m.get("Name")?.as_str()?.to_string();
                    Some(MountPlan::Volume {
                        to: volume_name(clone, &name),
                        from: name,
                        destination,
                    })
                }
                "bind" if read_only || is_system_path(&source) => Some(MountPlan::Shared {
                    source,
                    destination,
                    read_only,
                }),
                "bind" => Some(MountPlan::Bind {
                    file: is_file(&source),
                    from: source,
                    destination,
                }),
                _ => None,
            }
        })
        .collect()
}

/// The port the copy is reached on: the one asked for if the original has
/// it, else the first it publishes, else the first it exposes (tcp first).
/// Like "80/tcp".
pub fn main_port(inspect: &Value, wanted: Option<u16>) -> Option<String> {
    let mut ports: Vec<String> = Vec::new();
    for pointer in ["/HostConfig/PortBindings", "/Config/ExposedPorts"] {
        if let Some(map) = inspect.pointer(pointer).and_then(|p| p.as_object()) {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by_key(|k| {
                (
                    !k.ends_with("/tcp"),
                    k.split('/')
                        .next()
                        .and_then(|p| p.parse::<u16>().ok())
                        .unwrap_or(u16::MAX),
                )
            });
            ports.extend(keys.into_iter().cloned());
        }
    }
    if let Some(port) = wanted {
        let tcp = format!("{port}/tcp");
        return Some(if ports.iter().any(|p| p == &tcp) {
            tcp
        } else {
            ports
                .into_iter()
                .find(|p| p.starts_with(&format!("{port}/")))
                .unwrap_or(tcp)
        });
    }
    ports.into_iter().next()
}

/// Where a bind becomes the copy's own, under the clones folder.
pub fn bind_target(clones_dir: &str, clone: &str, index: usize, from: &str) -> String {
    let base: String = from
        .rsplit('/')
        .next()
        .unwrap_or("data")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .collect();
    format!(
        "{clones_dir}/{clone}/{index}-{}",
        if base.is_empty() { "data" } else { &base }
    )
}

/// The copy's create request and the extra networks it joins after. Same
/// image, command, environment, user and working folder as the original;
/// its own name and hostname; no compose labels (it isn't part of the
/// original's project) and no network aliases (or it would answer to the
/// original's name); `binds` for its mounts; published only on `port`
/// (container port, host address, host port), if any.
pub fn create_body(
    inspect: &Value,
    source_name: &str,
    binds: Vec<String>,
    port: Option<(String, String, u16)>,
) -> Option<(Value, Vec<String>)> {
    let mut body = inspect.get("Config")?.clone();
    let config = body.as_object_mut()?;
    config.remove("Hostname");
    config.remove("Domainname");
    config.remove("MacAddress");
    let mut labels = config
        .get("Labels")
        .and_then(|l| l.as_object())
        .cloned()
        .unwrap_or_default();
    labels.retain(|k, _| !k.starts_with("com.docker.compose."));
    labels.insert("com.serveros.managed".into(), json!("true"));
    labels.insert("com.serveros.clone-of".into(), json!(source_name));
    config.insert("Labels".into(), Value::Object(labels));
    config.insert(
        "ExposedPorts".into(),
        match &port {
            Some((container_port, _, _)) => json!({ container_port: {} }),
            None => config.get("ExposedPorts").cloned().unwrap_or(json!({})),
        },
    );

    let source_host = inspect.get("HostConfig")?;
    let mut host = serde_json::Map::new();
    for field in [
        "NetworkMode",
        "CapAdd",
        "CapDrop",
        "Privileged",
        "Memory",
        "NanoCpus",
        "ShmSize",
        "Ulimits",
        "ExtraHosts",
        "SecurityOpt",
        "Tmpfs",
        "Init",
        "Devices",
        "GroupAdd",
        "Sysctls",
        "LogConfig",
    ] {
        if let Some(value) = source_host.get(field).filter(|v| !v.is_null()) {
            host.insert(field.into(), value.clone());
        }
    }
    host.insert("Binds".into(), json!(binds));
    host.insert(
        "RestartPolicy".into(),
        json!({"Name": "unless-stopped", "MaximumRetryCount": 0}),
    );
    host.insert(
        "PortBindings".into(),
        match &port {
            Some((container_port, address, host_port)) => json!({ container_port: [{ "HostIp": address, "HostPort": host_port.to_string() }] }),
            None => json!({}),
        },
    );
    config.insert("HostConfig".into(), Value::Object(host));

    let mode = source_host
        .get("NetworkMode")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    let networks: Vec<String> = inspect
        .pointer("/NetworkSettings/Networks")
        .and_then(|n| n.as_object())
        .map(|n| n.keys().cloned().collect())
        .unwrap_or_default();
    let more = networks
        .into_iter()
        .filter(|n| n != &mode && !matches!(n.as_str(), "bridge" | "host" | "none" | "default"))
        .collect();

    Some((body, more))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspect() -> Value {
        json!({
            "Name": "/shop-db-1",
            "Config": {
                "Hostname": "abc123",
                "Image": "postgres:16",
                "Env": ["POSTGRES_PASSWORD=secret", "POSTGRES_USER=shop"],
                "Cmd": ["postgres"],
                "ExposedPorts": {"5432/tcp": {}},
                "Labels": {"com.docker.compose.project": "shop", "com.docker.compose.service": "db", "team": "web"}
            },
            "HostConfig": {
                "NetworkMode": "shop_default",
                "PortBindings": {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}]},
                "RestartPolicy": {"Name": "always"},
                "Binds": ["shop_data:/var/lib/postgresql/data:rw"]
            },
            "Mounts": [
                {"Type": "volume", "Name": "shop_data", "Source": "/var/lib/docker/volumes/shop_data/_data", "Destination": "/var/lib/postgresql/data", "RW": true},
                {"Type": "bind", "Source": "/srv/shop/init.sql", "Destination": "/docker-entrypoint-initdb.d/init.sql", "RW": true},
                {"Type": "bind", "Source": "/srv/shop/certs", "Destination": "/certs", "RW": false},
                {"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": true},
                {"Type": "bind", "Source": "/srv/shop/uploads", "Destination": "/uploads", "RW": true}
            ],
            "NetworkSettings": {"Networks": {"shop_default": {"Aliases": ["db"]}, "monitoring": {}}}
        })
    }

    #[test]
    fn mounts_become_the_copys_own_unless_read_only_or_the_machines() {
        let plan = mount_plan(&inspect(), "shop-db-test", |p| p.ends_with(".sql"));
        assert_eq!(
            plan,
            vec![
                MountPlan::Volume {
                    from: "shop_data".into(),
                    to: "shop-db-test-shop_data".into(),
                    destination: "/var/lib/postgresql/data".into()
                },
                MountPlan::Bind {
                    from: "/srv/shop/init.sql".into(),
                    destination: "/docker-entrypoint-initdb.d/init.sql".into(),
                    file: true
                },
                MountPlan::Shared {
                    source: "/srv/shop/certs".into(),
                    destination: "/certs".into(),
                    read_only: true
                },
                MountPlan::Shared {
                    source: "/var/run/docker.sock".into(),
                    destination: "/var/run/docker.sock".into(),
                    read_only: false
                },
                MountPlan::Bind {
                    from: "/srv/shop/uploads".into(),
                    destination: "/uploads".into(),
                    file: false
                },
            ]
        );
    }

    #[test]
    fn the_main_port_is_the_one_asked_for_or_the_first_published() {
        assert_eq!(main_port(&inspect(), None).as_deref(), Some("5432/tcp"));
        assert_eq!(
            main_port(&inspect(), Some(5432)).as_deref(),
            Some("5432/tcp")
        );
        assert_eq!(
            main_port(&inspect(), Some(8080)).as_deref(),
            Some("8080/tcp")
        );
        assert_eq!(main_port(&json!({"Config": {}}), None), None);
    }

    #[test]
    fn the_copy_has_its_own_name_ports_and_mounts_and_no_compose_labels_or_aliases() {
        let (body, more) = create_body(
            &inspect(),
            "shop-db-1",
            vec!["shop-db-test-shop_data:/var/lib/postgresql/data".into()],
            Some(("5432/tcp".into(), "127.0.0.1".into(), 15432)),
        )
        .unwrap();

        assert!(body.get("Hostname").is_none());
        assert_eq!(
            body["Env"],
            json!(["POSTGRES_PASSWORD=secret", "POSTGRES_USER=shop"])
        );
        assert_eq!(
            body["Labels"],
            json!({"team": "web", "com.serveros.managed": "true", "com.serveros.clone-of": "shop-db-1"})
        );
        assert_eq!(
            body["HostConfig"]["PortBindings"],
            json!({"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "15432"}]})
        );
        assert_eq!(
            body["HostConfig"]["Binds"],
            json!(["shop-db-test-shop_data:/var/lib/postgresql/data"])
        );
        assert_eq!(body["HostConfig"]["NetworkMode"], json!("shop_default"));
        assert_eq!(
            body["HostConfig"]["RestartPolicy"]["Name"],
            json!("unless-stopped")
        );
        assert!(
            body.get("NetworkingConfig").is_none(),
            "no aliases: it mustn't answer to the original's name"
        );
        assert_eq!(more, vec!["monitoring".to_string()]);

        let (unpublished, _) = create_body(&inspect(), "s", vec![], None).unwrap();
        assert_eq!(unpublished["HostConfig"]["PortBindings"], json!({}));
    }

    #[test]
    fn names_stay_tidy() {
        assert_eq!(
            volume_name("shop-test", "4f2a/../x y"),
            "shop-test-4f2a..xy"
        );
        assert_eq!(
            bind_target(
                "/var/lib/serverosd/clones",
                "shop-test",
                1,
                "/srv/shop/uploads"
            ),
            "/var/lib/serverosd/clones/shop-test/1-uploads"
        );
    }
}
