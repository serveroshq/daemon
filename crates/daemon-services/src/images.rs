//! Docker's images, volumes and build cache: what's there and what uses
//! it, removing what nothing uses, updating a container onto a newer image,
//! and reading an image's installed packages.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use base64::Engine;
use daemon_protocol::RegistryLogin;
use serde_json::{json, Value};

use crate::docker::{docker_error, request_full, valid_container_ref, DockerAdapter};
use crate::{Result, ServiceError};

/// How long a pull may take: big images on slow links take minutes.
const PULL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// How long a recreated container gets to show it's up.
const SETTLE: Duration = Duration::from_secs(10);
const SETTLE_MAX: Duration = Duration::from_secs(90);
/// The most of an image's package database read.
const MAX_ARCHIVE: usize = 48 * 1024 * 1024;

pub fn valid_image_id(id: &str) -> bool {
    id.strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()))
}

pub fn valid_volume_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

fn valid_image_ref(reference: &str) -> bool {
    !reference.is_empty()
        && reference.len() <= 512
        && reference
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '/' | ':' | '@'))
}

/// An image reference split for a pull: `(image, tag)`, the tag `latest`
/// when there's none. A reference pinned to a digest has nothing newer.
pub fn split_reference(reference: &str) -> Option<(String, String)> {
    if !valid_image_ref(reference) || reference.contains('@') || reference.starts_with("sha256:") {
        return None;
    }
    let slash = reference.rfind('/').map_or(0, |i| i + 1);
    match reference[slash..].rfind(':') {
        Some(colon) => Some((
            reference[..slash + colon].to_string(),
            reference[slash + colon + 1..].to_string(),
        )),
        None => Some((reference.to_string(), "latest".into())),
    }
}

/// The registry an image comes from, as logins name it: Docker Hub is
/// `docker.io`.
pub fn registry_host(image: &str) -> String {
    match image.split_once('/') {
        Some((first, _)) if first.contains(['.', ':']) || first == "localhost" => {
            first.to_ascii_lowercase()
        }
        _ => "docker.io".into(),
    }
}

fn hub_alias(host: &str) -> bool {
    matches!(
        host,
        "docker.io" | "index.docker.io" | "registry-1.docker.io" | "registry.hub.docker.com"
    )
}

/// The `X-Registry-Auth` header for a pull from `host`, when there's a
/// login for it.
pub fn registry_auth(host: &str, logins: &[RegistryLogin]) -> Option<String> {
    let login = logins.iter().find(|l| {
        let wanted = l.host.trim().to_ascii_lowercase();
        let wanted = wanted
            .strip_prefix("https://")
            .or_else(|| wanted.strip_prefix("http://"))
            .unwrap_or(&wanted);
        // `index.docker.io/v1/` is Docker Hub's old login address.
        let wanted = wanted.split('/').next().unwrap_or("");
        wanted == host || (hub_alias(wanted) && hub_alias(host))
    })?;
    let server = if hub_alias(host) {
        "https://index.docker.io/v1/".to_string()
    } else {
        host.to_string()
    };
    let body = json!({
        "username": login.username,
        "password": login.password.0,
        "serveraddress": server,
    });

    Some(base64::engine::general_purpose::URL_SAFE.encode(body.to_string()))
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn container_name(container: &Value) -> String {
    strings(container.get("Names"))
        .first()
        .map(|n| n.trim_start_matches('/').to_string())
        .unwrap_or_else(|| {
            let id = container.get("Id").and_then(Value::as_str).unwrap_or("");
            id[..id.len().min(12)].to_string()
        })
}

/// What's using images and volumes, from a container listing: image id =>
/// container names, volume name => container names.
fn usage(containers: &[Value]) -> (HashMap<String, Vec<String>>, HashMap<String, Vec<String>>) {
    let mut images: HashMap<String, Vec<String>> = HashMap::new();
    let mut volumes: HashMap<String, Vec<String>> = HashMap::new();
    for container in containers {
        let name = container_name(container);
        if let Some(image) = container.get("ImageID").and_then(Value::as_str) {
            images
                .entry(image.to_string())
                .or_default()
                .push(name.clone());
        }
        for mount in container
            .get("Mounts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if mount.get("Type").and_then(Value::as_str) == Some("volume") {
                if let Some(volume) = mount.get("Name").and_then(Value::as_str) {
                    volumes
                        .entry(volume.to_string())
                        .or_default()
                        .push(name.clone());
                }
            }
        }
    }
    (images, volumes)
}

fn anonymous(name: &str, labels: Option<&Value>) -> bool {
    labels
        .and_then(|l| l.get("com.docker.volume.anonymous"))
        .is_some()
        || (name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit()))
}

/// `/system/df` as what the panel shows: every image and volume, its size
/// and what uses it, and the build cache.
pub fn parse_df(df: &Value) -> Value {
    let containers: Vec<Value> = df
        .get("Containers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let (image_users, volume_users) = usage(&containers);

    let images: Vec<Value> = df
        .get("Images")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|image| {
            let id = image
                .get("Id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let tags: Vec<String> = strings(image.get("RepoTags"))
                .into_iter()
                .filter(|t| t != "<none>:<none>")
                .collect();
            let digests: Vec<String> = strings(image.get("RepoDigests"))
                .into_iter()
                .filter(|d| !d.starts_with("<none>"))
                .collect();
            let users = image_users.get(&id).cloned().unwrap_or_default();
            json!({
                "id": id,
                "tags": tags,
                "digests": digests,
                "size": image.get("Size").and_then(Value::as_i64).unwrap_or(0).max(0),
                "created": image.get("Created").and_then(Value::as_i64).unwrap_or(0),
                "containers": users,
            })
        })
        .collect();

    let volumes: Vec<Value> = df
        .get("Volumes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|volume| {
            let name = volume.get("Name").and_then(Value::as_str).unwrap_or("").to_string();
            let labels = volume.get("Labels");
            // Docker reports -1 when it couldn't size a volume.
            let size = volume
                .pointer("/UsageData/Size")
                .and_then(Value::as_i64)
                .filter(|s| *s >= 0);
            let users = volume_users.get(&name).cloned().unwrap_or_default();
            json!({
                "name": name,
                "driver": volume.get("Driver").and_then(Value::as_str).unwrap_or("local"),
                "size": size,
                "created": volume.get("CreatedAt").and_then(Value::as_str),
                "project": labels.and_then(|l| l.get("com.docker.compose.project")).and_then(Value::as_str),
                "anonymous": anonymous(&name, labels),
                "containers": users,
            })
        })
        .collect();

    let mut cache_size = 0i64;
    let mut cache_reclaimable = 0i64;
    for entry in df
        .get("BuildCache")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let size = entry
            .get("Size")
            .and_then(Value::as_i64)
            .unwrap_or(0)
            .max(0);
        cache_size += size;
        let in_use = entry.get("InUse").and_then(Value::as_bool).unwrap_or(false);
        let shared = entry
            .get("Shared")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !in_use && !shared {
            cache_reclaimable += size;
        }
    }

    json!({
        "images": images,
        "volumes": volumes,
        "build_cache": {"size": cache_size, "reclaimable": cache_reclaimable},
        "containers": containers.len(),
    })
}

/// The settings to create `inspect`'s container again on a newer image:
/// its own config, host config, networks and volumes, with whatever it
/// only had because the old image said so (environment, command, labels,
/// ports, a healthcheck) left out so the new image's apply. Anonymous
/// volumes come along by name, so the data in them stays.
///
/// Returns the create body, and the other networks to join (with their
/// endpoint settings) before it starts.
pub fn update_create_body(
    inspect: &Value,
    image_config: &Value,
) -> Option<(Value, Vec<(String, Value)>)> {
    let mut config = inspect.get("Config")?.clone();
    let mut host = inspect.get("HostConfig")?.clone();
    let id = inspect.get("Id").and_then(Value::as_str).unwrap_or("");
    let short_id = &id[..id.len().min(12)];

    let object = config.as_object_mut()?;
    if let Some(image_env) = image_config.get("Env").and_then(Value::as_array) {
        if let Some(env) = object.get_mut("Env").and_then(Value::as_array_mut) {
            env.retain(|e| !image_env.contains(e));
        }
    }
    for field in [
        "Cmd",
        "Entrypoint",
        "WorkingDir",
        "User",
        "Healthcheck",
        "StopSignal",
        "Shell",
    ] {
        let ours = object.get(field);
        let theirs = image_config.get(field);
        let empty = |v: Option<&Value>| match v {
            None | Some(Value::Null) => true,
            Some(Value::String(s)) => s.is_empty(),
            _ => false,
        };
        if ours == theirs || (empty(ours) && empty(theirs)) {
            object.remove(field);
        }
    }
    for field in ["Labels", "ExposedPorts", "Volumes"] {
        let image_map = image_config.get(field).and_then(Value::as_object).cloned();
        if let (Some(image_map), Some(map)) = (
            image_map,
            object.get_mut(field).and_then(Value::as_object_mut),
        ) {
            map.retain(|key, value| image_map.get(key) != Some(value));
        }
    }
    object.remove("OnBuild");
    if object.get("Hostname").and_then(Value::as_str) == Some(short_id) {
        object.remove("Hostname");
    }

    // Volumes the container got from the image (anonymous ones) and any
    // it was given by name, kept by name so the new container reads the
    // same data.
    let mut taken: BTreeSet<String> = BTreeSet::new();
    for bind in strings(host.get("Binds")) {
        if let Some(target) = bind.split(':').nth(1) {
            taken.insert(target.to_string());
        }
    }
    for mount in host
        .get("Mounts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(target) = mount.get("Target").and_then(Value::as_str) {
            taken.insert(target.to_string());
        }
    }
    let mut kept = Vec::new();
    for mount in inspect
        .get("Mounts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if mount.get("Type").and_then(Value::as_str) != Some("volume") {
            continue;
        }
        let (Some(name), Some(target)) = (
            mount.get("Name").and_then(Value::as_str),
            mount.get("Destination").and_then(Value::as_str),
        ) else {
            continue;
        };
        if taken.contains(target) {
            continue;
        }
        kept.push(json!({
            "Type": "volume",
            "Source": name,
            "Target": target,
            "ReadOnly": !mount.get("RW").and_then(Value::as_bool).unwrap_or(true),
        }));
    }
    if !kept.is_empty() {
        let host_object = host.as_object_mut()?;
        let mounts = host_object
            .entry("Mounts")
            .or_insert_with(|| Value::Array(Vec::new()));
        if mounts.is_null() {
            *mounts = Value::Array(Vec::new());
        }
        mounts.as_array_mut()?.extend(kept);
    }

    let mode = host
        .get("NetworkMode")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mut endpoints: Vec<(String, Value)> = Vec::new();
    if !matches!(mode.as_str(), "host" | "none") && !mode.starts_with("container:") {
        for (name, endpoint) in inspect
            .pointer("/NetworkSettings/Networks")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            let mut settings = serde_json::Map::new();
            let aliases: Vec<Value> = strings(endpoint.get("Aliases"))
                .into_iter()
                .filter(|a| a != short_id)
                .map(Value::String)
                .collect();
            if !aliases.is_empty() {
                settings.insert("Aliases".into(), Value::Array(aliases));
            }
            for field in ["IPAMConfig", "Links", "DriverOpts"] {
                if let Some(value) = endpoint.get(field).filter(|v| !v.is_null()) {
                    settings.insert(field.into(), value.clone());
                }
            }
            endpoints.push((name.clone(), Value::Object(settings)));
        }
    }
    // The network the container is created on first: its own mode's.
    endpoints.sort_by_key(|(name, _)| name != &mode);

    let body_object = config.as_object_mut()?;
    body_object.insert("HostConfig".into(), host);
    let mut more = Vec::new();
    if let Some((first, settings)) = endpoints.first() {
        if !matches!(first.as_str(), "bridge" | "default") || settings.get("IPAMConfig").is_some() {
            body_object.insert(
                "NetworkingConfig".into(),
                json!({ "EndpointsConfig": { first.clone(): settings.clone() } }),
            );
        }
        more = endpoints[1..].to_vec();
    }

    Some((config, more))
}

/// Whether a just-started container looks fine: still running, not
/// restarting, and not unhealthy. `None` means it's too soon to say.
pub fn settled(inspect: &Value, waited: Duration) -> Option<std::result::Result<(), String>> {
    let state = inspect.get("State")?;
    let status = state.get("Status").and_then(Value::as_str).unwrap_or("");
    let restarts = inspect
        .get("RestartCount")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let exit = state.get("ExitCode").and_then(Value::as_i64).unwrap_or(0);
    let health = state.pointer("/Health/Status").and_then(Value::as_str);

    if matches!(status, "exited" | "dead") {
        return Some(Err(format!("it stopped (exit code {exit})")));
    }
    if state.get("Restarting").and_then(Value::as_bool) == Some(true) || restarts > 0 {
        return Some(Err("it keeps restarting".into()));
    }
    if health == Some("unhealthy") {
        return Some(Err("its healthcheck says it's unhealthy".into()));
    }
    if waited < SETTLE {
        return None;
    }
    match health {
        Some("starting") if waited < SETTLE_MAX => None,
        _ => Some(Ok(())),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pulled {
    pub reference: String,
    pub old_image: String,
    pub new_image: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Updated {
    pub name: String,
    pub old_id: String,
    pub new_id: String,
    pub old_kept: bool,
}

impl DockerAdapter {
    async fn get_json(&self, path: &str, what: &str) -> Result<Value> {
        let reply = self.call("GET", path, None, &[200], what).await?;
        Ok(serde_json::from_slice(&reply.body)?)
    }

    pub async fn resources(&self) -> Result<Value> {
        let slow = DockerAdapter {
            socket: self.socket.clone(),
            timeout: Duration::from_secs(150),
        };
        let df = slow.get_json("/system/df", "read disk usage").await?;
        Ok(parse_df(&df))
    }

    async fn containers(&self) -> Result<Vec<Value>> {
        let list = self
            .get_json("/containers/json?all=1", "list containers")
            .await?;
        Ok(list.as_array().cloned().unwrap_or_default())
    }

    /// Removes the images and volumes no container uses, and the build
    /// cache when asked; anything in use is skipped and said so.
    pub async fn prune(
        &self,
        images: &[String],
        volumes: &[String],
        build_cache: bool,
    ) -> Result<Value> {
        let (image_users, volume_users) = usage(&self.containers().await?);
        let mut removed_images = Vec::new();
        let mut removed_volumes = Vec::new();
        let mut skipped = Vec::new();

        for id in images {
            if !valid_image_id(id) {
                skipped.push(json!({"image": id, "reason": "not an image id"}));
                continue;
            }
            if let Some(users) = image_users.get(id) {
                skipped
                    .push(json!({"image": id, "reason": format!("used by {}", users.join(", "))}));
                continue;
            }
            let inspect = match self
                .get_json(&format!("/images/{id}/json"), "inspect image")
                .await
            {
                Ok(inspect) => inspect,
                Err(_) => {
                    // Already gone.
                    removed_images.push(json!({"id": id, "size": 0}));
                    continue;
                }
            };
            let size = inspect.get("Size").and_then(Value::as_i64).unwrap_or(0);
            // Untag first: removing an image with several tags by id needs
            // force, which would also take one a stopped container uses.
            let mut failed = None;
            for tag in strings(inspect.get("RepoTags")) {
                if !valid_image_ref(&tag) {
                    continue;
                }
                if let Err(e) = self
                    .call(
                        "DELETE",
                        &format!("/images/{tag}"),
                        None,
                        &[200, 404],
                        &format!("remove {tag}"),
                    )
                    .await
                {
                    failed = Some(e.to_string());
                    break;
                }
            }
            if failed.is_none() {
                if let Err(e) = self
                    .call(
                        "DELETE",
                        &format!("/images/{id}"),
                        None,
                        &[200, 404],
                        "remove image",
                    )
                    .await
                {
                    failed = Some(e.to_string());
                }
            }
            match failed {
                Some(reason) => skipped.push(json!({"image": id, "reason": reason})),
                None => removed_images.push(json!({"id": id, "size": size})),
            }
        }

        for name in volumes {
            if !valid_volume_name(name) {
                skipped.push(json!({"volume": name, "reason": "not a volume name"}));
                continue;
            }
            if let Some(users) = volume_users.get(name) {
                skipped.push(
                    json!({"volume": name, "reason": format!("used by {}", users.join(", "))}),
                );
                continue;
            }
            match self
                .call(
                    "DELETE",
                    &format!("/volumes/{name}"),
                    None,
                    &[204, 404],
                    &format!("remove volume {name}"),
                )
                .await
            {
                Ok(_) => removed_volumes.push(name.clone()),
                Err(e) => skipped.push(json!({"volume": name, "reason": e.to_string()})),
            }
        }

        let mut cache_reclaimed = 0;
        if build_cache {
            let slow = DockerAdapter {
                socket: self.socket.clone(),
                timeout: Duration::from_secs(300),
            };
            let reply = slow
                .call(
                    "POST",
                    "/build/prune?all=1",
                    None,
                    &[200],
                    "clear the build cache",
                )
                .await?;
            cache_reclaimed = serde_json::from_slice::<Value>(&reply.body)
                .ok()
                .and_then(|v| v.get("SpaceReclaimed").and_then(Value::as_i64))
                .unwrap_or(0);
        }

        Ok(json!({
            "images": removed_images,
            "volumes": removed_volumes,
            "build_cache": cache_reclaimed,
            "skipped": skipped,
        }))
    }

    /// Pulls the image a container was made from again. Says which image
    /// it runs now and which the reference points at after the pull.
    pub async fn pull_for(&self, container: &str, logins: &[RegistryLogin]) -> Result<Pulled> {
        if !valid_container_ref(container) {
            return Err(ServiceError::Docker(format!(
                "{container:?} is not a valid container reference"
            )));
        }
        let inspect = self
            .get_json(
                &format!("/containers/{container}/json"),
                "inspect container",
            )
            .await?;
        let reference = inspect
            .pointer("/Config/Image")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let old_image = inspect
            .get("Image")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let (image, tag) = split_reference(&reference).ok_or_else(|| {
            ServiceError::Docker(format!(
                "{reference} is pinned to one exact image, so there's nothing newer to pull"
            ))
        })?;
        let host = registry_host(&image);
        let headers: Vec<(&str, String)> = registry_auth(&host, logins)
            .map(|auth| vec![("X-Registry-Auth", auth)])
            .unwrap_or_default();

        let reply = request_full(
            &self.socket,
            "POST",
            &format!("/images/create?fromImage={image}&tag={tag}"),
            &headers,
            None,
            PULL_TIMEOUT,
        )
        .await?;
        if reply.status != 200 {
            return Err(docker_error(&reply, &format!("pull {reference}")));
        }
        // A pull that fails part way still answers 200, with the error in
        // the progress stream.
        for line in String::from_utf8_lossy(&reply.body).lines() {
            if let Ok(event) = serde_json::from_str::<Value>(line) {
                if let Some(error) = event.get("error").and_then(Value::as_str) {
                    return Err(ServiceError::Docker(format!("pull {reference}: {error}")));
                }
            }
        }

        let pulled = self
            .get_json(
                &format!("/images/{reference}/json"),
                "inspect the pulled image",
            )
            .await?;
        let new_image = pulled
            .get("Id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        Ok(Pulled {
            reference,
            old_image,
            new_image,
        })
    }

    /// Recreates a container on the image its reference points at now, with
    /// the same settings, and checks it stays up. If it doesn't, the new
    /// one is removed and the old one put back as it was.
    pub async fn recreate_on_new_image(&self, container: &str, old_image: &str) -> Result<Updated> {
        let inspect = self.inspect_with_secrets(container).await?;
        let old_id = inspect
            .get("Id")
            .and_then(Value::as_str)
            .unwrap_or(container)
            .to_string();
        let name = inspect
            .get("Name")
            .and_then(Value::as_str)
            .map(|n| n.trim_start_matches('/').to_string())
            .filter(|n| valid_container_ref(n))
            .ok_or_else(|| ServiceError::Docker(format!("{container} has no usable name")))?;
        let image_config = self
            .get_json(
                &format!("/images/{old_image}/json"),
                "inspect the old image",
            )
            .await
            .ok()
            .and_then(|i| i.get("Config").cloned())
            .unwrap_or(Value::Null);
        let (body, more_networks) = update_create_body(&inspect, &image_config)
            .ok_or_else(|| ServiceError::Docker(format!("couldn't read {name}'s settings")))?;
        let was_running = inspect.pointer("/State/Running").and_then(Value::as_bool) == Some(true);

        if was_running {
            self.call(
                "POST",
                &format!("/containers/{old_id}/stop?t=30"),
                None,
                &[204, 304],
                &format!("stop {name}"),
            )
            .await?;
        }
        let parked = format!("{name}-before-update");
        // A parked copy from an update that didn't finish is in the way.
        let _ = self
            .call(
                "DELETE",
                &format!("/containers/{parked}?v=0"),
                None,
                &[204, 404, 409],
                "clear the old parked copy",
            )
            .await;
        self.call(
            "POST",
            &format!("/containers/{old_id}/rename?name={parked}"),
            None,
            &[204],
            &format!("rename {name}"),
        )
        .await?;

        let put_back = || async {
            let _ = self
                .call(
                    "POST",
                    &format!("/containers/{old_id}/rename?name={name}"),
                    None,
                    &[204],
                    "rename back",
                )
                .await;
            if was_running {
                let _ = self
                    .call(
                        "POST",
                        &format!("/containers/{old_id}/start"),
                        None,
                        &[204, 304],
                        "start the old one",
                    )
                    .await;
            }
        };

        let new_id = match self
            .call(
                "POST",
                &format!("/containers/create?name={name}"),
                Some(&body),
                &[201],
                &format!("create {name}"),
            )
            .await
        {
            Ok(reply) => serde_json::from_slice::<Value>(&reply.body)?
                .get("Id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            Err(e) => {
                put_back().await;
                return Err(e);
            }
        };
        let remove_new = || async {
            let _ = self
                .call(
                    "DELETE",
                    &format!("/containers/{new_id}?force=1&v=0"),
                    None,
                    &[204, 404],
                    "remove the new one",
                )
                .await;
        };

        let started = async {
            for (network, settings) in &more_networks {
                self.call(
                    "POST",
                    &format!("/networks/{network}/connect"),
                    Some(&json!({"Container": new_id, "EndpointConfig": settings})),
                    &[200],
                    &format!("connect {name} to {network}"),
                )
                .await?;
            }
            if !was_running {
                return Ok(());
            }
            self.call(
                "POST",
                &format!("/containers/{new_id}/start"),
                None,
                &[204, 304],
                &format!("start {name}"),
            )
            .await?;
            let began = std::time::Instant::now();
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let now = self
                    .get_json(
                        &format!("/containers/{new_id}/json"),
                        "check the new container",
                    )
                    .await?;
                match settled(&now, began.elapsed()) {
                    None => continue,
                    Some(Ok(())) => return Ok(()),
                    Some(Err(why)) => {
                        let logs = self.tail(&new_id).await;
                        return Err(ServiceError::Docker(format!(
                            "{name} didn't stay up on the new image: {why}{logs}"
                        )));
                    }
                }
            }
        }
        .await;
        if let Err(e) = started {
            remove_new().await;
            put_back().await;
            let e = e.to_string();
            let e = e.strip_prefix("docker did not answer: ").unwrap_or(&e);
            return Err(ServiceError::Command(format!(
                "{e}\nThe old container is back as it was."
            )));
        }

        let old_kept = self
            .call(
                "DELETE",
                &format!("/containers/{old_id}?v=0"),
                None,
                &[204, 404],
                "remove the old one",
            )
            .await
            .is_err();

        Ok(Updated {
            name,
            old_id,
            new_id,
            old_kept,
        })
    }

    async fn tail(&self, id: &str) -> String {
        match self
            .call(
                "GET",
                &format!("/containers/{id}/logs?stdout=1&stderr=1&tail=15"),
                None,
                &[200],
                "logs",
            )
            .await
        {
            Ok(reply) => {
                let text = crate::docker::demux_log_stream(&reply.body);
                let text = text.trim();
                if text.is_empty() {
                    String::new()
                } else {
                    format!(". Its last lines:\n{}", daemon_core::ipmask::outgoing(text))
                }
            }
            Err(_) => String::new(),
        }
    }

    async fn archive(&self, container: &str, path: &str) -> Option<Vec<TarEntry>> {
        let reply = self
            .call(
                "GET",
                &format!("/containers/{container}/archive?path={path}"),
                None,
                &[200],
                "read",
            )
            .await
            .ok()?;
        if reply.body.len() > MAX_ARCHIVE {
            return None;
        }
        Some(read_tar(&reply.body))
    }

    /// An image's OS release and installed packages, read from a container
    /// made from it (one that's there already, or one made for this and
    /// removed again). Nothing inside the image runs.
    pub async fn image_packages(&self, image: &str) -> Result<Value> {
        if !valid_image_id(image) {
            return Err(ServiceError::Docker(format!(
                "{image:?} is not an image id"
            )));
        }
        let existing = self
            .containers()
            .await?
            .into_iter()
            .find(|c| c.get("ImageID").and_then(Value::as_str) == Some(image))
            .and_then(|c| c.get("Id").and_then(Value::as_str).map(str::to_string));
        let (container, made) = match existing {
            Some(id) => (id, false),
            None => {
                let reply = self
                    .call(
                        "POST",
                        "/containers/create",
                        Some(&json!({
                            "Image": image,
                            "Entrypoint": ["/serveros-never-runs"],
                            "Labels": {"com.serveros.scan": "1"},
                            "NetworkDisabled": true,
                        })),
                        &[201],
                        "make a container to read the image",
                    )
                    .await?;
                let id = serde_json::from_slice::<Value>(&reply.body)?
                    .get("Id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                (id, true)
            }
        };

        let mut os = BTreeMap::new();
        for path in ["/etc/os-release", "/usr/lib/os-release"] {
            if let Some(entries) = self.archive(&container, path).await {
                if let Some(file) = entries.iter().find(|e| e.regular) {
                    os = parse_os_release(&String::from_utf8_lossy(&file.data));
                    break;
                }
            }
        }

        let mut manager = Value::Null;
        let mut packages = Vec::new();
        if let Some(entries) = self.archive(&container, "/var/lib/dpkg/status").await {
            if let Some(file) = entries.iter().find(|e| e.regular) {
                manager = json!("dpkg");
                packages = parse_dpkg(&String::from_utf8_lossy(&file.data));
            }
        }
        if packages.is_empty() {
            // Distroless images keep one file per package.
            if let Some(entries) = self.archive(&container, "/var/lib/dpkg/status.d").await {
                for file in entries
                    .iter()
                    .filter(|e| e.regular && !e.name.ends_with(".md5sums"))
                {
                    packages.extend(parse_dpkg(&String::from_utf8_lossy(&file.data)));
                }
                if !packages.is_empty() {
                    manager = json!("dpkg");
                }
            }
        }
        if packages.is_empty() {
            if let Some(entries) = self.archive(&container, "/lib/apk/db/installed").await {
                if let Some(file) = entries.iter().find(|e| e.regular) {
                    manager = json!("apk");
                    packages = parse_apk(&String::from_utf8_lossy(&file.data));
                }
            }
        }

        if made {
            let _ = self
                .call(
                    "DELETE",
                    &format!("/containers/{container}?force=1&v=1"),
                    None,
                    &[204, 404],
                    "remove",
                )
                .await;
        }
        packages.truncate(5000);

        Ok(json!({
            "image": image,
            "os": {"id": os.get("ID"), "version_id": os.get("VERSION_ID")},
            "manager": manager,
            "packages": packages,
        }))
    }
}

pub fn parse_os_release(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| {
            (
                k.trim().to_string(),
                v.trim().trim_matches(['"', '\'']).to_string(),
            )
        })
        .collect()
}

/// `name (version)` or `name`, as dpkg writes a Source field.
fn source_field(value: &str) -> (String, Option<String>) {
    match value.split_once(' ') {
        Some((name, version)) => (
            name.to_string(),
            Some(version.trim().trim_matches(['(', ')']).to_string()),
        ),
        None => (value.to_string(), None),
    }
}

/// dpkg's status database: the packages installed.
pub fn parse_dpkg(text: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for stanza in text.split("\n\n") {
        let mut fields: HashMap<&str, &str> = HashMap::new();
        for line in stanza.lines() {
            if line.starts_with([' ', '\t']) {
                continue;
            }
            if let Some((key, value)) = line.split_once(':') {
                fields.insert(key.trim(), value.trim());
            }
        }
        let (Some(name), Some(version)) = (fields.get("Package"), fields.get("Version")) else {
            continue;
        };
        // Distroless files have no Status line; dpkg's own database does.
        if fields
            .get("Status")
            .is_some_and(|s| !s.ends_with(" installed"))
        {
            continue;
        }
        let (source, source_version) = fields
            .get("Source")
            .map(|s| source_field(s))
            .unwrap_or_else(|| (name.to_string(), None));
        out.push(json!({
            "name": name,
            "version": version,
            "source": source,
            "source_version": source_version.unwrap_or_else(|| version.to_string()),
        }));
    }
    out
}

/// apk's installed database.
pub fn parse_apk(text: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for stanza in text.split("\n\n") {
        let mut name = None;
        let mut version = None;
        let mut origin = None;
        for line in stanza.lines() {
            match line.split_once(':') {
                Some(("P", v)) => name = Some(v.trim()),
                Some(("V", v)) => version = Some(v.trim()),
                Some(("o", v)) => origin = Some(v.trim()),
                _ => {}
            }
        }
        if let (Some(name), Some(version)) = (name, version) {
            out.push(json!({
                "name": name,
                "version": version,
                "source": origin.unwrap_or(name),
                "source_version": version,
            }));
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarEntry {
    pub name: String,
    pub regular: bool,
    pub data: Vec<u8>,
}

fn octal(field: &[u8]) -> usize {
    let text = String::from_utf8_lossy(field);
    usize::from_str_radix(
        text.trim_matches(|c: char| c == '\0' || c.is_whitespace()),
        8,
    )
    .unwrap_or(0)
}

fn c_string(field: &[u8]) -> String {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// The files in an uncompressed tar, as Docker's archive endpoint sends
/// them: names (with GNU and pax long names) and regular files' contents.
pub fn read_tar(raw: &[u8]) -> Vec<TarEntry> {
    let mut out = Vec::new();
    let mut cursor = 0;
    let mut long_name: Option<String> = None;
    while cursor + 512 <= raw.len() {
        let header = &raw[cursor..cursor + 512];
        if header.iter().all(|b| *b == 0) {
            break;
        }
        let size = octal(&header[124..136]);
        let kind = header[156];
        let start = cursor + 512;
        let end = (start + size).min(raw.len());
        let data = &raw[start..end];
        cursor = start + size.div_ceil(512) * 512;

        match kind {
            b'L' => {
                long_name = Some(c_string(data));
                continue;
            }
            b'x' => {
                let text = String::from_utf8_lossy(data);
                for record in text.lines() {
                    if let Some(path) = record
                        .split_once(' ')
                        .and_then(|(_, kv)| kv.strip_prefix("path="))
                    {
                        long_name = Some(path.to_string());
                    }
                }
                continue;
            }
            b'g' => continue,
            _ => {}
        }

        let mut name = c_string(&header[0..100]);
        if &header[257..262] == b"ustar" {
            let prefix = c_string(&header[345..500]);
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        let name = long_name.take().unwrap_or(name);
        let regular = matches!(kind, b'0' | 0);
        out.push(TarEntry {
            name,
            regular,
            data: if regular { data.to_vec() } else { Vec::new() },
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_split_into_image_and_tag() {
        assert_eq!(
            split_reference("postgres:16-bookworm"),
            Some(("postgres".into(), "16-bookworm".into()))
        );
        assert_eq!(
            split_reference("nginx"),
            Some(("nginx".into(), "latest".into()))
        );
        assert_eq!(
            split_reference("registry.example.com:5000/team/app"),
            Some(("registry.example.com:5000/team/app".into(), "latest".into()))
        );
        assert_eq!(
            split_reference("ghcr.io/serveroshq/panel:1.4"),
            Some(("ghcr.io/serveroshq/panel".into(), "1.4".into()))
        );
        assert_eq!(split_reference("redis@sha256:abc"), None);
        assert_eq!(split_reference("sha256:abc"), None);
        assert_eq!(split_reference("bad ref"), None);
    }

    #[test]
    fn registry_logins_match_the_image_host() {
        assert_eq!(registry_host("postgres"), "docker.io");
        assert_eq!(registry_host("bitnami/redis"), "docker.io");
        assert_eq!(registry_host("ghcr.io/a/b"), "ghcr.io");
        assert_eq!(registry_host("localhost:5000/b"), "localhost:5000");

        let logins = vec![RegistryLogin {
            host: "https://index.docker.io/v1/".into(),
            username: "me".into(),
            password: daemon_protocol::RepoToken("pw".into()),
        }];
        let header = registry_auth("docker.io", &logins).unwrap();
        let decoded = base64::engine::general_purpose::URL_SAFE
            .decode(header)
            .unwrap();
        let value: Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(value["username"], "me");
        assert_eq!(value["password"], "pw");
        assert!(registry_auth("ghcr.io", &logins).is_none());
    }

    #[test]
    fn disk_usage_says_what_uses_each_image_and_volume() {
        let df = json!({
            "Images": [
                {"Id": "sha256:1", "RepoTags": ["postgres:16"], "RepoDigests": ["postgres@sha256:aa"], "Size": 400, "Created": 10},
                {"Id": "sha256:2", "RepoTags": ["<none>:<none>"], "RepoDigests": null, "Size": 50, "Created": 5}
            ],
            "Containers": [
                {"Id": "c1", "Names": ["/db"], "ImageID": "sha256:1", "Mounts": [{"Type": "volume", "Name": "pgdata"}, {"Type": "bind", "Source": "/srv"}]}
            ],
            "Volumes": [
                {"Name": "pgdata", "Driver": "local", "Labels": {"com.docker.compose.project": "shop"}, "UsageData": {"Size": 900, "RefCount": 1}},
                {"Name": "0f01188517dfb7a240072ee9e2705ffaa5309984a0811962ae5e8cd9988e4d61", "Driver": "local", "Labels": null, "UsageData": {"Size": -1, "RefCount": 0}}
            ],
            "BuildCache": [
                {"Size": 100, "InUse": false, "Shared": false},
                {"Size": 30, "InUse": true, "Shared": false}
            ]
        });
        let out = parse_df(&df);

        assert_eq!(out["images"][0]["containers"], json!(["db"]));
        assert_eq!(out["images"][1]["tags"], json!([]));
        assert_eq!(out["images"][1]["containers"], json!([]));
        assert_eq!(out["volumes"][0]["containers"], json!(["db"]));
        assert_eq!(out["volumes"][0]["project"], "shop");
        assert_eq!(out["volumes"][1]["size"], Value::Null);
        assert_eq!(out["volumes"][1]["anonymous"], true);
        assert_eq!(out["build_cache"], json!({"size": 130, "reclaimable": 100}));
    }

    #[test]
    fn a_recreated_container_keeps_its_settings_but_takes_the_new_image_s_defaults() {
        let inspect = json!({
            "Id": "abcdef1234567890",
            "Image": "sha256:old",
            "Config": {
                "Hostname": "abcdef123456",
                "Image": "postgres:16",
                "Env": ["POSTGRES_PASSWORD=secret", "PG_VERSION=16.4", "PATH=/usr/bin"],
                "Cmd": ["postgres"],
                "Entrypoint": ["docker-entrypoint.sh"],
                "Labels": {"com.docker.compose.service": "db", "org.opencontainers.image.version": "16.4"},
                "ExposedPorts": {"5432/tcp": {}},
                "WorkingDir": "",
                "Volumes": {"/var/lib/postgresql/data": {}}
            },
            "HostConfig": {"NetworkMode": "shop_default", "Binds": ["/srv/conf:/etc/conf:ro"], "RestartPolicy": {"Name": "unless-stopped"}},
            "Mounts": [
                {"Type": "volume", "Name": "4f5e", "Destination": "/var/lib/postgresql/data", "RW": true},
                {"Type": "bind", "Source": "/srv/conf", "Destination": "/etc/conf", "RW": false}
            ],
            "NetworkSettings": {"Networks": {
                "shop_default": {"Aliases": ["db", "abcdef123456"], "IPAMConfig": null},
                "monitoring": {"Aliases": ["db"]}
            }}
        });
        let image = json!({
            "Env": ["PG_VERSION=16.4", "PATH=/usr/bin"],
            "Cmd": ["postgres"],
            "Entrypoint": ["docker-entrypoint.sh"],
            "Labels": {"org.opencontainers.image.version": "16.4"},
            "ExposedPorts": {"5432/tcp": {}},
            "WorkingDir": "",
            "Volumes": {"/var/lib/postgresql/data": {}}
        });

        let (body, more) = update_create_body(&inspect, &image).unwrap();

        assert_eq!(body["Image"], "postgres:16");
        assert_eq!(body["Env"], json!(["POSTGRES_PASSWORD=secret"]));
        assert!(body.get("Cmd").is_none() && body.get("Entrypoint").is_none());
        assert!(body.get("Hostname").is_none());
        assert_eq!(body["Labels"], json!({"com.docker.compose.service": "db"}));
        assert_eq!(body["ExposedPorts"], json!({}));
        // The anonymous volume comes along by name; the bind is already there.
        assert_eq!(
            body["HostConfig"]["Mounts"],
            json!([{"Type": "volume", "Source": "4f5e", "Target": "/var/lib/postgresql/data", "ReadOnly": false}])
        );
        assert_eq!(
            body["HostConfig"]["RestartPolicy"]["Name"],
            "unless-stopped"
        );
        assert_eq!(
            body["NetworkingConfig"],
            json!({"EndpointsConfig": {"shop_default": {"Aliases": ["db"]}}})
        );
        assert_eq!(
            more,
            vec![("monitoring".to_string(), json!({"Aliases": ["db"]}))]
        );
    }

    #[test]
    fn a_container_on_host_networking_joins_no_networks() {
        let inspect = json!({
            "Id": "abc",
            "Config": {"Image": "app:1"},
            "HostConfig": {"NetworkMode": "host"},
            "NetworkSettings": {"Networks": {"host": {}}}
        });
        let (body, more) = update_create_body(&inspect, &Value::Null).unwrap();
        assert!(body.get("NetworkingConfig").is_none());
        assert!(more.is_empty());
    }

    #[test]
    fn a_new_container_has_to_stay_up() {
        let running =
            json!({"State": {"Status": "running", "Restarting": false}, "RestartCount": 0});
        assert_eq!(settled(&running, Duration::from_secs(2)), None);
        assert_eq!(settled(&running, Duration::from_secs(12)), Some(Ok(())));

        let exited = json!({"State": {"Status": "exited", "ExitCode": 1}, "RestartCount": 0});
        assert!(matches!(
            settled(&exited, Duration::from_secs(2)),
            Some(Err(_))
        ));

        let looping =
            json!({"State": {"Status": "running", "Restarting": false}, "RestartCount": 2});
        assert!(matches!(
            settled(&looping, Duration::from_secs(2)),
            Some(Err(_))
        ));

        let starting = json!({"State": {"Status": "running", "Health": {"Status": "starting"}}, "RestartCount": 0});
        assert_eq!(settled(&starting, Duration::from_secs(30)), None);
        assert_eq!(settled(&starting, Duration::from_secs(95)), Some(Ok(())));

        let unhealthy = json!({"State": {"Status": "running", "Health": {"Status": "unhealthy"}}, "RestartCount": 0});
        assert!(matches!(
            settled(&unhealthy, Duration::from_secs(30)),
            Some(Err(_))
        ));
    }

    #[test]
    fn reads_dpkg_and_apk_databases() {
        let dpkg = "Package: libssl3\nStatus: install ok installed\nVersion: 3.0.15-1~deb12u1\nSource: openssl\nDescription: x\n continued\n\nPackage: zlib1g\nStatus: install ok installed\nSource: zlib (1:1.2.13.dfsg-1)\nVersion: 1:1.2.13.dfsg-1\n\nPackage: gone\nStatus: deinstall ok config-files\nVersion: 1\n\nPackage: bash\nStatus: install ok installed\nVersion: 5.2.15-2+b7\n";
        let packages = parse_dpkg(dpkg);
        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0]["source"], "openssl");
        assert_eq!(packages[0]["source_version"], "3.0.15-1~deb12u1");
        assert_eq!(packages[1]["source"], "zlib");
        assert_eq!(packages[1]["source_version"], "1:1.2.13.dfsg-1");
        assert_eq!(packages[2]["source"], "bash");

        let apk = "C:Q1abc\nP:libcrypto3\nV:3.3.2-r0\no:openssl\n\nP:musl\nV:1.2.5-r0\n";
        let packages = parse_apk(apk);
        assert_eq!(packages[0]["source"], "openssl");
        assert_eq!(packages[1]["source"], "musl");

        let os = parse_os_release("ID=debian\nVERSION_ID=\"12\"\n");
        assert_eq!(os["VERSION_ID"], "12");
    }

    fn tar_file(name: &str, data: &[u8]) -> Vec<u8> {
        let mut header = vec![0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let size = format!("{:011o}\0", data.len());
        header[124..136].copy_from_slice(size.as_bytes());
        header[156] = b'0';
        header[257..262].copy_from_slice(b"ustar");
        let mut out = header;
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
        out
    }

    #[test]
    fn reads_docker_s_archive_tar() {
        let mut raw = tar_file("status", b"Package: a\nVersion: 1\n");
        raw.extend(tar_file("other", b"x"));
        raw.extend(vec![0u8; 1024]);
        let entries = read_tar(&raw);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "status");
        assert_eq!(entries[0].data, b"Package: a\nVersion: 1\n");
        assert!(entries[1].regular);
    }

    #[test]
    fn only_real_ids_and_names_are_removed() {
        assert!(valid_image_id(&format!("sha256:{}", "a".repeat(64))));
        assert!(!valid_image_id("sha256:abc"));
        assert!(!valid_image_id("postgres"));
        assert!(valid_volume_name("shop_pgdata"));
        assert!(!valid_volume_name("../etc"));
    }
}
