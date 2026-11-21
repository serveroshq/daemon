//! Against a real Docker: `SERVEROS_LIVE_DOCKER=1 cargo test -p daemon-services
//! --test images_live -- --ignored --nocapture`. Needs a container named
//! `sos-upd-app` running an image whose tag the registry has moved on from.

use daemon_services::docker::DockerAdapter;

#[tokio::test]
#[ignore]
async fn lists_reads_packages_and_updates_a_real_container() {
    if std::env::var("SERVEROS_LIVE_DOCKER").is_err() {
        return;
    }
    let docker = DockerAdapter::default();

    let resources = docker.resources().await.unwrap();
    println!(
        "images {} volumes {} cache {}",
        resources["images"].as_array().unwrap().len(),
        resources["volumes"].as_array().unwrap().len(),
        resources["build_cache"]
    );
    assert!(resources["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["name"] == "sos-upd-data"
            && v["containers"] == serde_json::json!(["sos-upd-app"])));

    let inspect = docker.inspect("sos-upd-app").await.unwrap();
    let image = inspect["Image"].as_str().unwrap().to_string();
    let packages = docker.image_packages(&image).await.unwrap();
    println!("os {} manager {}", packages["os"], packages["manager"]);

    if let Ok(debian) = std::env::var("SERVEROS_LIVE_DEBIAN_IMAGE") {
        let packages = docker.image_packages(&debian).await.unwrap();
        println!(
            "debian os {} manager {} packages {} first {}",
            packages["os"],
            packages["manager"],
            packages["packages"].as_array().unwrap().len(),
            packages["packages"][0]
        );
        assert_eq!(packages["manager"], "dpkg");
    }

    let pulled = docker.pull_for("sos-upd-app", &[]).await.unwrap();
    println!("{pulled:?}");
    assert_ne!(pulled.old_image, pulled.new_image);

    let updated = docker
        .recreate_on_new_image("sos-upd-app", &pulled.old_image)
        .await
        .unwrap();
    println!("{updated:?}");
    let after = docker.inspect("sos-upd-app").await.unwrap();
    assert_eq!(after["Image"], pulled.new_image.as_str());
    assert_eq!(after["State"]["Running"], true);
    let mounts = after["Mounts"].as_array().unwrap();
    let before_mounts = inspect["Mounts"].as_array().unwrap();
    for mount in before_mounts {
        assert!(
            mounts.iter().any(|m| m["Name"] == mount["Name"]),
            "lost {mount}"
        );
    }
    assert_eq!(
        after["HostConfig"]["RestartPolicy"]["Name"],
        "unless-stopped"
    );
}

#[tokio::test]
#[ignore]
async fn a_new_image_that_wont_start_puts_the_old_container_back() {
    if std::env::var("SERVEROS_LIVE_ROLLBACK").is_err() {
        return;
    }
    let docker = DockerAdapter::default();
    let before = docker.inspect("sos-upd-app").await.unwrap();
    let pulled = docker.pull_for("sos-upd-app", &[]).await.unwrap();
    let error = docker
        .recreate_on_new_image("sos-upd-app", &pulled.old_image)
        .await
        .unwrap_err();
    println!("{error}");
    let after = docker.inspect("sos-upd-app").await.unwrap();
    assert_eq!(after["Id"], before["Id"]);
    assert_eq!(after["State"]["Running"], true);
}

#[tokio::test]
#[ignore]
async fn removes_only_what_nothing_uses() {
    if std::env::var("SERVEROS_LIVE_PRUNE").is_err() {
        return;
    }
    let docker = DockerAdapter::default();
    let image = std::env::var("SERVEROS_LIVE_PRUNE_IMAGE").unwrap();
    let done = docker
        .prune(
            std::slice::from_ref(&image),
            &["sos-prune-vol".into(), "sos-upd-data".into()],
            false,
        )
        .await
        .unwrap();
    println!("{done}");
    assert_eq!(done["volumes"], serde_json::json!(["sos-prune-vol"]));
    assert_eq!(done["images"][0]["id"], image.as_str());
    assert!(done["skipped"][0]["reason"]
        .as_str()
        .unwrap()
        .contains("sos-upd-app"));
}
