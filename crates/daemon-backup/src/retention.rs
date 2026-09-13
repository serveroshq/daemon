//! Conservative pruning: keep the newest `keep`, and never, ever delete
//! the only remaining snapshot.

use crate::snapshot::Manifest;

/// Snapshots to delete, oldest first. `manifests` must be sorted by
/// `created_at` ascending.
pub fn to_prune(manifests: &[Manifest], keep: usize) -> Vec<Manifest> {
    let keep = keep.max(1);

    if manifests.len() <= keep {
        return Vec::new();
    }

    manifests[..manifests.len() - keep].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(id: &str, ts: i64) -> Manifest {
        Manifest {
            service: "x".into(),
            id: id.into(),
            created_at: ts,
            reason: "t".into(),
            strategy: "tar".into(),
            files: vec![],
            total_bytes: 0,
            uploaded_to: None,
        }
    }

    #[test]
    fn keeps_the_newest_and_never_the_last() {
        let all = vec![manifest("a", 1), manifest("b", 2), manifest("c", 3)];

        assert_eq!(
            to_prune(&all, 2)
                .iter()
                .map(|m| m.id.as_str())
                .collect::<Vec<_>>(),
            vec!["a"]
        );
        assert!(to_prune(&all, 5).is_empty());
        assert_eq!(to_prune(&all, 0).len(), 2, "keep=0 still keeps one");
        assert!(to_prune(&all[..1], 0).is_empty());
    }
}
