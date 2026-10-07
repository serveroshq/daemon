#!/usr/bin/env bash
# Locks down serveroshq/daemon so only maintainers can ship a release.
# Run once, right after making the repository public (rulesets and
# environment reviewers need a public repo on GitHub's free plan).
#
#   scripts/protect-github.sh            # you approve releases
#   REVIEWER=someone scripts/protect-github.sh
#
# What it sets up:
#   - main: changes only through a reviewed pull request with CI passing;
#     no force-pushes, no deleting it. Repo admins can bypass.
#   - v* tags (which publish a release): only repo admins can create,
#     move or delete them.
#   - the "release" environment: holds the release key and deploy token,
#     only runs for v* tags, and waits for REVIEWER to approve.
#   - pull requests from outside contributors wait for approval before CI runs.
#   - moves both secrets into the environment (you paste them in, since
#     GitHub never shows a secret's value), then removes the repo-wide copies.

set -euo pipefail

REPO=serveroshq/daemon
REVIEWER=${REVIEWER:-$(gh api user --jq .login)}
REVIEWER_ID=$(gh api "users/$REVIEWER" --jq .id)

if [ "$(gh api "repos/$REPO" --jq .visibility)" != public ]; then
  echo "$REPO is still private: make it public first." >&2
  exit 1
fi

# Repo admins (role 5) and org admins can bypass both rulesets.
BYPASS='[{"actor_type":"RepositoryRole","actor_id":5,"bypass_mode":"always"},{"actor_type":"OrganizationAdmin","actor_id":1,"bypass_mode":"always"}]'

echo "Protecting main"
gh api -X POST "repos/$REPO/rulesets" --input - >/dev/null <<JSON
{
  "name": "Protect main",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
  "bypass_actors": $BYPASS,
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "pull_request", "parameters": {
      "required_approving_review_count": 1,
      "dismiss_stale_reviews_on_push": true,
      "require_code_owner_review": false,
      "require_last_push_approval": true,
      "required_review_thread_resolution": false
    }},
    {"type": "required_status_checks", "parameters": {
      "strict_required_status_checks_policy": false,
      "required_status_checks": [
        {"context": "test (ubuntu-24.04)"},
        {"context": "test (ubuntu-22.04)"},
        {"context": "tests as root"},
        {"context": "static build (x86_64-unknown-linux-musl)"},
        {"context": "static build (aarch64-unknown-linux-musl)"}
      ]
    }}
  ]
}
JSON

echo "Locking release tags"
gh api -X POST "repos/$REPO/rulesets" --input - >/dev/null <<JSON
{
  "name": "Release tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
  "bypass_actors": $BYPASS,
  "rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"}]
}
JSON

echo "Setting up the release environment (approver: $REVIEWER)"
gh api -X PUT "repos/$REPO/environments/release" --input - >/dev/null <<JSON
{
  "reviewers": [{"type": "User", "id": $REVIEWER_ID}],
  "prevent_self_review": false,
  "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}
}
JSON
gh api -X POST "repos/$REPO/environments/release/deployment-branch-policies" \
  -f name='v*' -f type=tag >/dev/null

echo "Outside contributors' pull requests wait for approval before CI runs"
gh api -X PUT "repos/$REPO/actions/permissions/fork-pr-contributor-approval" \
  -f approval_policy=all_external_contributors >/dev/null

echo "Moving secrets into the release environment"
for secret in SERVEROS_RELEASE_KEY SERVEROS_DEPLOY_TOKEN; do
  # From the macOS Keychain (account serveroshq/daemon) when it's there,
  # otherwise pasted in.
  if value=$(security find-generic-password -a serveroshq/daemon -s "$secret" -w 2>/dev/null); then
    printf '%s' "$value" | gh secret set "$secret" --env release -R "$REPO"
    echo "$secret set from the Keychain"
  else
    echo "Paste $secret:"
    gh secret set "$secret" --env release -R "$REPO"
  fi
done
for secret in SERVEROS_RELEASE_KEY SERVEROS_DEPLOY_TOKEN; do
  gh secret delete "$secret" -R "$REPO"
done

echo "Done. Only repo admins can push v* tags, and every release waits for $REVIEWER."
