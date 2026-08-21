from __future__ import annotations

import subprocess
from pathlib import Path
from shutil import which

from skilltrust.models import ValidationStatus
from skilltrust.providers import (
    AzureDevOpsPullRequestAdapter,
    GenericGitReadOnlyAdapter,
    GitHubPullRequestAdapter,
    ReviewVerdict,
)

HEAD_SHA = "a" * 40
GIT = which("git") or "git"


class StaticHttpClient:
    def __init__(self, responses: dict[str, object]) -> None:
        self._responses = responses

    def get_json(self, url: str, *, headers: dict[str, str] | None = None) -> object:
        assert headers is not None
        return self._responses[url]


def test_github_pull_request_adapter_passes_on_exact_repo_sha_review_and_checks() -> None:
    client = StaticHttpClient(
        {
            "https://api.github.com/repos/acme/skills/pulls/42": {
                "state": "open",
                "merged": False,
                "draft": False,
                "head": {"sha": HEAD_SHA, "repo": {"id": 123}},
            },
            "https://api.github.com/repos/acme/skills/pulls/42/reviews": [
                {"state": "APPROVED", "user": {"login": "alice"}},
            ],
            f"https://api.github.com/repos/acme/skills/commits/{HEAD_SHA}/status": {
                "state": "success",
                "total_count": 1,
            },
        }
    )

    adapter = GitHubPullRequestAdapter(owner="acme", repository="skills", client=client)
    result = adapter.evaluate_pull_request(
        repository_id="123",
        pull_request_number=42,
        expected_head_sha=HEAD_SHA,
    )

    assert result.status is ValidationStatus.PASS
    assert result.review_verdict is ReviewVerdict.APPROVED
    assert result.approvers == ("alice",)


def test_github_pull_request_adapter_fails_on_head_sha_mismatch() -> None:
    client = StaticHttpClient(
        {
            "https://api.github.com/repos/acme/skills/pulls/7": {
                "state": "open",
                "merged": False,
                "draft": False,
                "head": {"sha": "b" * 40, "repo": {"id": "repo-1"}},
            },
            "https://api.github.com/repos/acme/skills/pulls/7/reviews": [],
            f"https://api.github.com/repos/acme/skills/commits/{HEAD_SHA}/status": {
                "state": "success",
                "total_count": 1,
            },
        }
    )

    adapter = GitHubPullRequestAdapter(owner="acme", repository="skills", client=client)
    result = adapter.evaluate_pull_request(
        repository_id="repo-1",
        pull_request_number=7,
        expected_head_sha=HEAD_SHA,
    )

    assert result.status is ValidationStatus.FAIL
    assert result.code == "github_head_sha_mismatch"


def test_azure_devops_pull_request_adapter_passes_on_active_approved_succeeded_review() -> None:
    client = StaticHttpClient(
        {
            (
                "https://dev.azure.com/acme/core/_apis/git/repositories/skills/"
                "pullRequests/9?api-version=7.1"
            ): {
                "status": "active",
                "isDraft": False,
                "repository": {"id": "repo-9"},
                "lastMergeSourceCommit": {"commitId": HEAD_SHA},
            },
            (
                "https://dev.azure.com/acme/core/_apis/git/repositories/skills/"
                "pullRequests/9/reviewers?api-version=7.1"
            ): {
                "value": [{"displayName": "Bob", "vote": 10, "isRequired": True}],
            },
            (
                "https://dev.azure.com/acme/core/_apis/git/repositories/skills/"
                "pullRequests/9/statuses?api-version=7.1"
            ): {
                "value": [{"state": "succeeded"}],
            },
        }
    )

    adapter = AzureDevOpsPullRequestAdapter(
        organization="acme",
        project="core",
        repository="skills",
        client=client,
    )
    result = adapter.evaluate_pull_request(
        repository_id="repo-9",
        pull_request_id=9,
        expected_head_sha=HEAD_SHA,
    )

    assert result.status is ValidationStatus.PASS
    assert result.approvers == ("Bob",)


def test_generic_git_read_only_adapter_reads_and_verifies_local_snapshot(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    subprocess.run([GIT, "init"], cwd=repository, check=True, capture_output=True)  # noqa: S603
    subprocess.run(  # noqa: S603
        [GIT, "config", "user.email", "tests@example.com"],
        cwd=repository,
        check=True,
        capture_output=True,
    )
    subprocess.run(  # noqa: S603
        [GIT, "config", "user.name", "SkillTrust Tests"],
        cwd=repository,
        check=True,
        capture_output=True,
    )
    subprocess.run(  # noqa: S603
        [GIT, "remote", "add", "origin", "https://example.com/acme/skills.git"],
        cwd=repository,
        check=True,
        capture_output=True,
    )
    (repository / "README.md").write_text("skilltrust\n")
    subprocess.run([GIT, "add", "README.md"], cwd=repository, check=True, capture_output=True)  # noqa: S603
    subprocess.run([GIT, "commit", "-m", "init"], cwd=repository, check=True, capture_output=True)  # noqa: S603
    head_sha = (
        subprocess.run(  # noqa: S603
            [GIT, "rev-parse", "HEAD"],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        )
        .stdout.strip()
    )

    adapter = GenericGitReadOnlyAdapter()
    snapshot = adapter.snapshot(repository)
    result = adapter.verify_revision(
        repository,
        expected_head_sha=head_sha,
        expected_repository_id=snapshot.repository_id,
    )

    assert snapshot.commit_sha == head_sha
    assert result.status is ValidationStatus.PASS
