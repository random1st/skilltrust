"""Provider-neutral contribution adapters for GitHub, Azure DevOps, and generic Git."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx

from skilltrust.models import ValidationStatus, sha256_digest

from .base import (
    CheckVerdict,
    CommandRunner,
    ContributionCheckResult,
    GitRevision,
    HttpxJsonClient,
    IntegrationResult,
    JsonHttpClient,
    ReviewVerdict,
    SubprocessCommandRunner,
    as_list,
    as_mapping,
)


def canonical_git_repository_id(clone_url: str) -> str:
    """Derive a stable fallback repository identifier from the immutable origin URL."""

    normalized = clone_url.strip().rstrip("/")
    return f"git:{sha256_digest(normalized.encode('utf-8'))}"


def _require_text(value: object, *, context: str) -> str:
    if isinstance(value, str):
        text = value.strip()
    elif isinstance(value, int):
        text = str(value)
    else:
        raise ValueError(f"{context} must be a string")
    if not text:
        raise ValueError(f"{context} cannot be empty")
    return text


def _finalize_result(
    *,
    provider: str,
    repository_id: str,
    contribution_id: str,
    head_sha: str,
    review_verdict: ReviewVerdict,
    checks_verdict: CheckVerdict,
    approvers: tuple[str, ...],
) -> ContributionCheckResult:
    if review_verdict is ReviewVerdict.CHANGES_REQUESTED:
        return ContributionCheckResult(
            provider=provider,
            status=ValidationStatus.FAIL,
            code=f"{provider}_changes_requested",
            message=f"{provider} review contains blocking change requests",
            repository_id=repository_id,
            contribution_id=contribution_id,
            head_sha=head_sha,
            review_verdict=review_verdict,
            checks_verdict=checks_verdict,
        )
    if checks_verdict is CheckVerdict.FAIL:
        return ContributionCheckResult(
            provider=provider,
            status=ValidationStatus.FAIL,
            code=f"{provider}_checks_failed",
            message=f"{provider} contribution checks failed for the pinned head SHA",
            repository_id=repository_id,
            contribution_id=contribution_id,
            head_sha=head_sha,
            review_verdict=review_verdict,
            checks_verdict=checks_verdict,
            approvers=approvers,
        )
    if review_verdict is ReviewVerdict.APPROVED and checks_verdict is CheckVerdict.PASS:
        return ContributionCheckResult(
            provider=provider,
            status=ValidationStatus.PASS,
            code=f"{provider}_review_verified",
            message=(
                f"{provider} review approval and contribution checks match the pinned head SHA"
            ),
            repository_id=repository_id,
            contribution_id=contribution_id,
            head_sha=head_sha,
            review_verdict=review_verdict,
            checks_verdict=checks_verdict,
            approvers=approvers,
        )
    return ContributionCheckResult(
        provider=provider,
        status=ValidationStatus.UNKNOWN,
        code=f"{provider}_review_incomplete",
        message=f"{provider} review or contribution checks are incomplete for the pinned head SHA",
        repository_id=repository_id,
        contribution_id=contribution_id,
        head_sha=head_sha,
        review_verdict=review_verdict,
        checks_verdict=checks_verdict,
        approvers=approvers,
    )


class GitHubPullRequestAdapter:
    """Normalize GitHub pull request reviews and commit statuses into fail-closed results."""

    def __init__(
        self,
        *,
        owner: str,
        repository: str,
        client: JsonHttpClient | None = None,
        token: str | None = None,
        base_url: str = "https://api.github.com",
    ) -> None:
        self._owner = owner
        self._repository = repository
        self._client = client or HttpxJsonClient()
        self._token = token
        self._base_url = base_url.rstrip("/")

    def evaluate_pull_request(
        self,
        *,
        repository_id: str,
        pull_request_number: int,
        expected_head_sha: str,
    ) -> ContributionCheckResult:
        contribution_id = str(pull_request_number)
        expected_sha = expected_head_sha.lower()
        try:
            pull_request = as_mapping(
                self._client.get_json(
                    self._url(f"/repos/{self._owner}/{self._repository}/pulls/{pull_request_number}"),
                    headers=self._headers(),
                ),
                context="GitHub pull request response",
            )
            reviews = as_list(
                self._client.get_json(
                    self._url(
                        f"/repos/{self._owner}/{self._repository}/pulls/{pull_request_number}/reviews"
                    ),
                    headers=self._headers(),
                ),
                context="GitHub pull request reviews response",
            )
            statuses = as_mapping(
                self._client.get_json(
                    self._url(
                        f"/repos/{self._owner}/{self._repository}/commits/{expected_sha}/status"
                    ),
                    headers=self._headers(),
                ),
                context="GitHub commit status response",
            )
        except (httpx.HTTPError, OSError, ValueError) as exc:
            return ContributionCheckResult(
                provider="github",
                status=ValidationStatus.UNKNOWN,
                code="github_provider_unavailable",
                message=f"GitHub contribution checks could not be completed: {exc}",
                repository_id=repository_id,
                contribution_id=contribution_id,
                head_sha=expected_sha,
            )

        actual_repository_id = self._extract_github_repository_id(pull_request)
        actual_head_sha = self._extract_github_head_sha(pull_request)
        pull_state = _require_text(
            pull_request.get("state"),
            context="GitHub pull request state",
        )

        if actual_repository_id != repository_id:
            return ContributionCheckResult(
                provider="github",
                status=ValidationStatus.FAIL,
                code="github_repository_id_mismatch",
                message=(
                    "GitHub pull request head repository does not match the pinned immutable "
                    "repository ID"
                ),
                repository_id=actual_repository_id,
                contribution_id=contribution_id,
                head_sha=actual_head_sha,
                details={"expected_repository_id": repository_id},
            )
        if actual_head_sha != expected_sha:
            return ContributionCheckResult(
                provider="github",
                status=ValidationStatus.FAIL,
                code="github_head_sha_mismatch",
                message="GitHub pull request head SHA differs from the pinned review subject",
                repository_id=actual_repository_id,
                contribution_id=contribution_id,
                head_sha=actual_head_sha,
                details={"expected_head_sha": expected_sha},
            )
        if pull_state != "open" or bool(pull_request.get("merged")):
            return ContributionCheckResult(
                provider="github",
                status=ValidationStatus.FAIL,
                code="github_pull_request_not_open",
                message="GitHub pull request is not an open review target at the pinned head SHA",
                repository_id=actual_repository_id,
                contribution_id=contribution_id,
                head_sha=actual_head_sha,
                details={"pull_state": pull_state},
            )
        if bool(pull_request.get("draft")):
            return ContributionCheckResult(
                provider="github",
                status=ValidationStatus.FAIL,
                code="github_pull_request_draft",
                message="GitHub draft pull requests are not eligible for trusted review decisions",
                repository_id=actual_repository_id,
                contribution_id=contribution_id,
                head_sha=actual_head_sha,
            )

        review_verdict, approvers = self._github_review_verdict(reviews)
        checks_verdict = self._github_checks_verdict(statuses)
        return _finalize_result(
            provider="github",
            repository_id=actual_repository_id,
            contribution_id=contribution_id,
            head_sha=actual_head_sha,
            review_verdict=review_verdict,
            checks_verdict=checks_verdict,
            approvers=approvers,
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _url(self, path: str) -> str:
        return f"{self._base_url}{path}"

    def _extract_github_repository_id(self, pull_request: Mapping[str, Any]) -> str:
        head = as_mapping(pull_request.get("head"), context="GitHub pull request head")
        repository = as_mapping(head.get("repo"), context="GitHub head repository")
        return _require_text(repository.get("id"), context="GitHub repository ID")

    def _extract_github_head_sha(self, pull_request: Mapping[str, Any]) -> str:
        head = as_mapping(pull_request.get("head"), context="GitHub pull request head")
        return _require_text(head.get("sha"), context="GitHub head SHA").lower()

    def _github_review_verdict(
        self,
        reviews: list[object],
    ) -> tuple[ReviewVerdict, tuple[str, ...]]:
        latest_state_by_user: dict[str, str] = {}
        for review_object in reviews:
            review = as_mapping(review_object, context="GitHub review")
            user = as_mapping(review.get("user"), context="GitHub review user")
            login = _require_text(user.get("login"), context="GitHub reviewer login")
            state = _require_text(review.get("state"), context="GitHub review state").upper()
            latest_state_by_user[login] = state

        if any(state == "CHANGES_REQUESTED" for state in latest_state_by_user.values()):
            return ReviewVerdict.CHANGES_REQUESTED, ()

        approvers = tuple(
            sorted(login for login, state in latest_state_by_user.items() if state == "APPROVED")
        )
        if approvers:
            return ReviewVerdict.APPROVED, approvers

        if latest_state_by_user:
            return ReviewVerdict.PENDING, ()
        return ReviewVerdict.UNKNOWN, ()

    def _github_checks_verdict(self, statuses: Mapping[str, Any]) -> CheckVerdict:
        total_count = statuses.get("total_count")
        if isinstance(total_count, int) and total_count == 0:
            return CheckVerdict.UNKNOWN

        state = _require_text(statuses.get("state"), context="GitHub combined status state")
        if state == "success":
            return CheckVerdict.PASS
        if state in {"error", "failure"}:
            return CheckVerdict.FAIL
        if state == "pending":
            return CheckVerdict.PENDING
        return CheckVerdict.UNKNOWN

class AzureDevOpsPullRequestAdapter:
    """Normalize Azure DevOps pull request votes and statuses into fail-closed results."""

    def __init__(
        self,
        *,
        organization: str,
        project: str,
        repository: str,
        client: JsonHttpClient | None = None,
        token: str | None = None,
        base_url: str = "https://dev.azure.com",
        api_version: str = "7.1",
    ) -> None:
        self._organization = organization
        self._project = project
        self._repository = repository
        self._client = client or HttpxJsonClient()
        self._token = token
        self._base_url = base_url.rstrip("/")
        self._api_version = api_version

    def evaluate_pull_request(
        self,
        *,
        repository_id: str,
        pull_request_id: int,
        expected_head_sha: str,
    ) -> ContributionCheckResult:
        contribution_id = str(pull_request_id)
        expected_sha = expected_head_sha.lower()
        try:
            pull_request = as_mapping(
                self._client.get_json(
                    self._pull_request_url(pull_request_id),
                    headers=self._headers(),
                ),
                context="Azure DevOps pull request response",
            )
            reviewers_payload = self._client.get_json(
                self._reviewers_url(pull_request_id),
                headers=self._headers(),
            )
            reviewers = as_list(
                as_mapping(
                    reviewers_payload,
                    context="Azure DevOps reviewers response",
                ).get("value"),
                context="Azure DevOps reviewers list",
            )
            statuses_payload = self._client.get_json(
                self._statuses_url(pull_request_id),
                headers=self._headers(),
            )
            statuses = as_list(
                as_mapping(statuses_payload, context="Azure DevOps statuses response").get("value"),
                context="Azure DevOps status list",
            )
        except (httpx.HTTPError, OSError, ValueError) as exc:
            return ContributionCheckResult(
                provider="azure-devops",
                status=ValidationStatus.UNKNOWN,
                code="azure_devops_provider_unavailable",
                message=f"Azure DevOps contribution checks could not be completed: {exc}",
                repository_id=repository_id,
                contribution_id=contribution_id,
                head_sha=expected_sha,
            )

        actual_repository_id = self._extract_azure_repository_id(pull_request)
        actual_head_sha = self._extract_azure_head_sha(pull_request)
        pull_request_state = _require_text(
            pull_request.get("status"),
            context="Azure DevOps pull request status",
        ).lower()

        if actual_repository_id != repository_id:
            return ContributionCheckResult(
                provider="azure-devops",
                status=ValidationStatus.FAIL,
                code="azure_devops_repository_id_mismatch",
                message=(
                    "Azure DevOps pull request repository does not match the pinned immutable "
                    "repository ID"
                ),
                repository_id=actual_repository_id,
                contribution_id=contribution_id,
                head_sha=actual_head_sha,
                details={"expected_repository_id": repository_id},
            )
        if actual_head_sha != expected_sha:
            return ContributionCheckResult(
                provider="azure-devops",
                status=ValidationStatus.FAIL,
                code="azure_devops_head_sha_mismatch",
                message="Azure DevOps pull request head SHA differs from the pinned review subject",
                repository_id=actual_repository_id,
                contribution_id=contribution_id,
                head_sha=actual_head_sha,
                details={"expected_head_sha": expected_sha},
            )
        if pull_request_state != "active":
            return ContributionCheckResult(
                provider="azure-devops",
                status=ValidationStatus.FAIL,
                code="azure_devops_pull_request_not_active",
                message=(
                    "Azure DevOps pull request is not an active review target at the pinned "
                    "head SHA"
                ),
                repository_id=actual_repository_id,
                contribution_id=contribution_id,
                head_sha=actual_head_sha,
                details={"pull_request_status": pull_request_state},
            )
        if bool(pull_request.get("isDraft")):
            return ContributionCheckResult(
                provider="azure-devops",
                status=ValidationStatus.FAIL,
                code="azure_devops_pull_request_draft",
                message=(
                    "Azure DevOps draft pull requests are not eligible for trusted review "
                    "decisions"
                ),
                repository_id=actual_repository_id,
                contribution_id=contribution_id,
                head_sha=actual_head_sha,
            )

        review_verdict, approvers = self._azure_review_verdict(reviewers)
        checks_verdict = self._azure_checks_verdict(statuses)
        return _finalize_result(
            provider="azure-devops",
            repository_id=actual_repository_id,
            contribution_id=contribution_id,
            head_sha=actual_head_sha,
            review_verdict=review_verdict,
            checks_verdict=checks_verdict,
            approvers=approvers,
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self._token:
            encoded = base64.b64encode(f":{self._token}".encode()).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"
        return headers

    def _pull_request_url(self, pull_request_id: int) -> str:
        return (
            f"{self._base_url}/{self._organization}/{self._project}/_apis/git/repositories/"
            f"{self._repository}/pullRequests/{pull_request_id}?api-version={self._api_version}"
        )

    def _reviewers_url(self, pull_request_id: int) -> str:
        return (
            f"{self._base_url}/{self._organization}/{self._project}/_apis/git/repositories/"
            f"{self._repository}/pullRequests/{pull_request_id}/reviewers?api-version={self._api_version}"
        )

    def _statuses_url(self, pull_request_id: int) -> str:
        return (
            f"{self._base_url}/{self._organization}/{self._project}/_apis/git/repositories/"
            f"{self._repository}/pullRequests/{pull_request_id}/statuses?api-version={self._api_version}"
        )

    def _extract_azure_repository_id(self, pull_request: Mapping[str, Any]) -> str:
        repository = as_mapping(pull_request.get("repository"), context="Azure DevOps repository")
        return _require_text(repository.get("id"), context="Azure DevOps repository ID")

    def _extract_azure_head_sha(self, pull_request: Mapping[str, Any]) -> str:
        source_commit = as_mapping(
            pull_request.get("lastMergeSourceCommit"),
            context="Azure DevOps source commit",
        )
        return _require_text(
            source_commit.get("commitId"),
            context="Azure DevOps source commit ID",
        ).lower()

    def _azure_review_verdict(
        self,
        reviewers: list[object],
    ) -> tuple[ReviewVerdict, tuple[str, ...]]:
        required_pending = False
        approvers: list[str] = []
        saw_reviewer = False

        for reviewer_object in reviewers:
            reviewer = as_mapping(reviewer_object, context="Azure DevOps reviewer")
            vote = reviewer.get("vote")
            if not isinstance(vote, int):
                raise ValueError("Azure DevOps reviewer vote must be an integer")
            display_name = _require_text(
                reviewer.get("displayName") or reviewer.get("uniqueName") or reviewer.get("id"),
                context="Azure DevOps reviewer name",
            )
            is_required = bool(reviewer.get("isRequired"))
            saw_reviewer = True

            if vote <= -5:
                return ReviewVerdict.CHANGES_REQUESTED, ()
            if vote >= 5:
                approvers.append(display_name)
                continue
            if is_required:
                required_pending = True

        if approvers and not required_pending:
            return ReviewVerdict.APPROVED, tuple(sorted(approvers))
        if saw_reviewer:
            return ReviewVerdict.PENDING, ()
        return ReviewVerdict.UNKNOWN, ()

    def _azure_checks_verdict(self, statuses: list[object]) -> CheckVerdict:
        if not statuses:
            return CheckVerdict.UNKNOWN

        saw_pending = False
        for status_object in statuses:
            status = as_mapping(status_object, context="Azure DevOps status")
            raw_state = _require_text(
                status.get("state") or status.get("status"),
                context="Azure DevOps status state",
            ).lower()
            if raw_state in {"failed", "failure", "error", "rejected"}:
                return CheckVerdict.FAIL
            if raw_state in {"pending", "notset", "inprogress"}:
                saw_pending = True

        if saw_pending:
            return CheckVerdict.PENDING
        return CheckVerdict.PASS
class GenericGitReadOnlyAdapter:
    """Read immutable source facts from a local clone without mutating Git state."""

    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
        git_executable: str = "git",
        timeout_seconds: float = 10.0,
    ) -> None:
        self._runner = runner or SubprocessCommandRunner()
        self._git_executable = git_executable
        self._timeout_seconds = timeout_seconds

    def snapshot(self, repository: Path, *, ref: str = "HEAD") -> GitRevision:
        clone_url = self._git_stdout(repository, "remote", "get-url", "origin")
        commit_sha = self._git_stdout(repository, "rev-parse", ref).lower()
        return GitRevision(
            repository_id=canonical_git_repository_id(clone_url),
            clone_url=clone_url,
            ref=ref,
            commit_sha=commit_sha,
        )

    def verify_revision(
        self,
        repository: Path,
        *,
        expected_head_sha: str,
        expected_repository_id: str | None = None,
        ref: str = "HEAD",
    ) -> IntegrationResult:
        expected_sha = expected_head_sha.lower()
        try:
            revision = self.snapshot(repository, ref=ref)
            self._git_check(repository, "cat-file", "-e", f"{expected_sha}^{{commit}}")
        except (FileNotFoundError, OSError, TimeoutError, ValueError) as exc:
            return IntegrationResult(
                provider="generic-git",
                status=ValidationStatus.UNKNOWN,
                code="generic_git_unavailable",
                message=f"generic Git read-only verification could not complete: {exc}",
            )

        if expected_repository_id and revision.repository_id != expected_repository_id:
            return IntegrationResult(
                provider="generic-git",
                status=ValidationStatus.FAIL,
                code="generic_git_repository_id_mismatch",
                message="generic Git repository ID does not match the pinned source identity",
                details={"expected_repository_id": expected_repository_id},
            )
        if revision.commit_sha != expected_sha:
            return IntegrationResult(
                provider="generic-git",
                status=ValidationStatus.FAIL,
                code="generic_git_head_sha_mismatch",
                message="generic Git ref does not resolve to the pinned source commit",
                details={"expected_head_sha": expected_sha, "actual_head_sha": revision.commit_sha},
            )
        return IntegrationResult(
            provider="generic-git",
            status=ValidationStatus.PASS,
            code="generic_git_revision_verified",
            message="generic Git ref resolves to the pinned immutable source commit",
            details={"repository_id": revision.repository_id},
        )

    def _git_stdout(self, repository: Path, *args: str) -> str:
        result = self._runner.run(
            (self._git_executable, *args),
            cwd=repository,
            timeout_seconds=self._timeout_seconds,
        )
        if result.returncode != 0:
            raise OSError(result.stderr.strip() or result.stdout.strip() or "git command failed")
        return result.stdout.strip()

    def _git_check(self, repository: Path, *args: str) -> None:
        result = self._runner.run(
            (self._git_executable, *args),
            cwd=repository,
            timeout_seconds=self._timeout_seconds,
        )
        if result.returncode != 0:
            raise OSError(result.stderr.strip() or result.stdout.strip() or "git command failed")
