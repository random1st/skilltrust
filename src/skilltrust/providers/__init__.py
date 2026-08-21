"""Provider-neutral adapters for source, signature, and distribution integrations."""

from skilltrust.providers.base import (
    ArtifactVerificationResult,
    CertificateProfile,
    CertificateValidationResult,
    CheckVerdict,
    CommandResult,
    ContributionCheckResult,
    GitRevision,
    HttpxJsonClient,
    IntegrationResult,
    ReviewVerdict,
    SubprocessCommandRunner,
)
from skilltrust.providers.git import (
    AzureDevOpsPullRequestAdapter,
    GenericGitReadOnlyAdapter,
    GitHubPullRequestAdapter,
    canonical_git_repository_id,
)

__all__ = [
    "ArtifactVerificationResult",
    "AzureDevOpsPullRequestAdapter",
    "CertificateProfile",
    "CertificateValidationResult",
    "CheckVerdict",
    "CommandResult",
    "ContributionCheckResult",
    "GenericGitReadOnlyAdapter",
    "GitHubPullRequestAdapter",
    "GitRevision",
    "HttpxJsonClient",
    "IntegrationResult",
    "ReviewVerdict",
    "SubprocessCommandRunner",
    "canonical_git_repository_id",
]
