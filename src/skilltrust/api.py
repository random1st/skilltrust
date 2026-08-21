"""FastAPI application factory with deny-by-default mutation authorization."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated, Protocol, runtime_checkable

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.responses import Response
from starlette.types import Message

from skilltrust.config import ServiceSettings, load_trust_policy
from skilltrust.models import ContributionRequestV1, RevocationV1, Sha256, StrictModel, TrustDomain
from skilltrust.service import (
    ArtifactAuditV1,
    ContributionAcceptedV1,
    ErrorResponseV1,
    RevocationAcceptedV1,
    ServiceError,
    SkillTrustService,
    VerificationRequestV1,
    VerificationResponseV1,
)
from skilltrust.storage import SkillTrustStorage


class Principal(StrictModel):
    subject: str
    authenticated: bool = False
    roles: tuple[str, ...] = ()


@runtime_checkable
class PrincipalAuthenticator(Protocol):
    def authenticate(self, request: Request) -> Principal: ...


@runtime_checkable
class Authorizer(Protocol):
    def authorize(self, principal: Principal, action: str) -> bool: ...


class AnonymousAuthenticator:
    def authenticate(self, request: Request) -> Principal:
        del request
        return Principal(subject="anonymous", authenticated=False)


class ReadOnlyAuthorizer:
    _ALLOWED = frozenset({"audit:read"})

    def authorize(self, principal: Principal, action: str) -> bool:
        del principal
        return action in self._ALLOWED


def create_app(
    *,
    storage: SkillTrustStorage,
    service: SkillTrustService,
    authenticator: PrincipalAuthenticator | None = None,
    authorizer: Authorizer | None = None,
    request_body_limit: int = 1_048_576,
) -> FastAPI:
    app = FastAPI(title="SkillTrust", version="0.1.0")
    principal_authenticator = authenticator or AnonymousAuthenticator()
    principal_authorizer = authorizer or ReadOnlyAuthorizer()

    @app.middleware("http")
    async def enforce_body_limit(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > request_body_limit:
                    return _error_response(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        error=ErrorResponseV1(
                            code="request_body_too_large",
                            message="request body exceeds the configured limit",
                            details={"limit_bytes": request_body_limit},
                        ),
                    )
            except ValueError:
                return _error_response(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    error=ErrorResponseV1(
                        code="invalid_content_length",
                        message="content-length header must be an integer",
                    ),
                )
        body = await request.body()
        if len(body) > request_body_limit:
            return _error_response(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                error=ErrorResponseV1(
                    code="request_body_too_large",
                    message="request body exceeds the configured limit",
                    details={"limit_bytes": request_body_limit},
                ),
            )
        received = False

        async def receive() -> Message:
            nonlocal received
            if received:
                return {"type": "http.request", "body": b"", "more_body": False}
            received = True
            return {"type": "http.request", "body": body, "more_body": False}

        replay_request = Request(request.scope, receive)
        return await call_next(replay_request)

    @app.exception_handler(ServiceError)
    async def service_error_handler(
        request: Request,
        error: ServiceError,
    ) -> JSONResponse:
        del request
        return _error_response(
            status_code=error.status_code,
            error=ErrorResponseV1(
                code=error.code,
                message=error.message,
                details=error.details,
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request,
        error: RequestValidationError,
    ) -> JSONResponse:
        del request
        return _error_response(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            error=ErrorResponseV1(
                code="request_validation_failed",
                message="request payload did not satisfy the typed API contract",
                details={"errors": error.errors()},
            ),
        )

    def current_principal(request: Request) -> Principal:
        return principal_authenticator.authenticate(request)

    authenticated_principal = Depends(current_principal)

    def require_action(action: str) -> Callable[[Principal], Principal]:
        def dependency(principal: Principal = authenticated_principal) -> Principal:
            if not principal_authorizer.authorize(principal, action):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "code": "authorization_denied",
                        "message": (
                            "the authenticated principal is not allowed to perform this action"
                        ),
                        "details": {"action": action},
                    },
                )
            return principal

        return dependency

    @app.exception_handler(HTTPException)
    async def http_exception_handler(
        request: Request,
        error: HTTPException,
    ) -> JSONResponse:
        del request
        if isinstance(error.detail, dict):
            detail = error.detail
            return _error_response(
                status_code=error.status_code,
                error=ErrorResponseV1(
                    code=str(detail.get("code", "http_error")),
                    message=str(detail.get("message", "request failed")),
                    details=_dict_details(detail.get("details")),
                ),
            )
        return _error_response(
            status_code=error.status_code,
            error=ErrorResponseV1(
                code="http_error",
                message=str(error.detail),
            ),
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/status")
    def status_endpoint() -> dict[str, object]:
        return {
            "status": "ok",
            "request_body_limit": request_body_limit,
            "mutation_mode": "deny-by-default",
        }

    @app.post(
        "/v1/contributions",
        response_model=ContributionAcceptedV1,
        status_code=status.HTTP_202_ACCEPTED,
        dependencies=[Depends(require_action("contributions:create"))],
    )
    def submit_contribution(payload: ContributionRequestV1) -> ContributionAcceptedV1:
        return service.submit_contribution(payload)

    @app.post(
        "/v1/revocations",
        response_model=RevocationAcceptedV1,
        status_code=status.HTTP_202_ACCEPTED,
        dependencies=[Depends(require_action("revocations:create"))],
    )
    def submit_revocation(payload: RevocationV1) -> RevocationAcceptedV1:
        return service.submit_revocation(payload)

    @app.post(
        "/v1/verifications",
        response_model=VerificationResponseV1,
        dependencies=[Depends(require_action("verifications:create"))],
    )
    def verify_artifact(payload: VerificationRequestV1) -> JSONResponse:
        response = service.verify_artifact(payload)
        status_code = (
            status.HTTP_200_OK
            if response.upstream_available
            else status.HTTP_503_SERVICE_UNAVAILABLE
        )
        return JSONResponse(status_code=status_code, content=response.model_dump(mode="json"))

    @app.get(
        "/v1/audit/artifacts/{trust_domain}/{artifact_digest}",
        response_model=ArtifactAuditV1,
        dependencies=[Depends(require_action("audit:read"))],
    )
    def audit_artifact(
        trust_domain: TrustDomain,
        artifact_digest: Sha256,
        decision_limit: Annotated[int, Query(ge=1, le=50)] = 10,
    ) -> ArtifactAuditV1:
        return service.audit_artifact(
            artifact_digest=artifact_digest,
            trust_domain=trust_domain,
            decision_limit=decision_limit,
        )

    app.state.skilltrust_storage = storage
    app.state.skilltrust_service = service
    return app


def build_default_app() -> FastAPI:
    settings = ServiceSettings()
    storage = SkillTrustStorage(settings.database_url)
    storage.create_schema()
    policy = load_trust_policy(settings.trust_policy_path)
    service = SkillTrustService(
        storage=storage,
        trust_policies={policy.trust_domain: policy},
    )
    return create_app(
        storage=storage,
        service=service,
        request_body_limit=settings.request_body_limit,
    )


def run() -> None:
    uvicorn.run(build_default_app(), host="127.0.0.1", port=8000)


def _error_response(*, status_code: int, error: ErrorResponseV1) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": error.model_dump(mode="json")})


def _dict_details(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


__all__ = [
    "AnonymousAuthenticator",
    "Authorizer",
    "Principal",
    "PrincipalAuthenticator",
    "ReadOnlyAuthorizer",
    "build_default_app",
    "create_app",
    "run",
]
