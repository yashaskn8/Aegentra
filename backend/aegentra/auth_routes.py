"""Browser-facing authentication boundary. No roles accepted from the client."""
from __future__ import annotations

import hmac
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegentra.asset_store import list_assets
from aegentra.audit import IdempotencyConflict, register_asset
from aegentra.case_store import (CaseNotFound, accessible_case, evidence_metadata,
                                 link_evidence, list_member_cases, register_case)
from aegentra.auth_store import AuthStore, AuthenticationError, NotEnrolledError, Principal
from aegentra.oidc import (
    OidcClient, OidcError, OidcSettings, authorization_url,
    csrf_for_session, random_token,
)
from aegentra.persistence import organization_session


SESSION_COOKIE = "__Host-aegentra"
LOGIN_COOKIE = "__Host-aegentra-login"


class AssetInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    slug: str = Field(min_length=3, max_length=80, pattern=r"^[a-z][a-z0-9-]+$")
    criticality: str = Field(pattern=r"^(LOW|MEDIUM|HIGH)$")


class CaseInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: UUID
    title: str = Field(min_length=3, max_length=140)


class LinkEvidenceInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence_id: UUID


def enable_auth(
    app: FastAPI,
    *,
    settings: OidcSettings,
    sessions: async_sessionmaker[AsyncSession],
    provider: OidcClient,
) -> None:
    store = AuthStore(sessions)
    router = APIRouter(prefix="/v1")

    async def principal(request: Request) -> Principal:
        try:
            return await store.authenticate(request.cookies.get(SESSION_COOKIE))
        except AuthenticationError as exc:
            raise HTTPException(status_code=401, detail="authentication required") from exc

    async def mutation_principal(request: Request) -> Principal:
        user = await principal(request)
        expected = csrf_for_session(settings.csrf_key, request.cookies[SESSION_COOKIE])
        provided = request.headers.get("x-csrf-token", "")
        if (
            request.headers.get("origin") != settings.origin
            or not hmac.compare_digest(expected, provided)
        ):
            raise HTTPException(status_code=403, detail="invalid request origin or CSRF token")
        return user

    @router.get("/auth/login")
    async def login() -> RedirectResponse:
        state, browser, nonce, verifier = (
            random_token(), random_token(), random_token(), random_token()
        )
        await store.begin_login(state, browser, verifier, nonce)
        response = RedirectResponse(
            authorization_url(settings, state, nonce, verifier), status_code=302
        )
        response.set_cookie(
            LOGIN_COOKIE, browser, max_age=300, secure=True, httponly=True,
            samesite="lax", path="/",
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @router.get("/auth/callback")
    async def callback(
        request: Request,
        code: str = Query(min_length=1, max_length=2048),
        state: str = Query(min_length=1, max_length=128),
    ) -> RedirectResponse:
        try:
            verifier, nonce = await store.consume_login(
                state, request.cookies.get(LOGIN_COOKIE, "")
            )
            subject = await provider.authenticate(code, verifier, nonce)
            session_token = await store.create_session(settings.issuer, subject)
        except (AuthenticationError, OidcError) as exc:
            raise HTTPException(status_code=400, detail="login verification failed") from exc
        except NotEnrolledError as exc:
            raise HTTPException(status_code=403, detail="identity not enrolled") from exc
        response = RedirectResponse("/", status_code=303)
        response.delete_cookie(LOGIN_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
        response.set_cookie(
            SESSION_COOKIE, session_token, max_age=8 * 3600,
            secure=True, httponly=True, samesite="lax", path="/",
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @router.get("/me")
    async def me(request: Request, response: Response, user: Principal = Depends(principal)) -> dict:
        response.headers["Cache-Control"] = "no-store"
        return {
            "identity_id": str(user.identity_id),
            "org_id": str(user.org_id),
            "role": user.role,
            "csrf_token": csrf_for_session(settings.csrf_key, request.cookies[SESSION_COOKIE]),
        }

    @router.post("/auth/logout", status_code=204)
    async def logout(
        request: Request, response: Response, user: Principal = Depends(mutation_principal)
    ) -> None:
        await store.revoke(request.cookies[SESSION_COOKIE])
        response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
        response.headers["Cache-Control"] = "no-store"

    @router.get("/assets")
    async def assets(response: Response, user: Principal = Depends(principal)) -> dict:
        response.headers["Cache-Control"] = "no-store"
        async with organization_session(sessions, user.org_id) as session:
            items = await list_assets(session, org_id=user.org_id)
            return {
                "items": [
                    {"id": str(item.id), "slug": item.slug, "criticality": item.criticality}
                    for item in items[:100]
                ],
                "truncated": len(items) > 100,
            }

    @router.post("/assets", status_code=201)
    async def add_asset(
        body: AssetInput,
        response: Response,
        idempotency_key: str = Header(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"),
        user: Principal = Depends(mutation_principal),
    ) -> dict:
        if user.role not in {"ADMIN", "EDITOR"}:
            raise HTTPException(status_code=403, detail="asset creation not permitted")
        try:
            async with organization_session(sessions, user.org_id) as session:
                result = await register_asset(
                    session, org_id=user.org_id, actor_id=user.identity_id,
                    key=idempotency_key, slug=body.slug, criticality=body.criticality,
                )
        except IntegrityError as exc:
            raise HTTPException(status_code=409, detail="asset already exists") from exc
        except IdempotencyConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        response.headers["Cache-Control"] = "no-store"
        return result

    @router.get("/cases")
    async def cases(response: Response, user: Principal = Depends(principal)) -> dict:
        response.headers["Cache-Control"] = "no-store"
        async with organization_session(sessions, user.org_id) as session:
            items = await list_member_cases(
                session, org_id=user.org_id, identity_id=user.identity_id
            )
            return {
                "items": [
                    {
                        "id": str(item.id), "asset_id": str(item.asset_id),
                        "title": item.title, "status": item.status,
                        "revision": item.revision,
                    }
                    for item in items[:100]
                ],
                "truncated": len(items) > 100,
            }

    @router.post("/cases", status_code=201)
    async def add_case(
        body: CaseInput,
        response: Response,
        idempotency_key: str = Header(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"),
        user: Principal = Depends(mutation_principal),
    ) -> dict:
        if user.role not in {"ADMIN", "ANALYST"}:
            raise HTTPException(status_code=403, detail="case creation not permitted")
        try:
            async with organization_session(sessions, user.org_id) as session:
                result = await register_case(
                    session, org_id=user.org_id, identity_id=user.identity_id,
                    key=idempotency_key, asset_id=body.asset_id, title=body.title,
                )
        except CaseNotFound as exc:
            raise HTTPException(status_code=404, detail="asset unavailable") from exc
        except IdempotencyConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        response.headers["Cache-Control"] = "no-store"
        return result

    @router.get("/cases/{case_id}")
    async def case_details(
        case_id: UUID, response: Response,
        user: Principal = Depends(principal),
    ) -> dict:
        try:
            async with organization_session(sessions, user.org_id) as session:
                item = await accessible_case(
                    session, org_id=user.org_id, identity_id=user.identity_id,
                    case_id=case_id,
                )
                result = {
                    "id": str(item.id), "asset_id": str(item.asset_id),
                    "title": item.title, "status": item.status,
                    "revision": item.revision,
                }
        except CaseNotFound as exc:
            raise HTTPException(status_code=404, detail="case unavailable") from exc
        response.headers["Cache-Control"] = "no-store"
        return result

    @router.post("/cases/{case_id}/evidence", status_code=201)
    async def add_case_evidence(
        case_id: UUID, body: LinkEvidenceInput, response: Response,
        user: Principal = Depends(mutation_principal),
    ) -> dict:
        if user.role not in {"ADMIN", "ANALYST"}:
            raise HTTPException(status_code=403, detail="case update not permitted")
        try:
            async with organization_session(sessions, user.org_id) as session:
                result = await link_evidence(
                    session, org_id=user.org_id, identity_id=user.identity_id,
                    case_id=case_id, evidence_id=body.evidence_id,
                )
        except CaseNotFound as exc:
            raise HTTPException(status_code=404, detail="evidence or case unavailable") from exc
        except IntegrityError as exc:
            raise HTTPException(status_code=409, detail="evidence already linked") from exc
        response.headers["Cache-Control"] = "no-store"
        return result

    @router.get("/cases/{case_id}/evidence/{evidence_id}/meta")
    async def case_evidence_meta(
        case_id: UUID, evidence_id: UUID, response: Response,
        user: Principal = Depends(principal),
    ) -> dict:
        try:
            async with organization_session(sessions, user.org_id) as session:
                result = await evidence_metadata(
                    session, org_id=user.org_id, identity_id=user.identity_id,
                    case_id=case_id, evidence_id=evidence_id,
                )
        except CaseNotFound as exc:
            raise HTTPException(status_code=404, detail="evidence unavailable") from exc
        response.headers["Cache-Control"] = "no-store"
        return result

    app.include_router(router)
