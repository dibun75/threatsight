"""Fail-closed checks for the public synthetic demonstration."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threatsight_api.config import Settings
from threatsight_api.persistence.models import (
    ConnectorInstance,
    RunnerCredential,
    RunnerRegistration,
    SecretReference,
    Workspace,
    WorkspaceMembership,
)

ALLOWED_SECRET_SCHEMES = frozenset({"local", "fixture"})
ENABLED_RUNNER_STATES = frozenset({"active", "connected"})


def ensure_demo_viewer(session: Session, settings: Settings) -> None:
    workspace = session.scalar(
        select(Workspace).where(Workspace.key == settings.public_demo_workspace_key.strip().lower())
    )
    if workspace is None:
        return
    subject = settings.public_demo_subject.strip()
    membership = session.scalar(
        select(WorkspaceMembership).where(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.subject == subject,
        )
    )
    if membership is None:
        session.add(WorkspaceMembership(workspace_id=workspace.id, subject=subject, role="viewer"))
    elif membership.role != "viewer":
        membership.role = "viewer"
    session.commit()


def demo_boundary_problems(session: Session, settings: Settings) -> list[str]:
    """Return stable problem codes. Callers must not show these to visitors."""
    workspace = session.scalar(
        select(Workspace).where(
            Workspace.key == settings.public_demo_workspace_key.strip().lower(),
            Workspace.status == "active",
        )
    )
    if workspace is None:
        return ["workspace_missing"]
    problems: list[str] = []
    if workspace.classification != "synthetic_demo":
        problems.append("not_synthetic")
    live = session.scalar(
        select(func.count()).select_from(ConnectorInstance).where(
            ConnectorInstance.workspace_id == workspace.id,
            ConnectorInstance.maturity == "live_verified",
        )
    )
    if live:
        problems.append("live_verified")
    enabled = session.scalar(
        select(func.count()).select_from(RunnerRegistration).where(
            RunnerRegistration.workspace_id == workspace.id,
            RunnerRegistration.status.in_(tuple(ENABLED_RUNNER_STATES)),
        )
    )
    if enabled:
        problems.append("enabled_runner")
    credentials = session.scalar(
        select(func.count()).select_from(RunnerCredential).join(
            RunnerRegistration, RunnerRegistration.id == RunnerCredential.runner_id
        ).where(
            RunnerRegistration.workspace_id == workspace.id,
            RunnerCredential.revoked_at.is_(None),
        )
    )
    if credentials:
        problems.append("unrevoked_credential")
    for locator in session.scalars(
        select(SecretReference.locator).where(SecretReference.workspace_id == workspace.id)
    ):
        scheme = str(locator).split(":", 1)[0].lower()
        if scheme not in ALLOWED_SECRET_SCHEMES:
            problems.append("secret_reference")
            break
    membership = session.scalar(
        select(WorkspaceMembership).where(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.subject == settings.public_demo_subject.strip(),
        )
    )
    if membership is None or membership.role != "viewer":
        problems.append("viewer_missing")
    return problems
