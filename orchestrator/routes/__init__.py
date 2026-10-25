"""Mount domain routers on the broker app."""
from __future__ import annotations

from fastapi import FastAPI

from routes import (
    analytics, auth, health, detections, situations, cases, search, decisions, explanations,
)


def register_routes(app: FastAPI) -> None:
    for mod in (
        health, detections, situations, cases, search, decisions, explanations, analytics, auth,
    ):
        app.include_router(mod.router)
    app.add_exception_handler(auth.HumanAuthError, auth.human_auth_error_response)
