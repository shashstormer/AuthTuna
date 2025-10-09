"""
This file gonna contain routes for ui (dashboards, user info and logins etc etc, gonna work on this soon)
"""
from fastapi import APIRouter
from fastapi.templating import Jinja2Templates
from authtuna.core.config import settings


router = APIRouter(prefix="/ui", tags=["ui"])
templates = Jinja2Templates(directory=settings.HTML_TEMPLATE_DIR)
