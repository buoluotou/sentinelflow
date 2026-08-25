from fastapi import APIRouter

from app.api.v1.alerts import router as alerts_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.events import router as events_router
from app.api.v1.incidents import router as incidents_router
from app.api.v1.normalize import router as normalize_router

router = APIRouter()
router.include_router(alerts_router)
router.include_router(dashboard_router)
router.include_router(events_router)
router.include_router(incidents_router)
router.include_router(normalize_router)
