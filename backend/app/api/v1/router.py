from fastapi import APIRouter

from app.api.v1.alerts import router as alerts_router

router = APIRouter()
router.include_router(alerts_router)
