from fastapi import APIRouter

from org.xyz.backslash.models.schemas import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Service liveness check."""
    return HealthResponse(status="ok")
