from fastapi import APIRouter

from app.api.v1.endpoints.gateway import chat_completions


router = APIRouter()
router.add_api_route("/chat/completions", chat_completions, methods=["POST"])
