from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any, List

from app.api.dependencies import get_current_tenant, get_current_user, get_db, require_roles
from app.models.tenant import Tenant
from app.models.user import User
from app.core.engine.agent import run_security_scan_agent
from app.schemas.approval import ScanRequest

router = APIRouter()

@router.post("/analyze")
async def trigger_agent_scan(
    request: ScanRequest,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(require_roles(["owner", "admin"])),
    db: AsyncSession = Depends(get_db)
):
    """Trigger the LangGraph agent to scan the infrastructure and propose remediation."""
    try:
        result = await run_security_scan_agent(
            str(tenant.id), request.target, db, actor_id=str(current_user.id)
        )
        return {"status": "success", "message": "Scan complete. Review action center.", "data": result}
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Agent scan failed: {str(e)}")

from pydantic import BaseModel
class ChatRequest(BaseModel):
    messages: List[Dict[str, str]]

from app.core.engine.assistant import run_assistant_chat

@router.post("/chat")
async def handle_agent_chat(
    request: ChatRequest,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    """Handle chat messages for the Compliance Agent Assistant."""
    try:
        reply = await run_assistant_chat(request.messages, tenant.id, db)
        return {"status": "success", "data": reply}
    except Exception as e:
        print(f"ERROR IN CHAT: {repr(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Agent chat failed: {str(e)}")
