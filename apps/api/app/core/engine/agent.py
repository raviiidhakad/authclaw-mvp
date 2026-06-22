import json
from datetime import datetime, timedelta
from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.approval import Approval, ApprovalStatus, ApprovalActionType
from app.models.provider import Provider
from app.core.encryption import decrypt_value
from app.models.integration import CloudProvider
from app.services.findings_context import FindingsContextBuilder

# --- State Definition ---
class AgentState(TypedDict):
    tenant_id: str
    actor_id: str          # User who triggered the scan (for non-transferable approval)
    scan_target: str
    findings: List[str]
    analysis_result: str
    remediation_script: str
    action_type: str
    approval_id: str
    db_session: AsyncSession  # Pass session to write to DB

async def get_langchain_llm(tenant_id: uuid.UUID, db: AsyncSession):
    result = await db.execute(
        select(Provider).where(Provider.tenant_id == tenant_id, Provider.is_active == True).limit(1)
    )
    provider = result.scalars().first()
    if not provider:
        raise Exception("No active AI provider configured for this tenant. Please configure one in the Providers settings.")
    
    api_key = decrypt_value(provider.api_key_encrypted)
    base_url = provider.config.get("base_url") if provider.config else None
    
    return ChatOpenAI(
        model="llama-3.3-70b-versatile" if "groq" in (base_url or "") else "gpt-4o", 
        api_key=api_key,
        base_url=base_url
    )

# --- Nodes ---
async def analyzer_node(state: AgentState):
    """Analyzes the findings and determines the best course of action."""
    llm = await get_langchain_llm(uuid.UUID(state["tenant_id"]), state["db_session"])
    
    prompt = f"""You are a senior security cloud architect.
Analyze the following security findings for target: {state['scan_target']}
Findings:
{json.dumps(state['findings'])}

Provide a brief, professional summary of the risks and what needs to be fixed.
"""
    response = await llm.ainvoke([HumanMessage(content=prompt)])
    return {"analysis_result": response.content}

async def planner_node(state: AgentState):
    """Generates the Terraform or CLI script to remediate the issues."""
    llm = await get_langchain_llm(uuid.UUID(state["tenant_id"]), state["db_session"])
    
    prompt = f"""You are an expert DevOps engineer.
Target: {state['scan_target']}
Analysis: {state['analysis_result']}

Write ONLY the raw Terraform code (or CLI commands) needed to fix these issues. 
Do not include markdown blocks like ```terraform. Just the raw code.
"""
    response = await llm.ainvoke([HumanMessage(content=prompt)])
    script = response.content.strip()
    if script.startswith("```"):
        lines = script.split("\n")
        script = "\n".join(lines[1:-1])
        
    return {
        "remediation_script": script,
        "action_type": "terraform" if "resource" in script or "aws_" in script else "cli"
    }

async def hitl_queue_node(state: AgentState):
    """Persists the generated plan to the database for Human-In-The-Loop approval."""
    session = state["db_session"]
    
    action_enum = ApprovalActionType.terraform if state.get("action_type") == "terraform" else ApprovalActionType.cli
    
    approval = Approval(
        tenant_id=uuid.UUID(state["tenant_id"]),
        title=f"Remediation for {state['scan_target']} Scan",
        description=state.get("analysis_result", "Automated security remediation plan."),
        action_type=action_enum,
        status=ApprovalStatus.pending,
        diff_content=state.get("remediation_script", ""),
        # TTL: Approvals expire after 30 minutes (non-transferable + expiring by design)
        expires_at=datetime.utcnow() + timedelta(minutes=30),
        # Track requesting user for non-transferable enforcement
        requested_by_user_id=uuid.UUID(state["actor_id"]) if state.get("actor_id") else None,
    )
    
    session.add(approval)
    await session.commit()
    

    return {"approval_id": str(approval.id)}

# --- Graph Construction ---
workflow = StateGraph(AgentState)

workflow.add_node("analyze", analyzer_node)
workflow.add_node("plan", planner_node)
workflow.add_node("queue_hitl", hitl_queue_node)

workflow.set_entry_point("analyze")
workflow.add_edge("analyze", "plan")
workflow.add_edge("plan", "queue_hitl")
workflow.add_edge("queue_hitl", END)

# Compile the graph
agent_executor = workflow.compile()

async def run_security_scan_agent(
    tenant_id: str,
    target: str,
    session: AsyncSession,
    actor_id: str = None,
) -> Dict[str, Any]:
    """Entry function to trigger the agentic workflow."""

    tenant_uuid = uuid.UUID(tenant_id)
    context_builder = FindingsContextBuilder(session)
    findings = await _build_findings_context(context_builder, tenant_uuid, target)

    if not findings:
        return {
            "approval_id": None,
            "analysis": (
                "No active persisted security findings were found for this target. "
                "Run or wait for ConnectorWorker scans before requesting remediation."
            ),
            "finding_count": 0,
        }
        
    initial_state = {
        "tenant_id": tenant_id,
        "actor_id": actor_id or "",
        "scan_target": target,
        "findings": findings,
        "db_session": session
    }
    
    final_state = await agent_executor.ainvoke(initial_state)
    
    return {
        "approval_id": final_state.get("approval_id"),
        "analysis": final_state.get("analysis_result"),
        "finding_count": len(findings),
    }


async def _build_findings_context(
    context_builder: FindingsContextBuilder,
    tenant_id: uuid.UUID,
    target: str,
) -> List[str]:
    normalized_target = (target or "").strip().lower()
    if normalized_target in {provider.value for provider in CloudProvider}:
        return await context_builder.build_for_provider(tenant_id, normalized_target)

    try:
        integration_id = uuid.UUID(str(target))
    except (TypeError, ValueError):
        return await context_builder.build_for_tenant(tenant_id)

    return await context_builder.build_for_integration(tenant_id, integration_id)
