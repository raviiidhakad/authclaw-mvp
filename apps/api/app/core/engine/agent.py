import json
from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph, END
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.approval import Approval, ApprovalStatus, ApprovalActionType
from app.core.config import settings

# --- State Definition ---
class AgentState(TypedDict):
    tenant_id: str
    scan_target: str
    findings: List[str]
    analysis_result: str
    remediation_script: str
    action_type: str
    approval_id: str
    db_session: AsyncSession  # Pass session to write to DB

# --- Nodes ---
async def analyzer_node(state: AgentState):
    """Analyzes the findings and determines the best course of action."""
    llm = ChatGroq(model="llama-3.3-70b-versatile", api_key=settings.GROQ_API_KEY)
    
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
    llm = ChatGroq(model="llama-3.3-70b-versatile", api_key=settings.GROQ_API_KEY)
    
    prompt = f"""You are an expert DevOps engineer.
Target: {state['scan_target']}
Analysis: {state['analysis_result']}

Write ONLY the raw Terraform code (or CLI commands) needed to fix these issues. 
Do not include markdown blocks like ```terraform. Just the raw code.
"""
    response = await llm.ainvoke([HumanMessage(content=prompt)])
    script = response.content.strip()
    if script.startswith("```"):
        lines = script.split("\\n")
        script = "\\n".join(lines[1:-1])
        
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
        diff_content=state.get("remediation_script", "")
    )
    
    session.add(approval)
    await session.commit()
    await session.refresh(approval)
    
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

async def run_security_scan_agent(tenant_id: str, target: str, session: AsyncSession) -> Dict[str, Any]:
    """Entry function to trigger the agentic workflow."""
    
    # Mock finding generator based on target
    mock_findings = []
    if target.lower() == "aws":
        mock_findings = ["S3 bucket 'company-data' has public read access.", "IAM user 'dev-1' lacks MFA."]
    elif target.lower() == "github":
        mock_findings = ["Repository 'authclaw' lacks branch protection rules on 'main'."]
    else:
        mock_findings = [f"Default configuration detected on {target} exposing internal ports."]
        
    initial_state = {
        "tenant_id": tenant_id,
        "scan_target": target,
        "findings": mock_findings,
        "db_session": session
    }
    
    final_state = await agent_executor.ainvoke(initial_state)
    
    return {
        "approval_id": final_state.get("approval_id"),
        "analysis": final_state.get("analysis_result")
    }
