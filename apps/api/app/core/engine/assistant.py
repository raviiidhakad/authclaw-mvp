import json
from typing import List, Dict, Any, Optional
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from openai import AsyncOpenAI
import structlog

from app.core.config import settings
from app.models.audit import AuditLog
from app.models.compliance import ComplianceScore
from app.models.policy import PolicyViolation
from app.models.approval import Approval, ApprovalActionType, ApprovalStatus

logger = structlog.get_logger(__name__)

# Initialize OpenAI client with Groq base URL and Key
client = AsyncOpenAI(
    base_url="https://api.groq.com/openai/v1",
    api_key=settings.GROQ_API_KEY,
)

# Groq recommends llama-3.3-70b-versatile for tool calling
MODEL_NAME = "llama-3.3-70b-versatile"

SYSTEM_PROMPT = """You are the AuthClaw Compliance & Security Assistant, an expert AI embedded within the AuthClaw enterprise platform. 
Your goal is to help users understand their security posture, explain policy violations, summarize audit logs, and recommend remediation actions.
IMPORTANT: Do NOT output raw XML or <function> tags in your responses. Always use the native JSON tool calling API to fetch data when asked about specific logs, scores, or violations.
When proposing a remediation action using the propose_remediation tool, you MUST ALWAYS provide the `diff_content` parameter containing the exact CLI command, bash script, terraform plan, or configuration code to execute the fix based on the specific violation context.
CRITICAL: You MUST format the `diff_content` with proper `\\n` newline characters and indentation so that it is readable multi-line code. DO NOT output a single long line.
Be professional, concise, and helpful."""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_recent_audit_logs",
            "description": "Fetch the most recent audit logs for the tenant.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Number of logs to fetch (max 50, default 10)",
                        "default": 10
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_compliance_scores",
            "description": "Fetch the latest compliance scores (GDPR, HIPAA, SOC2) for the tenant.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_policy_violations",
            "description": "Fetch the most recent policy violations triggered by the AI Gateway.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Number of violations to fetch (max 50, default 10)",
                        "default": 10
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "propose_remediation",
            "description": "Propose a remediation action for a security issue, which will create an approval request for an administrator to review.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "A short, descriptive title for the proposed action"
                    },
                    "description": {
                        "type": "string",
                        "description": "Detailed explanation of why this action is needed and what it does"
                    },
                    "action_type": {
                        "type": "string",
                        "enum": ["terraform", "cli", "config"],
                        "description": "The type of action to take"
                    },
                    "diff_content": {
                        "type": "string",
                        "description": "The exact script, terraform plan, or configuration code that will be executed"
                    }
                },
                "required": ["title", "description", "action_type", "diff_content"]
            }
        }
    }
]

async def _get_recent_audit_logs(tenant_id: uuid.UUID, db: AsyncSession, limit: int = 10) -> str:
    result = await db.execute(
        select(AuditLog).where(AuditLog.tenant_id == tenant_id).order_by(desc(AuditLog.created_at)).limit(limit)
    )
    logs = result.scalars().all()
    if not logs:
        return "No recent audit logs found."
    return json.dumps([{"event": l.event_type, "action": l.action, "resource": l.resource, "time": l.created_at.isoformat()} for l in logs])

async def _get_compliance_scores(tenant_id: uuid.UUID, db: AsyncSession) -> str:
    scores = {}
    for fw in ["gdpr", "hipaa", "soc2"]:
        result = await db.execute(
            select(ComplianceScore).where(ComplianceScore.tenant_id == tenant_id, ComplianceScore.framework == fw)
            .order_by(desc(ComplianceScore.calculated_at)).limit(1)
        )
        s = result.scalars().first()
        if s:
            scores[fw] = {"score": s.score, "critical_violations": s.critical_violations, "missing": len(s.breakdown) if s.breakdown else 0}
    
    if not scores:
        return "No compliance scores have been calculated yet."
    return json.dumps(scores)

async def _get_policy_violations(tenant_id: uuid.UUID, db: AsyncSession, limit: int = 10) -> str:
    result = await db.execute(
        select(PolicyViolation).where(PolicyViolation.tenant_id == tenant_id).order_by(desc(PolicyViolation.created_at)).limit(limit)
    )
    violations = result.scalars().all()
    if not violations:
        return "No recent policy violations found."
    return json.dumps([{"rule": str(v.rule_id), "action": v.resolution, "severity": v.severity, "details": v.description, "time": v.created_at.isoformat()} for v in violations])

async def _propose_remediation(tenant_id: uuid.UUID, db: AsyncSession, title: str, description: str, action_type: str, diff_content: str = None) -> str:
    try:
        enum_action = ApprovalActionType(action_type)
    except ValueError:
        return f"Error: Invalid action_type {action_type}. Must be terraform, cli, or config."
        
    if not diff_content:
        # We must instruct the LLM properly if it fails to provide diff_content
        logger.warning("LLM failed to provide diff_content for remediation plan")
        diff_content = "# No automated script generated by the assistant. Please review manually."

    approval = Approval(
        tenant_id=tenant_id,
        title=title,
        description=description,
        action_type=enum_action,
        diff_content=diff_content,
        status=ApprovalStatus.pending
    )
    db.add(approval)
    await db.commit()
    return f"Successfully created pending approval request '{title}'. An administrator must approve it using their MFA token."

async def execute_tool(tool_call, tenant_id: uuid.UUID, db: AsyncSession) -> str:
    name = tool_call.function.name
    args = json.loads(tool_call.function.arguments or "{}")
    
    try:
        if name == "get_recent_audit_logs":
            limit = min(args.get("limit", 10), 50)
            return await _get_recent_audit_logs(tenant_id, db, limit)
        elif name == "get_compliance_scores":
            return await _get_compliance_scores(tenant_id, db)
        elif name == "get_policy_violations":
            limit = min(args.get("limit", 10), 50)
            return await _get_policy_violations(tenant_id, db, limit)
        elif name == "propose_remediation":
            return await _propose_remediation(
                tenant_id, 
                db, 
                args.get("title"), 
                args.get("description"), 
                args.get("action_type"),
                args.get("diff_content")
            )
        else:
            return f"Error: Unknown tool {name}"
    except Exception as e:
        logger.error("tool_execution_failed", tool=name, error=str(e))
        return f"Error executing tool: {str(e)}"

async def run_assistant_chat(messages: List[Dict[str, str]], tenant_id: uuid.UUID, db: AsyncSession) -> Dict[str, Any]:
    # Ensure system prompt is first
    formatted_messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    
    # Map the incoming messages (which might be simple role/content dicts)
    for m in messages:
        if m["role"] != "system":
            formatted_messages.append({"role": m["role"], "content": m["content"]})
            
    try:
        # Step 1: Initial LLM call
        response = await client.chat.completions.create(
            model=MODEL_NAME,
            messages=formatted_messages,
            tools=TOOLS,
            tool_choice="auto",
            max_tokens=2048
        )
        
        response_message = response.choices[0].message
        
        # Step 2: Check if LLM wants to call tools
        if response_message.tool_calls:
            formatted_messages.append(response_message)
            
            for tool_call in response_message.tool_calls:
                logger.info("executing_tool", tool=tool_call.function.name)
                tool_result = await execute_tool(tool_call, tenant_id, db)
                formatted_messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "name": tool_call.function.name,
                    "content": tool_result,
                })
                
            # Step 3: Call LLM again with tool results
            final_response = await client.chat.completions.create(
                model=MODEL_NAME,
                messages=formatted_messages,
                max_tokens=2048
            )
            
            return {
                "content": final_response.choices[0].message.content,
                "role": "assistant"
            }
            
        return {
            "content": response_message.content,
            "role": "assistant"
        }
        
    except Exception as e:
        logger.error("assistant_chat_failed", error=str(e))
        raise e
