from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)


ROOT = Path(__file__).resolve().parent
OUT = ROOT / "output" / "pdf" / "authclaw-chat-pdf-analysis.pdf"
OUT.parent.mkdir(parents=True, exist_ok=True)

styles = getSampleStyleSheet()
styles.add(
    ParagraphStyle(
        name="TitleCustom",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#111827"),
        spaceAfter=12,
    )
)
styles.add(
    ParagraphStyle(
        name="H1Custom",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#111827"),
        spaceBefore=12,
        spaceAfter=6,
    )
)
styles.add(
    ParagraphStyle(
        name="BodyCustom",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#1f2937"),
        spaceAfter=6,
    )
)
styles.add(
    ParagraphStyle(
        name="SmallCustom",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#4b5563"),
    )
)


def p(text, style="BodyCustom"):
    return Paragraph(text, styles[style])


def bullet(items):
    story = []
    for item in items:
        story.append(p(f"- {item}"))
    return story


def table(rows, widths):
    wrapped = []
    for r_idx, row in enumerate(rows):
        style = styles["SmallCustom"]
        if r_idx == 0:
            style = ParagraphStyle(
                name=f"TableHeader{len(rows)}",
                parent=styles["SmallCustom"],
                fontName="Helvetica-Bold",
                textColor=colors.HexColor("#111827"),
            )
        wrapped.append([Paragraph(str(cell), style) for cell in row])

    t = Table(wrapped, colWidths=widths, hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEADING", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return t


story = [
    p("AuthClaw Chat History and PDF Analysis", "TitleCustom"),
    p(
        "Prepared from the shared ChatGPT conversation, the extracted local transcript, "
        "the actual AuthClaw_Project_Plan.pdf, README.md, and a focused inspection of the current repository."
    ),
    p(
        "PDF source: C:/Users/dhaka/Downloads/AuthClaw_Project_Plan.pdf. It is a 17-page "
        "LibreOffice-generated engineering project plan created on June 12, 2026. "
        "The earlier pdf_content.txt matches this PDF's substance, mostly with extraction-format differences."
    ),
    Spacer(1, 0.12 * inch),
    p("Executive Readout", "H1Custom"),
    *bullet(
        [
            "AuthClaw is an enterprise AI security and compliance platform: AI gateway, PII/PHI redaction, policy enforcement, audit evidence, and agentic remediation.",
            "The source engineering plan defines a 4-phase MVP: 640 engineering hours per phase, 2,560 hours total.",
            "The chat expanded the plan into implementation-ready sprint work. Current handoff is Sprint 2 Phase 2: Vault Integration.",
            "Local repo state matches the latest chat claim that Sprint 2 Phase 1 created CloudIntegration and SecurityFinding models plus migration b2c3d4e5f6a7.",
            "Before Phase 2, tighten a few indexes and keep credentials strictly out of Postgres.",
        ]
    ),
    p("Project Meaning", "H1Custom"),
    p(
        "AuthClaw sits between customer applications and LLM providers. It inspects inbound prompts "
        "and outbound responses, detects sensitive data, enforces tenant policy, records immutable "
        "audit events, and later drives approved cloud or repository remediation through HITL workflows."
    ),
    p("Source Plan Scope", "H1Custom"),
    table(
        [
            ["Area", "MVP expectation"],
            ["Gateway", "Reverse proxy for model providers, PII/PHI redaction, OPA/YAML policy checks, streaming-safe filtering."],
            ["Agentic engine", "LangGraph orchestrator, scoped ephemeral workers, AWS/GCP/GitHub connectors, RAG explanations, HITL approvals."],
            ["Compliance/audit", "SOC 2/GDPR/HIPAA scoring, immutable audit store, cryptographic export, trust center."],
            ["Console", "Next.js dashboard for gateway config, policy editor, agent chat, approvals, audit explorer, tenant/RBAC/API keys."],
            ["Platform", "Multi-tenant RBAC, OIDC/IdP auth, envelope-encrypted secrets, rate limits, CI/CD, HA direction."],
        ],
        [1.35 * inch, 5.15 * inch],
    ),
    p("Phase Model", "H1Custom"),
    table(
        [
            ["Phase", "Focus", "Hours"],
            ["1", "Foundation and architecture: core platform, auth, tenancy, gateway/audit backbone.", "640"],
            ["2", "Agentic engine and guardrails: Presidio, policies, LangGraph, connectors, HITL.", "640"],
            ["3", "Developer experience and console: dashboard, configuration, audit explorer, approval UX.", "640"],
            ["4", "Compliance hardening: red team harness, cryptographic audit, trust center, HA/security validation.", "640"],
        ],
        [0.55 * inch, 5.1 * inch, 0.85 * inch],
    ),
    PageBreak(),
    p("Chat History Conclusions", "H1Custom"),
    *bullet(
        [
            "The first prompt asked for a detailed Hinglish explanation of two project PDFs: project meaning, tech stack, phases, implementation plan, fallback, and everything required to build it.",
            "The conversation established the engineering plan as the stronger source of truth over the simpler master spec.",
            "It repeatedly corrected scope from a simple SaaS to an enterprise AI gateway plus compliance and remediation platform.",
            "Sprint 1 focused on making the gateway real: PII scanning, policy cache, embedded evaluator, Kafka/ClickHouse-style audit events, streaming pipeline, health checks, tests, and feature flags.",
            "Sprint 2 focuses on real AWS/GitHub/GCP connectors replacing mock findings while preserving existing LangGraph state shape and architecture.",
            "Latest chat state: Sprint 2 Phase 1 is approved; next phase is Vault Integration.",
        ]
    ),
    p("Verified Local Repo State", "H1Custom"),
    table(
        [
            ["Item", "Observed locally"],
            ["Transcript", "chatgpt-share-transcript.md created from the shared chat; 98 messages extracted."],
            ["Actual PDF", "C:/Users/dhaka/Downloads/AuthClaw_Project_Plan.pdf exists; 17 pages; 370,250 bytes."],
            ["PDF text", "authclaw_project_plan_actual.txt extracted from the actual PDF; pdf_content.txt appears to be the same plan text."],
            ["Sprint 2 models", "apps/api/app/models/integration.py and finding.py exist."],
            ["Migration", "apps/api/alembic/versions/b2c3d4e5f6a7_sprint2_cloud_integrations_and_findings.py exists."],
            ["Config", "MAX_FINDINGS_PER_SYNC, MAX_SCAN_DURATION, MAX_AGENT_CONTEXT_FINDINGS, Vault KV path settings, ClickHouse settings, and FF_USE_REAL_CONNECTORS exist."],
            ["Model registry", "apps/api/app/models/__init__.py imports CloudIntegration, CloudProvider, IntegrationStatus, SecurityFinding, FindingSeverity, FindingStatus."],
        ],
        [1.45 * inch, 5.05 * inch],
    ),
    p("Phase 2 Gate Checks", "H1Custom"),
    *bullet(
        [
            "Credentials must never be stored in Postgres; only vault_reference_id belongs in CloudIntegration.",
            "Vault path must be tenant-scoped: secret/authclaw/tenants/{tenant_id}/integrations/{integration_id}.",
            "Credential validation should run before storing or activating an integration.",
            "Logs must redact provider secrets, tokens, role ARNs, and OAuth material.",
            "Cross-tenant Vault access must fail loudly and be covered by security tests.",
            "Failure modes should preserve existing mock path when FF_USE_REAL_CONNECTORS is false.",
        ]
    ),
    p("Practical Gaps To Fix Before Or During Phase 2", "H1Custom"),
    *bullet(
        [
            "CloudIntegration migration indexes tenant_id and unique tenant/provider/target, but provider_type and status are not separate migration indexes.",
            "SecurityFinding has integration_id, status+severity, and dedup_hash indexes; updated_at is not indexed in the migration.",
            "SecurityFinding does not store tenant_id directly; tenant isolation depends on joining through CloudIntegration. That is acceptable, but service code must enforce the join consistently.",
            "Git status could not be checked because Git flagged the repository as dubious ownership for the sandbox user.",
        ]
    ),
    KeepTogether(
        [
            p("Recommended Next Action", "H1Custom"),
            p(
                "Proceed to Sprint 2 Phase 2: Vault Integration, but first add or confirm the missing operational indexes "
                "and write tests for tenant-scoped secret retrieval. After Vault is solid, move to connector credential "
                "validation, worker locking, primary/fallback scanner interfaces, and raw finding storage."
            ),
        ]
    ),
]


def add_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#6b7280"))
    canvas.drawString(0.72 * inch, 0.45 * inch, "AuthClaw analysis report")
    canvas.drawRightString(7.78 * inch, 0.45 * inch, f"Page {doc.page}")
    canvas.restoreState()


doc = SimpleDocTemplate(
    str(OUT),
    pagesize=letter,
    rightMargin=0.7 * inch,
    leftMargin=0.7 * inch,
    topMargin=0.65 * inch,
    bottomMargin=0.65 * inch,
)
doc.build(story, onFirstPage=add_footer, onLaterPages=add_footer)
print(OUT)
