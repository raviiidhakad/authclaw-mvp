import os
import ast

def parse_fastapi_endpoints(filepath):
    endpoints = []
    if not os.path.exists(filepath): return endpoints
    with open(filepath, 'r') as f:
        tree = ast.parse(f.read(), filename=filepath)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                    if dec.func.attr in ['get', 'post', 'put', 'delete', 'patch']:
                        path = ""
                        if dec.args and isinstance(dec.args[0], ast.Constant):
                            path = dec.args[0].value
                        endpoints.append(f"{dec.func.attr.upper()} {path}")
    return endpoints

matrix_md = "# Phase 3 Feature Matrix\n\n"

# Map out known features
features = [
    {"name": "Overview", "frontend_path": "page.tsx", "backend_module": "compliance.py"},
    {"name": "Providers", "frontend_path": "settings/page.tsx", "backend_module": "providers.py"},
    {"name": "Gateway Routes", "frontend_path": "gateway-routes/page.tsx", "backend_module": "gateway_routes.py"},
    {"name": "Live Traffic Inspector", "frontend_path": "gateway/page.tsx", "backend_module": "gateway.py"},
    {"name": "Policies & Guardrails", "frontend_path": "policies/page.tsx", "backend_module": "policies.py"},
    {"name": "Agent & Remediation Chat", "frontend_path": "agent/page.tsx", "backend_module": "agent.py"},
    {"name": "Approvals Queue", "frontend_path": "approvals/page.tsx", "backend_module": "approvals.py"},
    {"name": "Frameworks", "frontend_path": "compliance/page.tsx", "backend_module": "compliance.py"},
    {"name": "Audit & Trust Center", "frontend_path": "audit/page.tsx", "backend_module": "audit.py"},
    {"name": "Risk & Red Teaming", "frontend_path": "risk/page.tsx", "backend_module": "risk.py"},
    {"name": "Integrations", "frontend_path": "integrations/page.tsx", "backend_module": "integrations.py"},
    {"name": "Settings", "frontend_path": "settings/page.tsx", "backend_module": "settings.py"},
]

base_web = "C:/Users/dhaka/OneDrive/Desktop/AuthClaw Project/apps/web/src/app/(dashboard)/"
base_api = "C:/Users/dhaka/OneDrive/Desktop/AuthClaw Project/apps/api/app/api/v1/endpoints/"

for f in features:
    frontend_full = os.path.join(base_web, f['frontend_path'])
    backend_full = os.path.join(base_api, f['backend_module'])
    
    frontend_status = "MISSING"
    if os.path.exists(frontend_full):
        with open(frontend_full, 'r', encoding='utf-8') as web_f:
            content = web_f.read()
            if "TODO" in content or "mock" in content or "Not Implemented" in content:
                frontend_status = "MOCKED / INCOMPLETE"
            else:
                frontend_status = "IMPLEMENTED"
                
    backend_status = "MISSING"
    endpoints = []
    if os.path.exists(backend_full):
        endpoints = parse_fastapi_endpoints(backend_full)
        backend_status = "IMPLEMENTED" if endpoints else "MISSING / EMPTY"
        
    matrix_md += f"## {f['name']}\n"
    matrix_md += f"- **Frontend**: `{f['frontend_path']}` ({frontend_status})\n"
    matrix_md += f"- **Backend Module**: `{f['backend_module']}` ({backend_status})\n"
    matrix_md += f"- **Endpoints**: {', '.join(endpoints) if endpoints else 'None'}\n\n"

with open("C:/Users/dhaka/.gemini/antigravity/brain/8be91cef-0fab-4ec0-baaf-660ebaf94212/Phase3_Feature_Matrix.md", "w") as f:
    f.write(matrix_md)

print("Generated Phase3_Feature_Matrix.md")
