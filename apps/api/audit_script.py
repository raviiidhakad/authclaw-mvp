import json
import os

def check_file(path):
    return os.path.exists(path)

matrix = []

# 1. Overview
matrix.append({
    "Feature": "Overview Dashboard",
    "Frontend": "page.tsx",
    "Hook": "useDashboardStats, useComplianceDashboard",
    "Backend": "GET /api/v1/compliance/dashboard, GET /api/v1/gateway/dashboard",
    "Status": "UNKNOWN"
})

# 2. Gateway / Providers
matrix.append({
    "Feature": "Providers",
    "Frontend": "(dashboard)/settings/providers",
    "Hook": "useProviders",
    "Backend": "GET, POST, PATCH, DELETE /api/v1/providers",
    "Status": "WORKING"
})
matrix.append({
    "Feature": "Gateway Routes",
    "Frontend": "(dashboard)/gateway-routes",
    "Hook": "useGatewayRoutes",
    "Backend": "GET, POST, PATCH, DELETE /api/v1/gateway_routes",
    "Status": "WORKING"
})

print(json.dumps(matrix))
