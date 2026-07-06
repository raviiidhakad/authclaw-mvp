import { useQuery, useMutation, useQueryClient, type QueryClient, type QueryKey } from '@tanstack/react-query';
import type { AxiosResponse } from 'axios';
import { apiClient } from '@/lib/api-client';

type ApiResponseData = AxiosResponse['data'];

function invalidateOnSuccess(queryClient: QueryClient, queryKeys: QueryKey[]) {
  return () => {
    queryKeys.forEach((queryKey) => queryClient.invalidateQueries({ queryKey }));
  };
}

async function getData<T = ApiResponseData>(url: string, params?: Record<string, unknown>) {
  const res = await apiClient.get(url, params === undefined ? undefined : { params });
  return res.data as T;
}

async function getItems<T = ApiResponseData>(url: string, params?: Record<string, unknown>) {
  const data = await getData<T[] | { items?: T[] }>(url, params);
  return Array.isArray(data) ? data : (data.items ?? []);
}

async function postData<T = ApiResponseData>(url: string, data?: unknown) {
  const res = await apiClient.post(url, data);
  return res.data as T;
}

async function patchData<T = ApiResponseData>(url: string, data: unknown) {
  const res = await apiClient.patch(url, data);
  return res.data as T;
}

async function putData<T = ApiResponseData>(url: string, data: unknown) {
  const res = await apiClient.put(url, data);
  return res.data as T;
}

async function deleteData(url: string) {
  await apiClient.delete(url);
}

// ── Dashboard / Stats ──
export function useDashboardStats() {
  return useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: async () => {
      const [tenants, audit] = await Promise.all([
        apiClient.get('/tenants/stats'),
        apiClient.get('/audit/stats'),
      ]);
      return { tenants: tenants.data, audit: audit.data };
    },
    refetchInterval: 5000,
  });
}

// ── Policies ──
export function usePolicies(skip = 0, limit = 50) {
  return useQuery({
    queryKey: ['policies', skip, limit],
    queryFn: () => getItems('/policies', { skip, limit }),
  });
}

export function useCreatePolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Record<string, unknown>) => postData('/policies', data),
    onSuccess: invalidateOnSuccess(queryClient, [['policies']]),
  });
}

export function useDeletePolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deleteData(`/policies/${id}`),
    onSuccess: invalidateOnSuccess(queryClient, [['policies']]),
  });
}

export function useUpdatePolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) => patchData(`/policies/${id}`, data),
    onSuccess: invalidateOnSuccess(queryClient, [['policies']]),
  });
}

// ── Policy Violations (dedicated violations endpoint) ──
export function useValidatePolicyYaml() {
  return useMutation({
    mutationFn: (yamlSource: string) => postData('/policies/validate', { yaml_source: yamlSource }),
  });
}

export function useTestPolicyYaml() {
  return useMutation({
    mutationFn: ({ yamlSource, sampleText }: { yamlSource: string; sampleText: string }) => postData('/policies/test', { yaml_source: yamlSource, sample_text: sampleText }),
  });
}

export function useImportPolicyYaml() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (yamlSource: string) => postData('/policies/import-yaml', { yaml_source: yamlSource }),
    onSuccess: invalidateOnSuccess(queryClient, [['policies']]),
  });
}

export function usePolicyViolations(skip = 0, limit = 100) {
  return useQuery({
    queryKey: ['policy-violations', skip, limit],
    queryFn: async () => {
      const res = await apiClient.get('/audit/violations', { params: { skip, limit } });
      // Backend returns { items, total } or bare array — handle both
      return Array.isArray(res.data) ? res.data : (res.data?.items ?? []);
    },
  });
}

export function useGatewayRequests(skip = 0, limit = 50, status?: string) {
  return useQuery({
    queryKey: ['gateway-requests', skip, limit, status],
    queryFn: async () => {
      const params: { skip: number; limit: number; status?: string } = { skip, limit };
      if (status) params.status = status;
      return getData('/gateway/requests', params);
    },
    refetchInterval: 5000,
  });
}

export function useGatewayRequestDetail(id: string | null) {
  return useQuery({
    queryKey: ['gateway-request', id],
    queryFn: () => (id ? getData(`/gateway/requests/${id}`) : null),
    enabled: !!id,
  });
}

// ── Gateway Routes ──
export function useGatewayRoutes() {
  return useQuery({
    queryKey: ['gateway-routes'],
    queryFn: () => getItems('/gateway-routes'),
  });
}

export function useCreateGatewayRoute() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Record<string, unknown>) => postData('/gateway-routes', data),
    onSuccess: invalidateOnSuccess(queryClient, [['gateway-routes']]),
  });
}

export function useUpdateGatewayRoute() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) => patchData(`/gateway-routes/${id}`, data),
    onSuccess: invalidateOnSuccess(queryClient, [['gateway-routes']]),
  });
}

export function useDeleteGatewayRoute() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deleteData(`/gateway-routes/${id}`),
    onSuccess: invalidateOnSuccess(queryClient, [['gateway-routes']]),
  });
}

// ── Audit Logs ──
export function useAuditLogs(skip = 0, limit = 50, eventType?: string) {
  return useQuery({
    queryKey: ['audit-logs', skip, limit, eventType],
    queryFn: async () => {
      const params: { skip: number; limit: number; event_type?: string } = { skip, limit };
      if (eventType) params.event_type = eventType;
      const res = await apiClient.get('/audit/logs', { params });
      return res.data; // { items, total }
    },
  });
}

export type AuditIntegrityReport = {
  status: 'intact' | 'tampered' | string;
  scanned_records: number;
  missing_records: number;
  tampered_records: number;
  chain_breaks: number;
};

export function useAuditIntegrityVerification() {
  return useQuery({
    queryKey: ['audit-integrity-verification'],
    queryFn: () => getData<AuditIntegrityReport>('/audit/verify'),
    refetchInterval: 30000,
  });
}

// ── Compliance ──
export function useComplianceDashboard() {
  return useQuery({
    queryKey: ['compliance-dashboard'],
    queryFn: () => getData('/compliance/dashboard'),
    refetchInterval: 5000,
  });
}

export function useCalculateCompliance() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => postData('/compliance/scores/calculate'),
    onSuccess: invalidateOnSuccess(queryClient, [['compliance-dashboard'], ['compliance'], ['compliance-history']]),
  });
}

/**
 * Returns the latest scores for all frameworks as:
 * { gdpr: { score, critical_violations, ... } | null, hipaa: {...}, soc2: {...} }
 * plus a synthesised overall_score and missing_controls for the compliance page.
 */
export function useCompliance() {
  return useQuery({
    queryKey: ['compliance'],
    queryFn: async () => {
      const res = await apiClient.get('/compliance/scores');
      const data = res.data as Record<string, {
        score: number;
        critical_violations: number;
        policy_failures: number;
        security_findings: number;
        breakdown: Record<string, boolean>;
        calculated_at: string;
      } | null>;

      // Compute an overall score as the average of available framework scores
      const frameworkKeys = Object.keys(data);
      const validScores = frameworkKeys
        .map((k) => data[k]?.score)
        .filter((s): s is number => s != null);

      const overall_score =
        validScores.length > 0
          ? Math.round(validScores.reduce((a, b) => a + b, 0) / validScores.length)
          : 0;

      // Collect missing controls from breakdown (false entries)
      const missing_controls: string[] = [];
      for (const [fw, entry] of Object.entries(data)) {
        if (entry?.breakdown) {
          for (const [control, passed] of Object.entries(entry.breakdown)) {
            if (!passed) {
              missing_controls.push(`[${fw.toUpperCase()}] ${control}`);
            }
          }
        }
      }

      return { overall_score, missing_controls, frameworks: data };
    },
  });
}

/**
 * Score history for a specific framework — uses /compliance/scores/history.
 * Returns an array of { score, calculated_at, critical_violations, ... }
 */
export function useComplianceHistory(limit = 10, framework = 'gdpr') {
  return useQuery({
    queryKey: ['compliance-history', framework, limit],
    queryFn: async () => {
      const res = await apiClient.get('/compliance/scores/history', {
        params: { framework, limit },
      });
      return res.data as Array<{
        score: number;
        critical_violations: number;
        policy_failures: number;
        security_findings: number;
        calculated_at: string;
      }>;
    },
  });
}

// ── Settings (API Keys, Users, Providers) ──
export function useProviders() {
  return useQuery({
    queryKey: ['providers'],
    queryFn: () => getItems('/providers'),
  });
}

export function useCreateProvider() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Record<string, unknown>) => postData('/providers', data),
    onSuccess: invalidateOnSuccess(queryClient, [['providers']]),
  });
}

export function useDeleteProvider() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deleteData(`/providers/${id}`),
    onSuccess: invalidateOnSuccess(queryClient, [['providers']]),
  });
}

export function useUpdateProvider() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) => patchData(`/providers/${id}`, data),
    onSuccess: invalidateOnSuccess(queryClient, [['providers']]),
  });
}

export function useApiKeys(skip = 0, limit = 50) {
  return useQuery({
    queryKey: ['api-keys', skip, limit],
    queryFn: () => getData('/api-keys', { skip, limit }),
  });
}

export function useCreateApiKey() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Record<string, unknown>) => postData('/api-keys', data),
    onSuccess: invalidateOnSuccess(queryClient, [['api-keys']]),
  });
}

export function useRevokeApiKey() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await apiClient.post(`/api-keys/${id}/revoke`);
    },
    onSuccess: invalidateOnSuccess(queryClient, [['api-keys']]),
  });
}

export type TenantDetails = {
  id: string;
  name: string;
  slug: string;
  plan: string;
  status: string;
  settings: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type RateLimitTier = {
  plan_name: string;
  requests_per_minute: number;
  requests_per_day: number;
  api_key_requests_per_minute: number;
  route_model_requests_per_minute: number;
  provider_requests_per_minute: number;
  concurrent_gateway_requests: number;
  concurrent_streams: number;
  max_body_bytes: number;
  connector_scan_concurrency: number;
  connector_scan_interval_seconds: number;
  report_generation_per_hour: number;
  remediation_job_concurrency: number;
};

export type TenantUser = {
  id: string;
  email: string;
  first_name?: string | null;
  last_name?: string | null;
  is_active: boolean;
  tenant_id: string;
  roles: string[];
  created_at: string;
  updated_at?: string;
};

export function useTenantDetails() {
  return useQuery({
    queryKey: ['tenant-details'],
    queryFn: () => getData<TenantDetails>('/tenants'),
  });
}

export function useUpdateTenantDetails() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Partial<Pick<TenantDetails, 'name' | 'status' | 'plan' | 'settings'>>) => patchData<TenantDetails>('/tenants', data),
    onSuccess: invalidateOnSuccess(queryClient, [['tenant-details'], ['dashboard-stats']]),
  });
}

export function useRateLimitTiers() {
  return useQuery({
    queryKey: ['rate-limit-tiers'],
    queryFn: () => getData<RateLimitTier[]>('/tenants/rate-limit-tiers'),
  });
}

export function useTenantUsers() {
  return useQuery({
    queryKey: ['tenant-users'],
    queryFn: () => getData<TenantUser[]>('/users'),
  });
}

export function useCreateTenantUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { email: string; first_name: string; last_name: string; password: string; role_name: string }) => postData<TenantUser>('/users', data),
    onSuccess: invalidateOnSuccess(queryClient, [['tenant-users']]),
  });
}

export function useUpdateTenantUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Pick<TenantUser, 'email' | 'first_name' | 'last_name' | 'is_active'>> }) => patchData<TenantUser>(`/users/${id}`, data),
    onSuccess: invalidateOnSuccess(queryClient, [['tenant-users']]),
  });
}

export function useAssignTenantUserRoles() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, roles }: { id: string; roles: string[] }) => putData<TenantUser>(`/users/${id}/roles`, { roles }),
    onSuccess: invalidateOnSuccess(queryClient, [['tenant-users']]),
  });
}

export function useDeleteTenantUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deleteData(`/users/${id}`),
    onSuccess: invalidateOnSuccess(queryClient, [['tenant-users']]),
  });
}

// ── Agent & Approvals (HITL) ──
export function useApprovals() {
  const queryClient = useQueryClient();
  return useQuery({
    queryKey: ['approvals'],
    queryFn: async () => {
      const res = await apiClient.get('/approvals?_t=' + Date.now());
      const newData = res.data;
      
      // Defense in depth: Approvals are append-only/immutable history.
      // If the backend intermittently returns an empty array due to a failure,
      // preserve the existing valid state to prevent UI flicker.
      if (Array.isArray(newData) && newData.length === 0) {
        const previousData = queryClient.getQueryData(['approvals']);
        if (Array.isArray(previousData) && previousData.length > 0) {
          console.warn('Backend returned empty approvals but we have existing data. Preserving existing data to prevent UI flicker.');
          return previousData;
        }
      }
      return newData;
    },
    refetchInterval: 5000,
  });
}

export function useApproveAction() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, code }: { id: string; code: string }) => postData(`/approvals/${id}/approve`, { code }),
    onSuccess: invalidateOnSuccess(queryClient, [['approvals']]),
  });
}

export function useRejectAction() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => postData(`/approvals/${id}/reject`),
    onSuccess: invalidateOnSuccess(queryClient, [['approvals']]),
  });
}

export function useRunAgentScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (target: string) => postData('/ai/analyze', { target }),
    onSuccess: invalidateOnSuccess(queryClient, [['approvals']]),
  });
}

// -- Sprint 2 Phase 10: Cloud integrations and findings --
export type CloudProvider = 'aws' | 'github' | 'gcp';
export type IntegrationStatus = 'pending' | 'active' | 'error' | 'syncing' | 'disabled';
export type FindingSeverity = 'low' | 'medium' | 'high' | 'critical';
export type FindingStatus = 'new' | 'active' | 'remediating' | 'resolved' | 'suppressed';

export interface CloudIntegration {
  id: string;
  tenant_id: string;
  provider_type: CloudProvider;
  target_identifier: string;
  display_name?: string | null;
  status: IntegrationStatus;
  vault_reference_id?: string;
  last_sync_at?: string | null;
  last_sync_finding_count: number;
  error_message?: string | null;
  created_at: string;
  updated_at: string;
}

export interface IntegrationHealth {
  integration_id?: string | null;
  provider_type?: CloudProvider | null;
  status?: IntegrationStatus | null;
  last_sync_at?: string | null;
  last_success_at?: string | null;
  last_failure_at?: string | null;
  last_error_code?: string | null;
  circuit_breaker_state?: Record<string, unknown> | null;
  worker_visibility: string;
  registered_connector_available: boolean;
}

export interface SecurityFinding {
  id: string;
  integration_id: string;
  provider_type: CloudProvider;
  dedup_hash: string;
  external_id: string;
  resource_id: string;
  title: string;
  description?: string | null;
  remediation_instructions?: string | null;
  severity: FindingSeverity;
  status: FindingStatus;
  resolved_at?: string | null;
  created_at: string;
  updated_at: string;
  compliance_tags: string[];
  service?: string | null;
}

export interface IntegrationCreatePayload {
  provider_type: CloudProvider;
  target_identifier: string;
  display_name?: string;
  credentials: Record<string, unknown>;
}

export interface IntegrationUpdatePayload {
  target_identifier?: string;
  display_name?: string;
  status?: IntegrationStatus;
  credentials?: Record<string, unknown>;
}

export interface IntegrationValidationResult {
  provider_type: CloudProvider;
  valid: boolean;
  error_code?: string | null;
  missing_permissions: string[];
}

export interface FindingsFilters {
  provider_type?: string;
  integration_id?: string;
  severity?: string;
  status?: string;
  service?: string;
  skip?: number;
  limit?: number;
}

export async function listIntegrations(params?: { provider_type?: string; status?: string; skip?: number; limit?: number }) {
  return getData<{ items: CloudIntegration[]; total: number }>('/integrations', params);
}

export async function getIntegration(id: string) {
  return getData<CloudIntegration>(`/integrations/${id}`);
}

export async function createIntegration(data: IntegrationCreatePayload) {
  return postData<CloudIntegration>('/integrations', data);
}

export async function updateIntegration({ id, data }: { id: string; data: IntegrationUpdatePayload }) {
  return patchData<CloudIntegration>(`/integrations/${id}`, data);
}

export async function deleteIntegration(id: string) {
  await deleteData(`/integrations/${id}`);
}

export async function validateIntegration(data: IntegrationCreatePayload) {
  return postData<IntegrationValidationResult>('/integrations/validate', data);
}

export async function validateExistingIntegration(id: string) {
  return postData<IntegrationValidationResult>(`/integrations/${id}/validate`);
}

export async function requestIntegrationSync(id: string) {
  return postData<{ integration_id: string; status: string; queued: boolean }>(`/integrations/${id}/sync`);
}

export async function getIntegrationHealth(id?: string) {
  return getData<IntegrationHealth | { registered_providers: string[]; circuit_breakers: Record<string, unknown>; items: IntegrationHealth[] }>(id ? `/integrations/${id}/health` : '/integrations/health');
}

export async function listFindings(params: FindingsFilters = {}) {
  return getData<{ items: SecurityFinding[]; total: number; skip: number; limit: number }>('/findings', cleanParams(params));
}

export async function getFinding(id: string) {
  return getData<SecurityFinding>(`/findings/${id}`);
}

export async function updateFindingStatus({ id, status }: { id: string; status: FindingStatus }) {
  return patchData<SecurityFinding>(`/findings/${id}`, { status });
}

export function useIntegrations(params?: { provider_type?: string; status?: string; skip?: number; limit?: number }) {
  return useQuery({
    queryKey: ['integrations', params],
    queryFn: () => listIntegrations(params),
    refetchInterval: 10000,
  });
}

export function useCreateIntegration() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: createIntegration,
    onSuccess: invalidateOnSuccess(queryClient, [['integrations'], ['integration-health']]),
  });
}

export function useUpdateIntegration() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: updateIntegration,
    onSuccess: invalidateOnSuccess(queryClient, [['integrations'], ['integration-health']]),
  });
}

export function useDeleteIntegration() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: deleteIntegration,
    onSuccess: invalidateOnSuccess(queryClient, [['integrations'], ['integration-health']]),
  });
}

export function useValidateIntegration() {
  return useMutation({ mutationFn: validateIntegration });
}

export function useValidateExistingIntegration() {
  return useMutation({ mutationFn: validateExistingIntegration });
}

export function useRequestIntegrationSync() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: requestIntegrationSync,
    onSuccess: invalidateOnSuccess(queryClient, [['integrations'], ['integration-health']]),
  });
}

export function useIntegrationHealth() {
  return useQuery({
    queryKey: ['integration-health'],
    queryFn: () => getIntegrationHealth() as Promise<{ registered_providers: string[]; circuit_breakers: Record<string, unknown>; items: IntegrationHealth[] }>,
    refetchInterval: 10000,
  });
}

export function useFindings(filters: FindingsFilters) {
  return useQuery({
    queryKey: ['findings', filters],
    queryFn: () => listFindings(filters),
    refetchInterval: 10000,
  });
}

export function useFinding(id: string | null) {
  return useQuery({
    queryKey: ['finding', id],
    queryFn: () => (id ? getFinding(id) : null),
    enabled: !!id,
  });
}

export function useUpdateFindingStatus() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: updateFindingStatus,
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      queryClient.invalidateQueries({ queryKey: ['finding', variables.id] });
    },
  });
}

// -- Sprint 3 Phase 7: Compliance Intelligence Console --
export interface ComplianceFramework {
  id: string;
  key: string;
  version: string;
  name: string;
  description?: string | null;
  source_url?: string | null;
  license_note: string;
  status: string;
  metadata: Record<string, unknown>;
  control_count: number;
  created_at: string;
  updated_at: string;
}

export interface ComplianceRequirement {
  id: string;
  requirement_key: string;
  summary: string;
  evidence_expectation?: string | null;
  sort_order: number;
}

export interface ComplianceControl {
  id: string;
  framework_id: string;
  control_code: string;
  title: string;
  summary: string;
  domain: string;
  category?: string | null;
  severity_weight: number;
  requires_review: boolean;
  sort_order: number;
  metadata: Record<string, unknown>;
  requirements: ComplianceRequirement[];
  created_at: string;
  updated_at: string;
}

export interface ComplianceMapping {
  id: string;
  tenant_id: string;
  finding_id: string;
  control_id: string;
  rule_id: string;
  confidence: number;
  mapping_source: string;
  review_status: string;
  override_reason?: string | null;
  control_code?: string | null;
  control_title?: string | null;
  framework_key?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ControlAssessmentResult {
  id: string;
  tenant_id: string;
  assessment_id: string;
  control_id: string;
  score: number;
  score_band: string;
  evidence_count: number;
  gap_count: number;
  explanation: string;
  metadata: Record<string, unknown>;
  control_code?: string | null;
  control_title?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ComplianceAssessment {
  id: string;
  tenant_id: string;
  framework_id: string;
  framework_key?: string | null;
  status: string;
  score: number;
  score_band: string;
  started_at: string;
  completed_at?: string | null;
  inputs_hash: string;
  explanation: string;
  control_results: ControlAssessmentResult[];
  gaps: ComplianceGap[];
  created_at: string;
  updated_at: string;
}

export interface EvidenceItem {
  id: string;
  tenant_id: string;
  control_id: string;
  finding_id?: string | null;
  integration_id?: string | null;
  audit_log_id?: string | null;
  mapping_id?: string | null;
  source_type: string;
  status: string;
  safe_summary: string;
  proof_hash?: string | null;
  freshness_expires_at?: string | null;
  metadata: Record<string, unknown>;
  control_code?: string | null;
  framework_key?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ComplianceGap {
  id: string;
  tenant_id: string;
  assessment_id: string;
  control_id: string;
  evidence_id?: string | null;
  mapping_id?: string | null;
  finding_id?: string | null;
  gap_type: string;
  severity: string;
  reason: string;
  evidence_status: string;
  metadata: Record<string, unknown>;
  control_code?: string | null;
  framework_key?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ComplianceRecommendation {
  id: string;
  tenant_id: string;
  control_id: string;
  gap_id?: string | null;
  finding_id?: string | null;
  severity: string;
  status: string;
  title: string;
  summary: string;
  control_code?: string | null;
  framework_key?: string | null;
  created_at: string;
}

export interface KnowledgeDocument {
  id: string;
  tenant_id?: string | null;
  framework_id?: string | null;
  source_type: string;
  title: string;
  source_url?: string | null;
  license_status: string;
  trust_level: string;
  checksum: string;
  status: string;
  ingested_by?: string | null;
  metadata: Record<string, unknown>;
  chunk_count: number;
  chunks?: KnowledgeChunk[];
  created_at: string;
  updated_at: string;
}

export interface KnowledgeChunk {
  id: string;
  document_id: string;
  framework_id?: string | null;
  tenant_id?: string | null;
  control_id?: string | null;
  chunk_index: number;
  chunk_text: string;
  summary?: string | null;
  metadata: Record<string, unknown>;
  source_locator?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ComplianceAskResponse {
  answer: string;
  confidence: number;
  citations: Record<string, unknown>[];
  related_controls: Record<string, unknown>[];
  related_evidence: Record<string, unknown>[];
  related_gaps: Record<string, unknown>[];
  recommended_next_steps: string[];
  refusal_reason?: string | null;
  retrieval_trace_id?: string | null;
  session_id: string;
}

export interface ComplianceAskSession {
  id: string;
  tenant_id: string;
  user_id?: string | null;
  question_hash: string;
  answer: string;
  citations: Record<string, unknown>[];
  confidence: number;
  refused: boolean;
  refusal_reason?: string | null;
  framework_id?: string | null;
  control_id?: string | null;
  assessment_id?: string | null;
  retrieval_trace_id?: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

type ListResponse<T> = { items: T[]; total: number; skip: number; limit: number; status?: string };

function cleanParams(params: object = {}) {
  return Object.fromEntries(
    Object.entries(params).filter(([, value]) => value !== undefined && value !== null && value !== '')
  );
}

export async function listComplianceFrameworks(params: Record<string, unknown> = {}) {
  return getData<ComplianceFramework[]>('/compliance/frameworks', cleanParams(params));
}

export async function getComplianceFramework(id: string) {
  return getData<ComplianceFramework>(`/compliance/frameworks/${id}`);
}

export async function listComplianceControls(frameworkId: string, params: Record<string, unknown> = {}) {
  return getData<ListResponse<ComplianceControl>>(`/compliance/frameworks/${frameworkId}/controls`, cleanParams(params));
}

export async function getComplianceControl(id: string) {
  return getData<ComplianceControl>(`/compliance/controls/${id}`);
}

export async function listComplianceMappings(params: Record<string, unknown> = {}) {
  return getData<ListResponse<ComplianceMapping>>('/compliance/mappings', cleanParams(params));
}

export async function reviewComplianceMapping({ id, data }: { id: string; data: { review_status: 'approved' | 'rejected' | 'overridden'; override_reason?: string } }) {
  return patchData<ComplianceMapping>(`/compliance/mappings/${id}/review`, data);
}

export async function runComplianceAssessment(data: { framework_id?: string; framework?: string }) {
  return postData<ComplianceAssessment>('/compliance/assessments/run', data);
}

export async function listComplianceAssessments(params: Record<string, unknown> = {}) {
  return getData<ListResponse<ComplianceAssessment>>('/compliance/assessments', cleanParams(params));
}

export async function getComplianceAssessment(id: string) {
  return getData<ComplianceAssessment>(`/compliance/assessments/${id}`);
}

export async function getAssessmentControls(id: string, params: Record<string, unknown> = {}) {
  return getData<ControlAssessmentResult[]>(`/compliance/assessments/${id}/controls`, cleanParams(params));
}

export async function listComplianceEvidence(params: Record<string, unknown> = {}) {
  return getData<ListResponse<EvidenceItem>>('/compliance/evidence', cleanParams(params));
}

export async function getComplianceEvidence(id: string) {
  return getData<EvidenceItem>(`/compliance/evidence/${id}`);
}

export async function listComplianceGaps(params: Record<string, unknown> = {}) {
  return getData<ListResponse<ComplianceGap>>('/compliance/gaps', cleanParams(params));
}

export async function getComplianceGap(id: string) {
  return getData<ComplianceGap>(`/compliance/gaps/${id}`);
}

export async function listComplianceRecommendations(params: Record<string, unknown> = {}) {
  return getData<ListResponse<ComplianceRecommendation>>('/compliance/recommendations', cleanParams(params));
}

export async function listKnowledgeDocuments(params: Record<string, unknown> = {}) {
  return getData<ListResponse<KnowledgeDocument>>('/compliance/knowledge', cleanParams(params));
}

export async function getKnowledgeDocument(id: string) {
  return getData<KnowledgeDocument>(`/compliance/knowledge/${id}`);
}

export async function ingestKnowledge(data: { tenant_scoped?: boolean } = { tenant_scoped: false }) {
  return postData<{ documents_seen: number; documents_created: number; documents_updated: number; chunks_created: number }>('/compliance/knowledge/ingest', data);
}

export async function queryComplianceRetrieval(data: { query: string; framework_id?: string; control_id?: string; limit?: number; session_id?: string }) {
  return postData('/compliance/retrieval/query', data);
}

export async function askCompliance(data: { question: string; framework_id?: string; control_id?: string; finding_id?: string; assessment_id?: string }) {
  return postData<ComplianceAskResponse>('/compliance/ask', data);
}

export async function listComplianceAskSessions(params: Record<string, unknown> = {}) {
  return getData<ListResponse<ComplianceAskSession>>('/compliance/ask/sessions', cleanParams(params));
}

export async function getComplianceAskSession(id: string) {
  return getData<ComplianceAskSession>(`/compliance/ask/sessions/${id}`);
}

export function useComplianceFrameworks(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['compliance-frameworks', params], queryFn: () => listComplianceFrameworks(params) });
}

export function useComplianceFramework(id?: string) {
  return useQuery({ queryKey: ['compliance-framework', id], queryFn: () => (id ? getComplianceFramework(id) : null), enabled: !!id });
}

export function useComplianceControls(frameworkId?: string, params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['compliance-controls', frameworkId, params], queryFn: () => (frameworkId ? listComplianceControls(frameworkId, params) : { items: [], total: 0, skip: 0, limit: 0 }), enabled: !!frameworkId });
}

export function useComplianceControl(id?: string) {
  return useQuery({ queryKey: ['compliance-control', id], queryFn: () => (id ? getComplianceControl(id) : null), enabled: !!id });
}

export function useComplianceMappings(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['compliance-mappings', params], queryFn: () => listComplianceMappings(params) });
}

export function useReviewComplianceMapping() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: reviewComplianceMapping,
    onSuccess: invalidateOnSuccess(queryClient, [['compliance-mappings']]),
  });
}

export function useRunComplianceAssessment() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: runComplianceAssessment,
    onSuccess: invalidateOnSuccess(queryClient, [['compliance-assessments'], ['compliance-gaps'], ['compliance-evidence'], ['compliance-recommendations']]),
  });
}

export function useComplianceAssessments(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['compliance-assessments', params], queryFn: () => listComplianceAssessments(params) });
}

export function useAssessmentControls(id?: string, params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['compliance-assessment-controls', id, params], queryFn: () => (id ? getAssessmentControls(id, params) : []), enabled: !!id });
}

export function useComplianceEvidence(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['compliance-evidence', params], queryFn: () => listComplianceEvidence(params) });
}

export function useComplianceGaps(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['compliance-gaps', params], queryFn: () => listComplianceGaps(params) });
}

export function useComplianceRecommendations(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['compliance-recommendations', params], queryFn: () => listComplianceRecommendations(params) });
}

export function useKnowledgeDocuments(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['compliance-knowledge', params], queryFn: () => listKnowledgeDocuments(params) });
}

export function useIngestKnowledge() {
  const queryClient = useQueryClient();
  return useMutation({ mutationFn: ingestKnowledge, onSuccess: invalidateOnSuccess(queryClient, [['compliance-knowledge']]) });
}

export function useAskCompliance() {
  const queryClient = useQueryClient();
  return useMutation({ mutationFn: askCompliance, onSuccess: invalidateOnSuccess(queryClient, [['compliance-ask-sessions']]) });
}

export function useComplianceAskSessions(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['compliance-ask-sessions', params], queryFn: () => listComplianceAskSessions(params) });
}

// -- Sprint 5 Phase 4: Trust Center and Report Center --
export interface TrustPosture {
  tenant_id: string;
  generated_at: string;
  language: string;
  posture: string;
  counts: Record<string, unknown>;
  status_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  freshness: Record<string, unknown>;
}

export interface TrustOverview {
  tenant_id: string;
  generated_at: string;
  language: string;
  security_posture: TrustPosture;
  compliance_posture: TrustPosture;
  remediation_posture: TrustPosture;
  integration_health: TrustPosture;
}

export interface AuditExportVerificationStateInfo {
  state: string;
  severity: string;
  meaning: string;
}

export interface AuditExportVerificationStates {
  generated_at: string;
  language: string;
  states: AuditExportVerificationStateInfo[];
}

export interface TrustNotification {
  id: string;
  tenant_id: string;
  recipient_user_id?: string | null;
  type: string;
  severity: string;
  title: string;
  body: string;
  resource_type?: string | null;
  resource_id?: string | null;
  read_at?: string | null;
  created_at: string;
}

export interface ActivityTimelineItem {
  id: string;
  tenant_id: string;
  occurred_at: string;
  source: string;
  action: string;
  severity: string;
  actor_user_id?: string | null;
  resource_type: string;
  resource_id?: string | null;
  title: string;
  summary: string;
  metadata: Record<string, unknown>;
}

export interface ReportTemplate {
  id: string;
  tenant_id: string;
  name: string;
  type: string;
  format: 'json' | string;
  filters_schema: Record<string, unknown>;
  default_sections: unknown[];
  created_by?: string | null;
  created_at: string;
  updated_at: string;
  is_system: boolean;
}

export interface ReportTemplatePayload {
  name: string;
  type: string;
  format?: 'json';
  filters_schema?: Record<string, unknown>;
  default_sections?: unknown[];
  is_system?: boolean;
}

export interface ReportArtifactMetadata {
  id: string;
  tenant_id: string;
  run_id: string;
  artifact_type: string;
  content_hash: string;
  size_bytes: number;
  sanitization_version: string;
  created_at: string;
  expires_at?: string | null;
  manifest_hash?: string | null;
}

export interface ExportManifest {
  id: string;
  tenant_id: string;
  artifact_id: string;
  manifest_json: Record<string, unknown>;
  manifest_hash: string;
  hash_algorithm: string;
  created_at: string;
}

export interface ReportRun {
  id: string;
  tenant_id: string;
  template_id?: string | null;
  requested_by?: string | null;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'expired' | string;
  filters: Record<string, unknown>;
  started_at?: string | null;
  completed_at?: string | null;
  failed_reason?: string | null;
  expires_at?: string | null;
  artifacts: ReportArtifactMetadata[];
  manifest_hash?: string | null;
}

export interface ReportRunPayload {
  template_id?: string | null;
  report_type?: string;
  filters?: Record<string, unknown>;
  retention_days?: number;
}

export interface EvidencePackagePayload {
  framework_id?: string | null;
  control_ids?: string[] | null;
  date_from?: string | null;
  date_to?: string | null;
  evidence_freshness_days?: number | null;
  include_findings: boolean;
  include_remediation: boolean;
  output_format: 'json';
  template_id?: string | null;
  retention_days?: number;
}

export interface EvidencePackageResponse {
  run: ReportRun;
  artifact?: ReportArtifactMetadata | null;
  manifest?: ExportManifest | null;
}

export interface ReportAccessLog {
  id: string;
  tenant_id: string;
  artifact_id: string;
  actor_user_id?: string | null;
  external_share_id?: string | null;
  action: string;
  ip_hash?: string | null;
  user_agent_hash?: string | null;
  created_at: string;
}

export interface ReportArtifactDownload {
  artifact_id: string;
  tenant_id: string;
  requester_id?: string | null;
  external_share_id?: string | null;
  downloaded_at: string;
  manifest_hash?: string | null;
  content_type: 'application/json';
  watermark: Record<string, unknown>;
  artifact: Record<string, unknown>;
}

export interface ShareLinkRecord {
  id: string;
  tenant_id: string;
  artifact_id: string;
  scope: Record<string, unknown>;
  created_by?: string | null;
  expires_at: string;
  revoked_at?: string | null;
  max_downloads: number;
  token?: string;
}

export type TrustReportListResponse<T> = { items: T[]; total: number; skip: number; limit: number };

export async function getTrustOverview() {
  return getData<TrustOverview>('/trust/overview');
}

export async function getTrustPosture(kind: 'security' | 'compliance' | 'remediation' | 'integrations') {
  const pathByKind = {
    security: '/trust/security-posture',
    compliance: '/trust/compliance-posture',
    remediation: '/trust/remediation-posture',
    integrations: '/trust/integration-health',
  } satisfies Record<string, string>;
  return getData<TrustPosture>(pathByKind[kind]);
}

export async function getAuditExportVerificationStates() {
  return getData<AuditExportVerificationStates>('/trust/audit-export-verification-states');
}

export async function listTrustNotifications(params: Record<string, unknown> = {}) {
  return getData<TrustReportListResponse<TrustNotification> & { unread: number }>('/trust/notifications', cleanParams(params));
}

export async function getNotificationUnreadCount() {
  return getData<{ unread: number }>('/trust/notifications/unread-count');
}

export async function markTrustNotificationRead(id: string) {
  return postData<TrustNotification>(`/trust/notifications/${id}/read`);
}

export async function markAllTrustNotificationsRead() {
  return postData<{ unread: number }>('/trust/notifications/mark-all-read');
}

export async function listActivityTimeline(params: Record<string, unknown> = {}) {
  return getData<TrustReportListResponse<ActivityTimelineItem>>('/trust/activity', cleanParams(params));
}

export async function listReportTemplates(params: Record<string, unknown> = {}) {
  return getData<TrustReportListResponse<ReportTemplate>>('/reports/templates', cleanParams(params));
}

export async function createReportTemplate(data: ReportTemplatePayload) {
  return postData<ReportTemplate>('/reports/templates', { format: 'json', ...data });
}

export async function updateReportTemplate({ id, data }: { id: string; data: Partial<ReportTemplatePayload> }) {
  return patchData<ReportTemplate>(`/reports/templates/${id}`, data);
}

export async function deleteReportTemplate(id: string) {
  await apiClient.delete(`/reports/templates/${id}`);
}

export async function createReportRun(data: ReportRunPayload) {
  return postData<ReportRun>('/reports/run', data);
}

export async function listReportRuns(params: Record<string, unknown> = {}) {
  return getData<TrustReportListResponse<ReportRun>>('/reports/runs', cleanParams(params));
}

export async function getReportRun(id: string) {
  return getData<ReportRun>(`/reports/runs/${id}`);
}

export async function listReportArtifacts(params: Record<string, unknown> = {}) {
  return getData<TrustReportListResponse<ReportArtifactMetadata>>('/reports/artifacts', cleanParams(params));
}

export async function getReportArtifact(id: string) {
  return getData<ReportArtifactMetadata>(`/reports/artifacts/${id}`);
}

export async function getReportArtifactManifest(id: string) {
  return getData<ExportManifest>(`/reports/artifacts/${id}/manifest`);
}

export async function downloadReportArtifact(id: string) {
  return getData<ReportArtifactDownload>(`/reports/artifacts/${id}/download`);
}

export async function createShareLink(data: { artifact_id: string; expires_at: string; max_downloads: number }) {
  return postData<ShareLinkRecord>('/trust/share-links', data);
}

export async function listShareLinks(params: Record<string, unknown> = {}) {
  return getData<TrustReportListResponse<ShareLinkRecord>>('/trust/share-links', cleanParams(params));
}

export async function revokeShareLink(id: string) {
  return postData<ShareLinkRecord>(`/trust/share-links/${id}/revoke`);
}

export async function createEvidencePackage(data: EvidencePackagePayload) {
  return postData<EvidencePackageResponse>('/evidence-packages', data);
}

export async function listEvidencePackages(params: Record<string, unknown> = {}) {
  return getData<TrustReportListResponse<ReportRun>>('/evidence-packages', cleanParams(params));
}

export async function getEvidencePackage(id: string) {
  return getData<EvidencePackageResponse>(`/evidence-packages/${id}`);
}

export async function listReportAccessLogs(params: Record<string, unknown> = {}) {
  return getData<TrustReportListResponse<ReportAccessLog>>('/reports/access-logs', cleanParams(params));
}

export function useTrustOverview() {
  return useQuery({ queryKey: ['trust-overview'], queryFn: getTrustOverview, refetchInterval: 15000 });
}

export function useTrustPosture(kind: 'security' | 'compliance' | 'remediation' | 'integrations') {
  return useQuery({ queryKey: ['trust-posture', kind], queryFn: () => getTrustPosture(kind), refetchInterval: 15000 });
}

export function useAuditExportVerificationStates() {
  return useQuery({ queryKey: ['audit-export-verification-states'], queryFn: getAuditExportVerificationStates, refetchInterval: 30000 });
}

export function useTrustNotifications(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['trust-notifications', params], queryFn: () => listTrustNotifications(params), refetchInterval: 15000 });
}

export function useNotificationUnreadCount() {
  return useQuery({ queryKey: ['trust-notification-unread-count'], queryFn: getNotificationUnreadCount, refetchInterval: 15000 });
}

export function useMarkTrustNotificationRead() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: markTrustNotificationRead,
    onSuccess: invalidateOnSuccess(queryClient, [['trust-notifications'], ['trust-notification-unread-count']]),
  });
}

export function useMarkAllTrustNotificationsRead() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: markAllTrustNotificationsRead,
    onSuccess: invalidateOnSuccess(queryClient, [['trust-notifications'], ['trust-notification-unread-count']]),
  });
}

export function useActivityTimeline(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['trust-activity', params], queryFn: () => listActivityTimeline(params), refetchInterval: 15000 });
}

export function useReportTemplates(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['report-templates', params], queryFn: () => listReportTemplates(params) });
}

export function useCreateReportTemplate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: createReportTemplate,
    onSuccess: invalidateOnSuccess(queryClient, [['report-templates']]),
  });
}

export function useUpdateReportTemplate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: updateReportTemplate,
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['report-templates'] });
      queryClient.invalidateQueries({ queryKey: ['report-template', variables.id] });
    },
  });
}

export function useDeleteReportTemplate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: deleteReportTemplate,
    onSuccess: invalidateOnSuccess(queryClient, [['report-templates']]),
  });
}

export function useCreateReportRun() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: createReportRun,
    onSuccess: invalidateOnSuccess(queryClient, [['report-runs'], ['report-artifacts']]),
  });
}

export function useReportRuns(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['report-runs', params], queryFn: () => listReportRuns(params), refetchInterval: 10000 });
}

export function useReportRun(id?: string) {
  return useQuery({ queryKey: ['report-run', id], queryFn: () => (id ? getReportRun(id) : null), enabled: !!id });
}

export function useReportArtifacts(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['report-artifacts', params], queryFn: () => listReportArtifacts(params), refetchInterval: 10000 });
}

export function useReportArtifactManifest(id?: string) {
  return useQuery({ queryKey: ['report-artifact-manifest', id], queryFn: () => (id ? getReportArtifactManifest(id) : null), enabled: !!id });
}

export function useDownloadReportArtifact() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: downloadReportArtifact,
    onSuccess: invalidateOnSuccess(queryClient, [['report-access-logs']]),
  });
}

export function useCreateShareLink() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: createShareLink,
    onSuccess: invalidateOnSuccess(queryClient, [['share-links'], ['report-access-logs']]),
  });
}

export function useShareLinks(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['share-links', params], queryFn: () => listShareLinks(params), refetchInterval: 15000 });
}

export function useRevokeShareLink() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: revokeShareLink,
    onSuccess: invalidateOnSuccess(queryClient, [['share-links'], ['report-access-logs']]),
  });
}

export function useCreateEvidencePackage() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: createEvidencePackage,
    onSuccess: invalidateOnSuccess(queryClient, [['evidence-packages'], ['report-runs'], ['report-artifacts']]),
  });
}

export function useEvidencePackages(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['evidence-packages', params], queryFn: () => listEvidencePackages(params), refetchInterval: 10000 });
}

export function useEvidencePackage(id?: string) {
  return useQuery({ queryKey: ['evidence-package', id], queryFn: () => (id ? getEvidencePackage(id) : null), enabled: !!id });
}

export function useReportAccessLogs(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['report-access-logs', params], queryFn: () => listReportAccessLogs(params), refetchInterval: 15000 });
}

// -- Risk & Red Teaming MVP --
export type RiskProbeCategory =
  | 'prompt_injection'
  | 'data_disclosure'
  | 'credential_leakage'
  | 'harmful_content'
  | 'sycophancy_policy_bypass'
  | 'policy_bypass'
  | 'report_export_leakage';
export type RiskProbeStatus = 'queued' | 'running' | 'completed' | 'failed' | 'blocked';
export type RiskVulnerabilitySeverity = 'low' | 'medium' | 'high' | 'critical';
export type RiskVulnerabilityStatus = 'open' | 'triaged' | 'remediating' | 'accepted_risk' | 'resolved' | 'false_positive';
export type RiskGoNoGoVerdict = 'go' | 'needs_review' | 'no_go';

export interface AdversarialProbeRun {
  id: string;
  tenant_id: string;
  name: string;
  category: RiskProbeCategory | string;
  status: RiskProbeStatus | string;
  target_surface: string;
  model_target?: string | null;
  execution_mode: string;
  owner_user_id?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  safe_prompt_preview?: string | null;
  result_summary: string;
  risk_score: number;
  probes_total: number;
  blocked_count: number;
  allowed_count: number;
  vulnerability_count: number;
  evidence: Record<string, unknown>;
  results?: RedTeamProbeResult[];
  raw_payload_stored: boolean;
  created_at: string;
  updated_at: string;
}

export interface RedTeamProbeResult {
  id: string;
  tenant_id: string;
  probe_run_id: string;
  category: RiskProbeCategory | string;
  target_surface: string;
  status: string;
  severity: RiskVulnerabilitySeverity | string;
  confidence: number;
  evidence_summary: string;
  sanitized_input_summary: string;
  sanitized_output_summary: string;
  linked_finding_id?: string | null;
  linked_remediation_plan_id?: string | null;
  linked_control_id?: string | null;
  linked_report_artifact_id?: string | null;
  raw_payload_stored: boolean;
  created_at: string;
  updated_at: string;
}

export interface VulnerabilityRegisterItem {
  id: string;
  tenant_id: string;
  probe_run_id?: string | null;
  remediation_plan_id?: string | null;
  category: RiskProbeCategory | string;
  title: string;
  description: string;
  severity: RiskVulnerabilitySeverity | string;
  status: RiskVulnerabilityStatus | string;
  owner_user_id?: string | null;
  confidence: number;
  due_date?: string | null;
  linked_finding_id?: string | null;
  linked_control_id?: string | null;
  linked_report_artifact_id?: string | null;
  evidence_summary: string;
  remediation_summary?: string | null;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
}

export interface RiskPosture {
  verdict: RiskGoNoGoVerdict | string;
  summary: string;
  counts: {
    probe_runs?: number;
    vulnerabilities?: number;
    open_items?: number;
    open_high?: number;
    open_critical?: number;
    by_severity?: Record<string, number>;
    by_status?: Record<string, number>;
    by_category?: Record<string, number>;
    probe_categories_covered?: string[];
    [key: string]: unknown;
  };
  blockers: Array<Record<string, unknown>>;
  recommendations: unknown[];
  evidence_summary: string;
  generated_at: string;
}

export async function listRiskProbeRuns(params: Record<string, unknown> = {}) {
  return getData<RemediationListResponse<AdversarialProbeRun>>('/risk/probes', cleanParams(params));
}

export async function createRiskProbeRun(data: { name: string; category: RiskProbeCategory | string; target_surface?: string; model_target?: string | null }) {
  return postData<AdversarialProbeRun>('/risk/probes/run', data);
}

export async function listRiskVulnerabilities(params: Record<string, unknown> = {}) {
  return getData<RemediationListResponse<VulnerabilityRegisterItem>>('/risk/vulnerabilities', cleanParams(params));
}

export async function updateRiskVulnerability({ id, data }: { id: string; data: Record<string, unknown> }) {
  return patchData<VulnerabilityRegisterItem>(`/risk/vulnerabilities/${id}`, data);
}

export async function getRiskPosture() {
  return getData<RiskPosture>('/risk/posture');
}

export async function seedRiskDemoData() {
  return postData<Record<string, number>>('/risk/seed-demo');
}

export function useRiskProbeRuns(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['risk-probe-runs', params], queryFn: () => listRiskProbeRuns(params), refetchInterval: 15000 });
}

export function useCreateRiskProbeRun() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: createRiskProbeRun,
    onSuccess: invalidateOnSuccess(queryClient, [['risk-probe-runs'], ['risk-posture']]),
  });
}

export function useRiskVulnerabilities(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['risk-vulnerabilities', params], queryFn: () => listRiskVulnerabilities(params), refetchInterval: 15000 });
}

export function useUpdateRiskVulnerability() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: updateRiskVulnerability,
    onSuccess: invalidateOnSuccess(queryClient, [['risk-vulnerabilities'], ['risk-posture']]),
  });
}

export function useRiskPosture() {
  return useQuery({ queryKey: ['risk-posture'], queryFn: getRiskPosture, refetchInterval: 15000 });
}

export function useSeedRiskDemoData() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: seedRiskDemoData,
    onSuccess: invalidateOnSuccess(queryClient, [['risk-probe-runs'], ['risk-vulnerabilities'], ['risk-posture']]),
  });
}

// -- Sprint 4 Phase 6: Remediation Approval Console --
export type RemediationRiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type RemediationPlanStatus =
  | 'detected'
  | 'recommendation_created'
  | 'plan_drafted'
  | 'plan_validated'
  | 'approval_requested'
  | 'approved'
  | 'rejected'
  | 'expired'
  | 'queued_for_execution'
  | 'executing'
  | 'succeeded'
  | 'failed'
  | 'rollback_required'
  | 'rolled_back'
  | 'verified';
export type RemediationApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired' | 'revoked' | 'used';
export type RemediationApprovalLevel = 'operator' | 'admin' | 'owner' | 'security_admin';
export type RemediationExecutionStatus =
  | 'disabled'
  | 'queued'
  | 'dry_run_requested'
  | 'dry_run_succeeded'
  | 'dry_run_failed'
  | 'executing'
  | 'succeeded'
  | 'failed'
  | 'rollback_required'
  | 'rolled_back';
export type RemediationDryRunStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'rejected';
export type RemediationVerificationStatus = 'pending' | 'verified' | 'failed' | 'inconclusive';

export interface RemediationArtifact {
  id: string;
  tenant_id: string;
  plan_id: string;
  artifact_type: string;
  content_redacted?: string | null;
  diff_summary?: string | null;
  artifact_hash: string;
  risk_flags: Record<string, unknown>;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface RemediationRollbackPlan {
  id: string;
  tenant_id: string;
  plan_id: string;
  rollback_summary: string;
  rollback_artifact_hash?: string | null;
  risk_level: RemediationRiskLevel | string;
  created_at: string;
  updated_at?: string | null;
}

export interface RemediationPolicyCheck {
  id: string;
  tenant_id: string;
  plan_id: string;
  artifact_id?: string | null;
  passed: boolean;
  warnings: Array<Record<string, unknown>>;
  blocking_reasons: Array<Record<string, unknown>>;
  required_approval_level: RemediationApprovalLevel | string;
  policy_check_hash: string;
  created_at: string;
  updated_at: string;
}

export interface RemediationApproval {
  id: string;
  tenant_id: string;
  plan_id: string;
  artifact_hash: string;
  policy_check_hash: string;
  required_approval_level?: RemediationApprovalLevel | string | null;
  requested_by?: string | null;
  approved_by?: string | null;
  status: RemediationApprovalStatus | string;
  expires_at: string;
  resolved_at?: string | null;
  mfa_verified: boolean;
  approval_reason?: string | null;
  created_at: string;
  updated_at: string;
}

export interface RemediationExecutionJob {
  id: string;
  tenant_id: string;
  plan_id: string;
  approval_id?: string | null;
  sandbox_id?: string | null;
  dry_run_result_id?: string | null;
  status: RemediationExecutionStatus | string;
  disabled_reason?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface RemediationDryRunResult {
  id: string;
  tenant_id: string;
  job_id?: string | null;
  plan_id: string;
  artifact_id: string;
  approval_id?: string | null;
  sandbox_id: string;
  dry_run_type: string;
  status: RemediationDryRunStatus | string;
  output_summary: string;
  warnings: Array<Record<string, unknown>>;
  blocking_reasons: Array<Record<string, unknown>>;
  started_at?: string | null;
  completed_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface RemediationVerificationResult {
  id: string;
  tenant_id: string;
  plan_id: string;
  job_id?: string | null;
  finding_status_before?: string | null;
  finding_status_after?: string | null;
  evidence_id?: string | null;
  verified: boolean;
  verification_summary: string;
  status: RemediationVerificationStatus | string;
  created_at: string;
  updated_at: string;
}

export interface RemediationPlan {
  id: string;
  tenant_id: string;
  finding_id?: string | null;
  gap_id?: string | null;
  recommendation_id?: string | null;
  integration_id?: string | null;
  provider?: string | null;
  resource_ref?: string | null;
  risk_level: RemediationRiskLevel | string;
  status: RemediationPlanStatus | string;
  summary: string;
  expected_impact: string;
  created_by?: string | null;
  created_at: string;
  updated_at: string;
}

export interface RemediationPlanDetail extends RemediationPlan {
  artifacts: RemediationArtifact[];
  rollback_plan?: RemediationRollbackPlan | null;
  policy_checks: RemediationPolicyCheck[];
  approvals: RemediationApproval[];
  execution_jobs: RemediationExecutionJob[];
}

export type RemediationListResponse<T> = { items: T[]; total: number; skip: number; limit: number };

export async function listRemediationPlans(params: Record<string, unknown> = {}) {
  return getData<RemediationListResponse<RemediationPlan>>('/remediation/plans', cleanParams(params));
}

export async function generateRemediationPlan(data: { source_type: 'finding' | 'gap' | 'recommendation'; source_id: string }) {
  return postData<RemediationPlanDetail>('/remediation/plans/generate', data);
}

export async function getRemediationPlan(id: string) {
  return getData<RemediationPlanDetail>(`/remediation/plans/${id}`);
}

export async function listPlanArtifacts(planId: string, params: Record<string, unknown> = {}) {
  return getData<RemediationListResponse<RemediationArtifact>>(`/remediation/plans/${planId}/artifacts`, cleanParams(params));
}

export async function getRemediationArtifact(id: string) {
  return getData<RemediationArtifact>(`/remediation/artifacts/${id}`);
}

export async function validateRemediationPlan(planId: string) {
  return postData<{ plan: RemediationPlan; artifact: RemediationArtifact; policy_check: RemediationPolicyCheck }>(`/remediation/plans/${planId}/validate`);
}

export async function listPolicyChecks(planId: string, params: Record<string, unknown> = {}) {
  return getData<RemediationListResponse<RemediationPolicyCheck>>(`/remediation/plans/${planId}/policy-checks`, cleanParams(params));
}

export async function requestRemediationApproval({ planId, reason }: { planId: string; reason?: string }) {
  return postData<RemediationApproval>(`/remediation/plans/${planId}/request-approval`, { reason });
}

export async function listRemediationApprovals(params: Record<string, unknown> = {}) {
  return getData<RemediationListResponse<RemediationApproval>>('/remediation/approvals', cleanParams(params));
}

export async function getRemediationApproval(id: string) {
  return getData<RemediationApproval>(`/remediation/approvals/${id}`);
}

export async function approveRemediationApproval({ id, approval_reason, mfa_verified }: { id: string; approval_reason: string; mfa_verified: boolean }) {
  return postData<RemediationApproval>(`/remediation/approvals/${id}/approve`, { approval_reason, mfa_verified });
}

export async function rejectRemediationApproval({ id, rejection_reason }: { id: string; rejection_reason: string }) {
  return postData<RemediationApproval>(`/remediation/approvals/${id}/reject`, { rejection_reason });
}

export async function revokeRemediationApproval({ id, reason }: { id: string; reason: string }) {
  return postData<RemediationApproval>(`/remediation/approvals/${id}/revoke`, { reason });
}

export async function listRemediationJobs(params: Record<string, unknown> = {}) {
  return getData<RemediationListResponse<RemediationExecutionJob>>('/remediation/jobs', cleanParams(params));
}

export async function getRemediationJob(id: string) {
  return getData<RemediationExecutionJob>(`/remediation/jobs/${id}`);
}

export async function listRemediationDryRuns(params: Record<string, unknown> = {}) {
  return getData<RemediationListResponse<RemediationDryRunResult>>('/remediation/dry-runs', cleanParams(params));
}

export async function getRemediationDryRun(id: string) {
  return getData<RemediationDryRunResult>(`/remediation/dry-runs/${id}`);
}

export async function listRemediationVerificationResults(params: Record<string, unknown> = {}) {
  return getData<RemediationListResponse<RemediationVerificationResult>>('/remediation/verification-results', cleanParams(params));
}

export async function getRemediationVerificationResult(id: string) {
  return getData<RemediationVerificationResult>(`/remediation/verification-results/${id}`);
}

export function useRemediationPlans(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['remediation-plans', params], queryFn: () => listRemediationPlans(params) });
}

export function useGenerateRemediationPlan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: generateRemediationPlan,
    onSuccess: invalidateOnSuccess(queryClient, [['remediation-plans']]),
  });
}

export function useRemediationPlan(id?: string) {
  return useQuery({ queryKey: ['remediation-plan', id], queryFn: () => (id ? getRemediationPlan(id) : null), enabled: !!id });
}

export function usePlanArtifacts(planId?: string, params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['remediation-artifacts', planId, params], queryFn: () => (planId ? listPlanArtifacts(planId, params) : { items: [], total: 0, skip: 0, limit: 0 }), enabled: !!planId });
}

export function useRemediationArtifact(id?: string) {
  return useQuery({ queryKey: ['remediation-artifact', id], queryFn: () => (id ? getRemediationArtifact(id) : null), enabled: !!id });
}

export function useValidateRemediationPlan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: validateRemediationPlan,
    onSuccess: (_data, planId) => {
      queryClient.invalidateQueries({ queryKey: ['remediation-plans'] });
      queryClient.invalidateQueries({ queryKey: ['remediation-plan', planId] });
    },
  });
}

export function usePolicyChecks(planId?: string, params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['remediation-policy-checks', planId, params], queryFn: () => (planId ? listPolicyChecks(planId, params) : { items: [], total: 0, skip: 0, limit: 0 }), enabled: !!planId });
}

export function useRequestRemediationApproval() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: requestRemediationApproval,
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['remediation-approvals'] });
      queryClient.invalidateQueries({ queryKey: ['remediation-plans'] });
      queryClient.invalidateQueries({ queryKey: ['remediation-plan', variables.planId] });
    },
  });
}

export function useRemediationApprovals(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['remediation-approvals', params], queryFn: () => listRemediationApprovals(params) });
}

export function useRemediationApproval(id?: string) {
  return useQuery({ queryKey: ['remediation-approval', id], queryFn: () => (id ? getRemediationApproval(id) : null), enabled: !!id });
}

export function useApproveRemediationApproval() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: approveRemediationApproval,
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['remediation-approvals'] });
      queryClient.invalidateQueries({ queryKey: ['remediation-approval', variables.id] });
      queryClient.invalidateQueries({ queryKey: ['remediation-plans'] });
    },
  });
}

export function useRejectRemediationApproval() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: rejectRemediationApproval,
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['remediation-approvals'] });
      queryClient.invalidateQueries({ queryKey: ['remediation-approval', variables.id] });
      queryClient.invalidateQueries({ queryKey: ['remediation-plans'] });
    },
  });
}

export function useRevokeRemediationApproval() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: revokeRemediationApproval,
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['remediation-approvals'] });
      queryClient.invalidateQueries({ queryKey: ['remediation-approval', variables.id] });
      queryClient.invalidateQueries({ queryKey: ['remediation-plans'] });
    },
  });
}

export function useRemediationJobs(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['remediation-jobs', params], queryFn: () => listRemediationJobs(params) });
}

export function useRemediationJob(id?: string) {
  return useQuery({ queryKey: ['remediation-job', id], queryFn: () => (id ? getRemediationJob(id) : null), enabled: !!id });
}

export function useRemediationDryRuns(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['remediation-dry-runs', params], queryFn: () => listRemediationDryRuns(params) });
}

export function useRemediationDryRun(id?: string) {
  return useQuery({ queryKey: ['remediation-dry-run', id], queryFn: () => (id ? getRemediationDryRun(id) : null), enabled: !!id });
}

export function useRemediationVerificationResults(params: Record<string, unknown> = {}) {
  return useQuery({ queryKey: ['remediation-verification-results', params], queryFn: () => listRemediationVerificationResults(params) });
}

export function useRemediationVerificationResult(id?: string) {
  return useQuery({ queryKey: ['remediation-verification-result', id], queryFn: () => (id ? getRemediationVerificationResult(id) : null), enabled: !!id });
}
