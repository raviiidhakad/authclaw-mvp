import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '@/lib/api-client';

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
    queryFn: async () => {
      const res = await apiClient.get('/policies', { params: { skip, limit } });
      return Array.isArray(res.data) ? res.data : (res.data?.items ?? []);
    },
  });
}

export function useCreatePolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: any) => {
      const res = await apiClient.post('/policies', data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] });
    },
  });
}

export function useDeletePolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/policies/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] });
    },
  });
}

export function useUpdatePolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, data }: { id: string; data: any }) => {
      const res = await apiClient.patch(`/policies/${id}`, data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] });
    },
  });
}

// ── Policy Violations (dedicated violations endpoint) ──
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
      const params: any = { skip, limit };
      if (status) params.status = status;
      const res = await apiClient.get('/gateway/requests', { params });
      return res.data; // { items, total }
    },
    refetchInterval: 5000,
  });
}

export function useGatewayRequestDetail(id: string | null) {
  return useQuery({
    queryKey: ['gateway-request', id],
    queryFn: async () => {
      if (!id) return null;
      const res = await apiClient.get(`/gateway/requests/${id}`);
      return res.data;
    },
    enabled: !!id,
  });
}

// ── Audit Logs ──
export function useAuditLogs(skip = 0, limit = 50, eventType?: string) {
  return useQuery({
    queryKey: ['audit-logs', skip, limit, eventType],
    queryFn: async () => {
      const params: any = { skip, limit };
      if (eventType) params.event_type = eventType;
      const res = await apiClient.get('/audit/logs', { params });
      return res.data; // { items, total }
    },
  });
}

// ── Compliance ──
export function useComplianceDashboard() {
  return useQuery({
    queryKey: ['compliance-dashboard'],
    queryFn: async () => {
      const res = await apiClient.get('/compliance/dashboard');
      return res.data;
    },
    refetchInterval: 5000,
  });
}

export function useCalculateCompliance() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const res = await apiClient.post('/compliance/scores/calculate');
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-dashboard'] });
      queryClient.invalidateQueries({ queryKey: ['compliance'] });
      queryClient.invalidateQueries({ queryKey: ['compliance-history'] });
    },
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
    queryFn: async () => {
      const res = await apiClient.get('/providers');
      return Array.isArray(res.data) ? res.data : (res.data?.items ?? []);
    },
  });
}

export function useCreateProvider() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: any) => {
      const res = await apiClient.post('/providers', data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['providers'] });
    },
  });
}

export function useDeleteProvider() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/providers/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['providers'] });
    },
  });
}

export function useApiKeys(skip = 0, limit = 50) {
  return useQuery({
    queryKey: ['api-keys', skip, limit],
    queryFn: async () => {
      const res = await apiClient.get('/api-keys', { params: { skip, limit } });
      return res.data; // { items, total }
    },
  });
}

export function useCreateApiKey() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: any) => {
      const res = await apiClient.post('/api-keys', data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] });
    },
  });
}

export function useRevokeApiKey() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await apiClient.delete(`/api-keys/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] });
    },
  });
}
