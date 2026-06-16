"use client";

import { useState } from 'react';
import { Activity, Clock, CheckCircle, XCircle, AlertTriangle, Shield, RefreshCw } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { useGatewayRequests, useGatewayRequestDetail } from '@/hooks/use-data';

// ─── Status badge ─────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  switch (status?.toLowerCase()) {
    case 'completed':
      return <Badge className="bg-green-500/10 text-green-400 border-green-500/20">Allowed</Badge>;
    case 'blocked':
      return <Badge className="bg-red-500/10 text-red-400 border-red-500/20">Blocked</Badge>;
    case 'error':
      return <Badge className="bg-amber-500/10 text-amber-400 border-amber-500/20">Error</Badge>;
    default:
      return <Badge className="bg-neutral-500/10 text-neutral-400 border-neutral-500/20">{status || 'Unknown'}</Badge>;
  }
}

// ─── Request Detail Drawer ────────────────────────────────────────────────────

function RequestDetailDrawer({
  requestId,
  onClose,
}: {
  requestId: string | null;
  onClose: () => void;
}) {
  const { data: detail, isLoading } = useGatewayRequestDetail(requestId);

  return (
    <Dialog open={!!requestId} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto bg-neutral-900 border-neutral-800 text-neutral-100">
        <DialogHeader>
          <DialogTitle className="text-xl">Request Details</DialogTitle>
        </DialogHeader>

        {isLoading ? (
          <div className="py-16 text-center text-neutral-500 flex flex-col items-center gap-3">
            <RefreshCw className="w-6 h-6 animate-spin" />
            Loading details…
          </div>
        ) : !detail ? (
          <div className="py-16 text-center text-neutral-500">Details not found.</div>
        ) : (
          <div className="space-y-5 mt-2">
            {/* Header row */}
            <div className="flex flex-wrap items-center gap-3">
              <StatusBadge status={detail.status} />
              <span className="text-sm text-neutral-400">
                {new Date(detail.created_at).toLocaleString()}
              </span>
              {detail.latency_ms > 0 && (
                <span className="text-sm text-neutral-500">
                  Latency: <span className="text-neutral-300 font-mono">{detail.latency_ms}ms</span>
                </span>
              )}
              {detail.model && (
                <span className="text-sm text-neutral-500">
                  Model: <span className="text-neutral-300 font-mono">{detail.model}</span>
                </span>
              )}
            </div>

            {/* Provider error banner */}
            {detail.error_message && (
              <div className="p-4 bg-red-950/40 border border-red-500/30 rounded-lg space-y-1">
                <div className="flex items-center gap-2 text-red-400 font-semibold text-sm">
                  <XCircle className="w-4 h-4" />
                  Provider Error
                  {detail.provider_status_code && (
                    <span className="ml-auto font-mono text-xs bg-red-500/20 px-2 py-0.5 rounded">
                      HTTP {detail.provider_status_code}
                    </span>
                  )}
                </div>
                <p className="text-red-300 text-sm font-mono">{detail.error_message}</p>
                {(detail.error_type || detail.error_code) && (
                  <p className="text-red-500/70 text-xs">
                    {detail.error_type && `type: ${detail.error_type}`}
                    {detail.error_type && detail.error_code && ' · '}
                    {detail.error_code && `code: ${detail.error_code}`}
                  </p>
                )}
              </div>
            )}

            {/* Policy violations */}
            {detail.violations && detail.violations.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-sm font-semibold text-neutral-300 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-red-400" />
                  Policy Violations ({detail.violations.length})
                </h4>
                {detail.violations.map((v: any) => (
                  <div key={v.id} className="p-3 bg-red-950/30 border border-red-500/20 rounded-lg text-sm space-y-1">
                    <p className="text-red-300 font-medium">{v.description}</p>
                    <div className="flex gap-3 text-xs text-neutral-500">
                      <span>Severity: <span className="text-neutral-400">{v.severity}</span></span>
                      <span>Resolution: <span className="text-neutral-400">{v.resolution}</span></span>
                    </div>
                    {v.context && Object.keys(v.context).length > 0 && (
                      <pre className="text-xs text-neutral-500 mt-1 bg-neutral-950 rounded p-2 overflow-x-auto">
                        {JSON.stringify(v.context, null, 2)}
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* Original prompt */}
            <div className="space-y-1">
              <h4 className="text-sm font-semibold text-neutral-300">Original Prompt</h4>
              <div className="p-3 bg-neutral-950 border border-neutral-800 rounded-lg">
                <pre className="text-xs text-neutral-300 whitespace-pre-wrap font-mono">
                  {detail.prompt_original || '(empty)'}
                </pre>
              </div>
            </div>

            {/* Redacted prompt */}
            {detail.prompt_redacted && (
              <div className="space-y-1">
                <h4 className="text-sm font-semibold text-amber-400 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" />
                  Redacted Prompt
                </h4>
                <div className="p-3 bg-amber-950/20 border border-amber-500/20 rounded-lg">
                  <pre className="text-xs text-amber-300/80 whitespace-pre-wrap font-mono">
                    {detail.prompt_redacted}
                  </pre>
                </div>
              </div>
            )}

            {/* Provider response */}
            <div className="space-y-1">
              <h4 className="text-sm font-semibold text-neutral-300">Provider Response</h4>
              <div className="p-3 bg-neutral-950 border border-neutral-800 rounded-lg">
                <pre className="text-xs text-neutral-300 whitespace-pre-wrap font-mono">
                  {detail.response?.response_original || '(no response body)'}
                </pre>
              </div>
            </div>

            {/* Token usage */}
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 bg-neutral-800/40 rounded-lg border border-neutral-800">
                <p className="text-xs text-neutral-500 mb-1">Prompt Tokens</p>
                <p className="font-mono text-base text-neutral-200">{detail.token_count_prompt ?? 0}</p>
              </div>
              <div className="p-3 bg-neutral-800/40 rounded-lg border border-neutral-800">
                <p className="text-xs text-neutral-500 mb-1">Completion Tokens</p>
                <p className="font-mono text-base text-neutral-200">{detail.response?.token_count_completion ?? 0}</p>
              </div>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function GatewayPage() {
  const { data, isLoading } = useGatewayRequests(0, 100);
  const logs: any[] = data?.items || [];
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const total     = data?.total || 0;
  const allowed   = logs.filter((l) => l.status === 'completed').length;
  const blocked   = logs.filter((l) => l.status === 'blocked').length;
  const errors    = logs.filter((l) => l.status === 'error').length;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Gateway Explorer</h2>
        <p className="text-neutral-400">Monitor all AI traffic passing through the AuthClaw gateway.</p>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        {[
          { label: 'Total Requests', value: total,   icon: Activity,      color: 'text-blue-500' },
          { label: 'Allowed',        value: allowed,  icon: CheckCircle,   color: 'text-green-500' },
          { label: 'Blocked',        value: blocked,  icon: XCircle,       color: 'text-red-500' },
          { label: 'Errors',         value: errors,   icon: AlertTriangle, color: 'text-amber-500' },
        ].map(({ label, value, icon: Icon, color }) => (
          <Card key={label} className="bg-neutral-900 border-neutral-800">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-neutral-400">{label}</CardTitle>
              <Icon className={`h-4 w-4 ${color}`} />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-neutral-100">{value}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Request Log */}
      <Card className="bg-neutral-900 border-neutral-800">
        <CardHeader>
          <CardTitle className="text-neutral-100">Request Log</CardTitle>
          <p className="text-xs text-neutral-500">Click any row for full details.</p>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-12 text-neutral-500 gap-3">
              <RefreshCw className="w-5 h-5 animate-spin" /> Loading…
            </div>
          ) : logs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-neutral-500">
              <Activity className="w-10 h-10 mb-3 opacity-40" />
              <p>No gateway traffic yet.</p>
              <p className="text-xs mt-1">Send a request through the gateway to see it here.</p>
            </div>
          ) : (
            <div className="rounded-md border border-neutral-800 overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-neutral-800 bg-neutral-800/50">
                    <th className="text-left p-3 text-neutral-400 font-medium">Timestamp</th>
                    <th className="text-left p-3 text-neutral-400 font-medium">Model</th>
                    <th className="text-left p-3 text-neutral-400 font-medium">Status</th>
                    <th className="text-left p-3 text-neutral-400 font-medium">Latency</th>
                    <th className="text-left p-3 text-neutral-400 font-medium">Details</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map((log) => (
                    <tr
                      key={log.id}
                      className="border-b border-neutral-800 last:border-0 hover:bg-neutral-800/60 cursor-pointer transition-colors"
                      onClick={() => setSelectedId(log.id)}
                    >
                      <td className="p-3 text-neutral-400 text-xs">
                        <div className="flex items-center gap-2">
                          <Clock className="w-3 h-3 flex-shrink-0" />
                          {new Date(log.created_at).toLocaleString()}
                        </div>
                      </td>
                      <td className="p-3 text-neutral-200 font-mono text-xs">{log.model || '—'}</td>
                      <td className="p-3"><StatusBadge status={log.status} /></td>
                      <td className="p-3 text-neutral-400 text-xs font-mono">
                        {log.latency_ms ? `${log.latency_ms}ms` : '—'}
                      </td>
                      <td className="p-3 text-neutral-500 text-xs max-w-xs truncate">
                        {log.error_message
                          ? <span className="text-red-400/80">{log.error_message}</span>
                          : log.status === 'completed'
                          ? <span className="text-green-400/70">OK</span>
                          : <span className="text-neutral-600">—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <RequestDetailDrawer requestId={selectedId} onClose={() => setSelectedId(null)} />
    </div>
  );
}
