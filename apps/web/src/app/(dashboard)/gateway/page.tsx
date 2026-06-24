"use client";

import { useState } from 'react';
import Link from 'next/link';
import { Activity, Clock, CheckCircle, XCircle, AlertTriangle, Shield, Server, ArrowRightLeft, ArrowUpRight, Copy, Send, Play, Key, MessageSquare, Zap, Lock, CheckCheck, ChevronDown, ChevronUp, Network } from 'lucide-react';
import { Card, CardContent, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { useGatewayRequests, useGatewayRequestDetail, useGatewayRoutes, useProviders } from '@/hooks/use-data';
import { TableSkeleton } from '@/components/shared/loaders';
import { EmptyState } from '@/components/shared/states';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'sonner';

type GatewayViolation = {
  description?: string;
  message?: string;
  context?: {
    findings?: string[];
    keywords?: string[];
    attempted_model?: string;
  };
};

type GatewayRequest = {
  id: string;
  created_at: string;
  status: string;
  model?: string | null;
  latency_ms?: number | null;
  error_message?: string | null;
};

type GatewayRequestDetail = GatewayRequest & {
  ip_address?: string | null;
  ip_hash?: string | null;
  user_agent_hash?: string | null;
  violations?: GatewayViolation[];
  request_payload?: unknown;
  modified_payload?: unknown;
  response_payload?: unknown;
};

type GatewayRoute = {
  id: string;
  name: string;
  provider_id?: string | null;
  is_default?: boolean;
  is_active?: boolean;
  redaction?: string | null;
};

type Provider = {
  id: string;
  name: string;
  provider_type?: string;
  type?: string;
  is_active?: boolean;
};

type GatewayResult = {
  status: number;
  ok: boolean;
  providerAuthError?: boolean;
  gatewayAuthError?: boolean;
  data: {
    error?: {
      message?: string;
      violations?: string[];
    };
    message?: string;
    choices?: Array<{
      message?: {
        content?: string;
      };
    }>;
    [key: string]: unknown;
  };
  blocked: boolean;
  error: boolean;
};

function safeText(value: unknown) {
  const raw = typeof value === 'string' ? value : JSON.stringify(value ?? '', null, 2);
  return raw
    .replace(/raw_provider_payload/gi, '[redacted-source]')
    .replace(/vault[:/][^\s,"'}]+/gi, '[redacted-vault-ref]')
    .replace(/authclaw\/tenants\/[^\s,"'}]+/gi, '[redacted-vault-ref]')
    .replace(/authorization\s*[:=]\s*bearer\s+[^\s,"'}]+/gi, 'authorization=[redacted]')
    .replace(/(token|secret|password|credential|api[_-]?key)\s*[:=]\s*[^,\s}]+/gi, '$1=[redacted]')
    .replace(/-----BEGIN [^-]+PRIVATE KEY-----[\s\S]*?-----END [^-]+PRIVATE KEY-----/g, '[redacted-private-key]')
    .replace(/gh[pousr]_[a-z0-9_]+/gi, '[redacted-token]')
    .replace(/AKIA[0-9A-Z]{12,}/g, '[redacted-key]');
}

// ─── Status badge ─────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  switch (status?.toLowerCase()) {
    case 'completed':
      return (
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]"></div>
          <span className="text-emerald-500 text-xs font-medium uppercase tracking-wider">Allowed</span>
        </div>
      );
    case 'blocked':
      return (
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]"></div>
          <span className="text-red-500 text-xs font-medium uppercase tracking-wider">Blocked</span>
        </div>
      );
    case 'error':
      return (
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 rounded-full bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.5)]"></div>
          <span className="text-amber-500 text-xs font-medium uppercase tracking-wider">Error</span>
        </div>
      );
    default:
      return (
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 rounded-full bg-neutral-500"></div>
          <span className="text-neutral-500 text-xs font-medium uppercase tracking-wider">{status || 'Unknown'}</span>
        </div>
      );
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
  const { data, isLoading } = useGatewayRequestDetail(requestId);
  const detail = data as GatewayRequestDetail | null | undefined;

  return (
    <Dialog open={!!requestId} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-hidden bg-[#0a0a0a] border-white/10 text-neutral-100 p-0 shadow-2xl flex flex-col">
        <DialogHeader className="p-6 border-b border-white/5 bg-white/[0.02] shrink-0">
          <div className="flex items-center justify-between">
            <DialogTitle className="text-xl font-bold flex items-center gap-2">
              <ArrowRightLeft className="w-5 h-5 text-neutral-400" />
              Gateway Trace Event
            </DialogTitle>
            {detail && <StatusBadge status={detail.status} />}
          </div>
          <DialogDescription className="text-neutral-500 font-mono text-xs mt-1">
            TRACE_ID: {requestId}
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto p-6">
          {isLoading ? (
            <div className="py-24 flex flex-col items-center gap-4">
              <div className="w-8 h-8 rounded-full border-2 border-emerald-500/20 border-t-emerald-500 animate-spin" />
              <span className="text-sm font-medium text-neutral-500 uppercase tracking-wider">Decrypting Trace Data...</span>
            </div>
          ) : !detail ? (
            <EmptyState title="Trace Not Found" description="The requested gateway trace could not be located in the ledger." icon={Activity} />
          ) : (
            <div className="space-y-8">
              {/* Header Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
                  <p className="text-[10px] text-neutral-500 uppercase tracking-wider mb-1">Timestamp</p>
                  <p className="font-mono text-xs text-neutral-300">{new Date(detail.created_at).toLocaleString()}</p>
                </div>
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
                  <p className="text-[10px] text-neutral-500 uppercase tracking-wider mb-1">Latency</p>
                  <p className="font-mono text-xs text-neutral-300">{(detail.latency_ms ?? 0) > 0 ? `${detail.latency_ms}ms` : '—'}</p>
                </div>
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
                  <p className="text-[10px] text-neutral-500 uppercase tracking-wider mb-1">Target Model</p>
                  <p className="font-mono text-xs text-neutral-300">{detail.model || 'Unknown'}</p>
                </div>
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5">
                  <p className="text-[10px] text-neutral-500 uppercase tracking-wider mb-1">Network Metadata</p>
                  <p className="font-mono text-xs text-neutral-300">{detail.ip_hash || detail.user_agent_hash || 'redacted'}</p>
                </div>
              </div>

              {/* Status + Violations */}
              {detail.violations && detail.violations.length > 0 && (
                <div className={`p-4 rounded-xl border ${detail.status === 'blocked' ? 'bg-red-500/5 border-red-500/20' : 'bg-amber-500/5 border-amber-500/20'}`}>
                  <p className={`text-xs font-semibold uppercase tracking-wider mb-3 flex items-center gap-2 ${detail.status === 'blocked' ? 'text-red-400' : 'text-amber-400'}`}>
                    <Shield className="w-3.5 h-3.5" /> {detail.status === 'blocked' ? 'Policy Violations (Blocked)' : 'Policy Interventions'}
                  </p>
                  <div className="space-y-2">
                    {detail.violations.map((v, i) => {
                      const isBlocked = detail.status === 'blocked';
                      return (
                        <div key={i} className={`flex flex-col gap-1.5 text-xs text-neutral-300 bg-black/20 p-3 rounded-lg border ${isBlocked ? 'border-red-500/10' : 'border-amber-500/10'}`}>
                          <div className="flex items-start gap-3">
                            {isBlocked ? <XCircle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" /> : <AlertTriangle className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />}
                            <div className="flex-1">
                              <span className={`font-medium ${isBlocked ? 'text-red-200' : 'text-amber-200'}`}>
                                {v.description || v.message || 'Policy Violation Detected'}
                              </span>
                              {v.context && Object.keys(v.context).length > 0 && (
                                <div className="mt-2 flex flex-wrap gap-2">
                                  {v.context.findings && (
                                    <span className={`text-[10px] text-neutral-400 px-2 py-1 rounded-md border ${isBlocked ? 'bg-red-500/10 border-red-500/20' : 'bg-amber-500/10 border-amber-500/20'}`}>
                                      Detected Data: <span className={`${isBlocked ? 'text-red-300' : 'text-amber-300'} font-mono font-medium`}>{safeText(v.context.findings.join(', '))}</span>
                                    </span>
                                  )}
                                  {v.context.keywords && (
                                    <span className={`text-[10px] text-neutral-400 px-2 py-1 rounded-md border ${isBlocked ? 'bg-red-500/10 border-red-500/20' : 'bg-amber-500/10 border-amber-500/20'}`}>
                                      Blocked Keywords: <span className={`${isBlocked ? 'text-red-300' : 'text-amber-300'} font-mono font-medium`}>{safeText(v.context.keywords.join(', '))}</span>
                                    </span>
                                  )}
                                  {v.context.attempted_model && (
                                    <span className={`text-[10px] text-neutral-400 px-2 py-1 rounded-md border ${isBlocked ? 'bg-red-500/10 border-red-500/20' : 'bg-amber-500/10 border-amber-500/20'}`}>
                                      Target Model: <span className={`${isBlocked ? 'text-red-300' : 'text-amber-300'} font-mono font-medium`}>{v.context.attempted_model}</span>
                                    </span>
                                  )}
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Request / Response payloads */}
              {[
                { label: 'Original Request', content: detail.request_payload },
                { label: 'Modified Request (Post-Redaction)', content: detail.modified_payload },
                { label: 'Provider Response', content: detail.response_payload },
              ].filter(s => s.content).map(({ label, content }) => (
                <div key={label}>
                  <p className="text-xs text-neutral-500 uppercase tracking-wider mb-2 font-medium">{label} Sanitized Preview</p>
                  <pre className="text-[11px] font-mono text-neutral-300 bg-white/[0.02] border border-white/5 rounded-xl p-4 overflow-auto max-h-48 whitespace-pre-wrap">
                    {safeText(content)}
                  </pre>
                </div>
              ))}
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Gateway Playground ────────────────────────────────────────────────────────

const QUICK_TESTS = [
  { label: 'Normal request', prompt: 'Explain machine learning in simple terms.' },
  { label: 'PII email pattern', prompt: 'A demo user entered person@example.test and it should be classified and protected.' },
  { label: 'Credential-like pattern', prompt: 'A demo credential marker token=demo-token-redacted should be blocked or redacted.' },
  { label: 'Phone pattern', prompt: 'A demo support caller entered +1 202-555-0100 and it should be classified and protected.' },
  { label: 'Payment-card pattern', prompt: 'A demo payment-card test value 4111 1111 1111 1111 should be classified and protected.' },
  { label: 'Content filter', prompt: 'Explain why bypassing security controls is unsafe.' },
];

function GatewayPlayground({ onRequestSent }: { onRequestSent: () => void }) {
  const [apiKey, setApiKey] = useState('');
  const [prompt, setPrompt] = useState('');
  const [model, setModel] = useState('gpt-3.5-turbo');
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<GatewayResult | null>(null);
  const [isExpanded, setIsExpanded] = useState(true);
  const [copied, setCopied] = useState(false);

  const sendRequest = async () => {
    if (!apiKey.trim()) {
      toast.error('API Key required', { description: 'Please enter your AuthClaw API key from Settings → API Keys.' });
      return;
    }
    if (!prompt.trim()) {
      toast.error('Message required', { description: 'Please enter a message to send through the gateway.' });
      return;
    }

    setIsLoading(true);
    setResult(null);

    const apiBase = process.env.NEXT_PUBLIC_API_URL?.replace('/api/v1', '') || 'http://localhost:8000';

    try {
      const resp = await fetch(`${apiBase}/api/v1/gateway/chat/completions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey.trim()}`,
          'X-API-Key': apiKey.trim(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: model,
          messages: [{ role: 'user', content: prompt }],
        }),
      });

      const data = await resp.json();
      const topLevelDetail = typeof data?.detail === 'string' ? data.detail : '';
      const nestedMessage = typeof data?.error?.message === 'string' ? data.error.message : '';
      const nestedType = typeof data?.error?.type === 'string' ? data.error.type : '';
      const providerAuthError =
        resp.status === 401 &&
        (nestedType.includes('auth') || /invalid api key|authentication|unauthorized/i.test(nestedMessage));
      const gatewayAuthError =
        resp.status === 401 &&
        !data?.error &&
        /invalid api key|gateway api key|authorization/i.test(topLevelDetail);

      setResult({
        status: resp.status,
        ok: resp.ok,
        data,
        blocked: resp.status === 403,
        error: !resp.ok && resp.status !== 403,
        providerAuthError,
        gatewayAuthError,
      });

      if (resp.status === 403) {
        toast.error('🚫 Request BLOCKED by Policy', { description: data?.error?.violations?.[0] || 'Policy violation detected.' });
      } else if (gatewayAuthError) {
        toast.error('AuthClaw API key rejected', { description: 'Paste the full ac_ key shown once in Settings, not only the prefix.' });
      } else if (providerAuthError) {
        toast.warning('Provider credential rejected', { description: 'AuthClaw accepted the gateway key, but the selected model provider returned 401.' });
      } else if (!resp.ok) {
        toast.warning('⚠️ Gateway Error', { description: data?.error?.message || 'An error occurred.' });
      } else {
        toast.success('✅ Request Allowed & Forwarded', { description: `Model: ${model}` });
      }

      // Trigger parent to refresh the log
      setTimeout(onRequestSent, 1000);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Network request failed.';
      setResult({ status: 0, ok: false, blocked: false, error: true, data: { message } });
      toast.error('Network Error', { description: message });
    } finally {
      setIsLoading(false);
    }
  };

  const copyApiKeyHelp = () => {
    navigator.clipboard.writeText('Settings → API Keys → Create New Key → Copy the full key');
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Card className="glass-card overflow-hidden">
      {/* Header */}
      <div
        className="p-4 border-b border-white/5 bg-black/20 flex items-center justify-between cursor-pointer"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <CardTitle className="text-neutral-100 text-base flex items-center gap-2">
          <Play className="w-4 h-4 text-violet-400" />
          Gateway Playground
          <span className="text-[10px] font-normal text-neutral-500 bg-white/5 border border-white/10 rounded-full px-2 py-0.5 ml-1">LIVE TEST</span>
        </CardTitle>
        <div className="flex items-center gap-3">
          <span className="text-xs text-neutral-500 hidden md:block">Test policy enforcement in real-time</span>
          {isExpanded ? <ChevronUp className="w-4 h-4 text-neutral-500" /> : <ChevronDown className="w-4 h-4 text-neutral-500" />}
        </div>
      </div>

      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
          >
            <div className="p-5 space-y-5">
              {/* How to get API Key notice */}
              <div className="flex items-start gap-3 p-3 rounded-lg bg-violet-500/5 border border-violet-500/20">
                <Key className="w-4 h-4 text-violet-400 shrink-0 mt-0.5" />
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-violet-300 font-medium">API Key Required</p>
                  <p className="text-[11px] text-neutral-400 mt-0.5">
                    Get your API key from <span className="text-violet-400 font-mono">Settings → API Keys</span>. The key starts with <span className="font-mono text-violet-400">ac_</span>
                  </p>
                </div>
                <button
                  onClick={copyApiKeyHelp}
                  className="shrink-0 p-1.5 rounded-lg bg-white/5 hover:bg-white/10 transition-colors text-neutral-400 hover:text-neutral-200"
                  title="Copy instructions"
                >
                  {copied ? <CheckCheck className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                {/* Left: Input */}
                <div className="space-y-4">
                  {/* API Key input */}
                  <div>
                    <label className="text-[11px] text-neutral-400 uppercase tracking-wider font-medium mb-1.5 flex items-center gap-1.5">
                      <Key className="w-3 h-3" /> AuthClaw API Key
                    </label>
                    <input
                      type="password"
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                      placeholder="ac_xxxxxxxxxxxxxxxxx"
                      className="w-full bg-black/30 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-neutral-200 placeholder-neutral-600 focus:outline-none focus:border-violet-500/50 focus:ring-1 focus:ring-violet-500/20 transition-all"
                    />
                  </div>

                  {/* Model */}
                  <div>
                    <label className="text-[11px] text-neutral-400 uppercase tracking-wider font-medium mb-1.5 flex items-center gap-1.5">
                      <Zap className="w-3 h-3" /> Target Model
                    </label>
                    <select
                      value={model}
                      onChange={(e) => setModel(e.target.value)}
                      className="w-full bg-black/30 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-neutral-200 focus:outline-none focus:border-violet-500/50 focus:ring-1 focus:ring-violet-500/20 transition-all"
                    >
                      <option value="gpt-3.5-turbo">gpt-3.5-turbo</option>
                      <option value="gpt-4">gpt-4</option>
                      <option value="llama-3.3-70b-versatile">llama-3.3-70b-versatile (Groq)</option>
                      <option value="llama3-8b-8192">llama3-8b-8192 (Groq)</option>
                      <option value="mixtral-8x7b-32768">mixtral-8x7b-32768 (Groq)</option>
                    </select>
                  </div>

                  {/* Quick test buttons */}
                  <div>
                    <label className="text-[11px] text-neutral-400 uppercase tracking-wider font-medium mb-2 flex items-center gap-1.5">
                      <Shield className="w-3 h-3" /> Quick Policy Tests
                    </label>
                    <div className="grid grid-cols-1 gap-1.5">
                      {QUICK_TESTS.map((t) => (
                        <button
                          key={t.label}
                          onClick={() => setPrompt(t.prompt)}
                          className="text-left px-3 py-2 rounded-lg bg-white/[0.02] hover:bg-white/[0.05] border border-white/5 hover:border-white/10 transition-all text-[11px] text-neutral-400 hover:text-neutral-200"
                        >
                          {t.label}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Right: Message + Response */}
                <div className="space-y-4">
                  {/* Message textarea */}
                  <div>
                    <label className="text-[11px] text-neutral-400 uppercase tracking-wider font-medium mb-1.5 flex items-center gap-1.5">
                      <MessageSquare className="w-3 h-3" /> Your Message
                    </label>
                    <textarea
                      value={prompt}
                      onChange={(e) => setPrompt(e.target.value)}
                      placeholder="Type your prompt here... try including a password, email, or phone number to test policy enforcement."
                      rows={6}
                      className="w-full bg-black/30 border border-white/10 rounded-lg px-3 py-2.5 text-xs text-neutral-200 placeholder-neutral-600 focus:outline-none focus:border-violet-500/50 focus:ring-1 focus:ring-violet-500/20 transition-all resize-none"
                    />
                    <button
                      onClick={sendRequest}
                      disabled={isLoading}
                      className="mt-2 w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-violet-600 hover:bg-violet-500 disabled:bg-violet-900 disabled:cursor-not-allowed text-white text-sm font-medium transition-all"
                    >
                      {isLoading ? (
                        <>
                          <div className="w-4 h-4 rounded-full border-2 border-white/20 border-t-white animate-spin" />
                          Sending through gateway...
                        </>
                      ) : (
                        <>
                          <Send className="w-4 h-4" />
                          Send Through Gateway
                        </>
                      )}
                    </button>
                  </div>

                  {/* Response */}
                  {result && (
                    <motion.div
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className={`p-4 rounded-xl border ${
                        result.blocked
                          ? 'bg-red-500/5 border-red-500/20'
                          : result.error
                          ? 'bg-amber-500/5 border-amber-500/20'
                          : 'bg-emerald-500/5 border-emerald-500/20'
                      }`}
                    >
                      {/* Status header */}
                      <div className="flex items-center gap-2 mb-3">
                        {result.blocked ? (
                          <>
                            <div className="w-2 h-2 rounded-full bg-red-500"></div>
                            <span className="text-xs font-bold text-red-400 uppercase tracking-wider">BLOCKED by Policy</span>
                            <span className="text-xs text-neutral-500 ml-auto font-mono">HTTP {result.status}</span>
                          </>
                        ) : result.error ? (
                          <>
                            <div className="w-2 h-2 rounded-full bg-amber-500"></div>
                            <span className="text-xs font-bold text-amber-400 uppercase tracking-wider">
                              {result.gatewayAuthError ? 'AuthClaw Key Error' : result.providerAuthError ? 'Provider Credential Error' : 'Gateway Error'}
                            </span>
                            <span className="text-xs text-neutral-500 ml-auto font-mono">HTTP {result.status}</span>
                          </>
                        ) : (
                          <>
                            <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]"></div>
                            <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider">Request ALLOWED</span>
                            <span className="text-xs text-neutral-500 ml-auto font-mono">HTTP {result.status}</span>
                          </>
                        )}
                      </div>

                      {/* Violations */}
                      {result.blocked && result.data?.error?.violations && (
                        <div className="mb-3 space-y-1">
                          {result.data.error.violations.map((v: string, i: number) => (
                            <div key={i} className="flex items-start gap-2 text-[11px] text-red-300">
                              <Lock className="w-3 h-3 shrink-0 mt-0.5" />
                              <span>{v}</span>
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Response content */}
                      {!result.blocked && !result.error && (
                        <div className="text-xs text-neutral-300 bg-black/20 rounded-lg p-3 font-mono whitespace-pre-wrap max-h-40 overflow-y-auto">
                          {result.data?.choices?.[0]?.message?.content || JSON.stringify(result.data, null, 2)}
                        </div>
                      )}

                      {result.error && (
                        <div className="text-xs text-amber-300 bg-black/20 rounded-lg p-3 font-mono">
                          {result.gatewayAuthError
                            ? 'The AuthClaw gateway key was rejected. Create a new key in Settings and copy the full ac_ value shown once.'
                            : result.providerAuthError
                            ? 'AuthClaw accepted this gateway key, but the upstream provider credential for the selected model is invalid or missing. Update the provider key in Settings before forwarding non-blocked requests.'
                            : result.data?.error?.message || result.data?.message || JSON.stringify(result.data, null, 2)}
                        </div>
                      )}

                      <p className="text-[10px] text-neutral-600 mt-2">
                        {result.blocked
                          ? '↳ Request was intercepted by the policy engine and never reached the AI provider.'
                          : result.error
                          ? '↳ Request passed policy checks but encountered a provider/config error.'
                          : '↳ Request passed all policy checks and was forwarded to the AI provider.'}
                      </p>
                    </motion.div>
                  )}
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </Card>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function GatewayPage() {
  const { data, isLoading, refetch } = useGatewayRequests(0, 100);
  const { data: routesData, isLoading: routesLoading } = useGatewayRoutes();
  const { data: providersData = [] } = useProviders();
  const logs = (data?.items || []) as GatewayRequest[];
  const routes = ((routesData as GatewayRoute[] | undefined) || []).slice(0, 5);
  const providers = (providersData as Provider[] | undefined) || [];
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const total     = data?.total || 0;
  const allowed   = logs.filter((l) => l.status === 'completed').length;
  const blocked   = logs.filter((l) => l.status === 'blocked').length;
  const errors    = logs.filter((l) => l.status === 'error').length;

  return (
    <div className="space-y-6 max-w-[1600px] mx-auto pb-10">
      <div className="flex flex-col md:flex-row items-start md:items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-neutral-100 font-sans">Gateway Explorer</h2>
          <p className="text-sm text-neutral-400 mt-1">Real-time observability of all AI model traffic and guardrail enforcement.</p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid gap-4 grid-cols-2 lg:grid-cols-4">
        {[
          { label: 'Total Requests', value: total,   icon: Server,        color: 'text-blue-400' },
          { label: 'Allowed',        value: allowed,  icon: CheckCircle,   color: 'text-emerald-400' },
          { label: 'Blocked',        value: blocked,  icon: Shield,        color: 'text-red-400' },
          { label: 'Errors',         value: errors,   icon: AlertTriangle, color: 'text-amber-400' },
        ].map(({ label, value, icon: Icon, color }, i) => (
          <motion.div key={label} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.1 }}>
            <Card className="glass-card">
              <CardContent className="p-4 flex items-center justify-between">
                <div>
                  <p className="text-xs text-neutral-400 font-medium uppercase tracking-wider">{label}</p>
                  <div className="text-2xl font-bold text-neutral-100 mt-1">{value}</div>
                </div>
                <div className={`p-3 rounded-full bg-white/5 border border-white/5 ${color}`}>
                  <Icon className="w-5 h-5" />
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      <Card className="glass-card overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20 flex items-center justify-between gap-4">
          <CardTitle className="text-neutral-100 text-base flex items-center gap-2">
            <Network className="w-4 h-4 text-blue-400" />
            Route and Provider Configuration
          </CardTitle>
          <Link href="/gateway-routes" className="text-xs text-blue-300 hover:text-blue-200">
            Manage routes
          </Link>
        </div>
        <CardContent className="p-0">
          {routesLoading ? (
            <div className="p-4"><TableSkeleton columns={5} rows={4} /></div>
          ) : routes.length === 0 ? (
            <EmptyState
              title="No gateway routes configured"
              description="Create routes before forwarding tenant traffic to model providers. Redaction modes supported by the console are mask, hash, and synthetic where the backend route supports it."
              icon={Network}
            />
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-neutral-900/80 border-b border-white/5">
                <tr>
                  <th className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">Route</th>
                  <th className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">Provider</th>
                  <th className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">Redaction Mode</th>
                  <th className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {routes.map((route) => {
                  const provider = providers.find((item) => item.id === route.provider_id);
                  return (
                    <tr key={route.id} className="hover:bg-white/[0.02]">
                      <td className="p-4 text-neutral-200">
                        <div className="font-medium">{route.name}</div>
                        {route.is_default && <div className="text-xs text-blue-300 mt-1">Default route</div>}
                      </td>
                      <td className="p-4 text-neutral-300">{provider ? `${provider.name} (${provider.provider_type || provider.type || 'provider'})` : 'Needs provider mapping'}</td>
                      <td className="p-4">
                        <Badge variant="outline" className="bg-purple-500/10 text-purple-300 border-purple-500/20 text-[10px] uppercase tracking-wider">
                          {route.redaction || 'not set'}
                        </Badge>
                      </td>
                      <td className="p-4">
                        <Badge variant="outline" className={route.is_active === false ? 'bg-neutral-500/10 text-neutral-400 border-neutral-700' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'}>
                          {route.is_active === false ? 'Disabled' : 'Active'}
                        </Badge>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      {/* Playground */}
      <GatewayPlayground onRequestSent={() => refetch()} />

      {/* Request Log */}
      <Card className="glass-card flex flex-col min-h-[600px] overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-black/20 flex items-center justify-between">
          <CardTitle className="text-neutral-100 text-base flex items-center gap-2">
            <ArrowRightLeft className="w-4 h-4 text-neutral-500" />
            Live Trace Log
          </CardTitle>
          <div className="flex items-center gap-2 text-xs text-neutral-500">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            Streaming
          </div>
        </div>
        <div className="flex-1 overflow-auto">
          {isLoading ? (
            <div className="p-4"><TableSkeleton columns={5} rows={10} /></div>
          ) : logs.length === 0 ? (
            <EmptyState 
              title="No Traffic Detected" 
              description="Use the Gateway Playground above to send a test request and see traces here."
              icon={Activity}
            />
          ) : (
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-neutral-900/90 backdrop-blur-md z-10 border-b border-white/5">
                <tr>
                  <th className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">Trace Time</th>
                  <th className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">Model Target</th>
                  <th className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">Enforcement</th>
                  <th className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">Latency</th>
                  <th className="text-left p-4 text-xs font-medium text-neutral-400 uppercase tracking-wider">Context</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {logs.map((log) => (
                  <tr
                    key={log.id}
                    className="hover:bg-white/[0.02] cursor-pointer transition-colors group"
                    onClick={() => setSelectedId(log.id)}
                  >
                    <td className="p-4 text-neutral-400 whitespace-nowrap">
                      <div className="flex items-center gap-2 font-mono text-[11px]">
                        <Clock className="w-3.5 h-3.5 text-neutral-500" />
                        {new Date(log.created_at).toLocaleString()}
                      </div>
                    </td>
                    <td className="p-4">
                      <Badge variant="outline" className="bg-black/20 text-neutral-300 font-mono text-[10px] border-white/10 uppercase">
                        {log.model || 'UNKNOWN_MODEL'}
                      </Badge>
                    </td>
                    <td className="p-4"><StatusBadge status={log.status} /></td>
                    <td className="p-4 text-neutral-400 font-mono text-xs">
                      {log.latency_ms ? `${log.latency_ms}ms` : '—'}
                    </td>
                    <td className="p-4 text-neutral-500 text-xs flex items-center justify-between group-hover:text-neutral-300 transition-colors">
                      <span className="truncate max-w-[200px]">
                        {log.error_message ? <span className="text-red-400/80">{log.error_message}</span> : log.status === 'completed' ? 'Forwarded to upstream' : 'Blocked by policy layer'}
                      </span>
                      <ArrowUpRight className="w-4 h-4 opacity-0 group-hover:opacity-100 transition-opacity" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </Card>

      <RequestDetailDrawer requestId={selectedId} onClose={() => setSelectedId(null)} />
    </div>
  );
}
