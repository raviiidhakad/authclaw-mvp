"use client";

import { useState } from 'react';
import { Plus, ShieldCheck, Trash2, Edit, ChevronRight } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { usePolicies, useCreatePolicy, useDeletePolicy, useUpdatePolicy } from '@/hooks/use-data';
import { PolicyForm } from '@/components/shared/PolicyForm';
import { toast } from 'sonner';

interface PolicyRule {
  id: string;
  rule_type: string;
  action: string;
  message?: string;
  is_active: boolean;
  conditions: Record<string, unknown>;
  created_at: string;
}

interface Policy {
  id: string;
  name: string;
  description?: string;
  is_active: boolean;
  priority: number;
  created_at: string;
  updated_at: string;
  rules: PolicyRule[];
}

const RULE_TYPE_COLORS: Record<string, string> = {
  pii_block: 'bg-red-500/10 text-red-400 border-red-500/20',
  pii_redact: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  content_filter: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  rate_limit: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  model_restrict: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  custom: 'bg-neutral-500/10 text-neutral-400 border-neutral-500/20',
};

const ACTION_COLORS: Record<string, string> = {
  block: 'text-red-400',
  warn: 'text-yellow-400',
  allow: 'text-green-400',
};

function RuleSummaryBadges({ rules }: { rules: PolicyRule[] }) {
  if (!rules?.length) {
    return <span className="text-xs text-neutral-600 italic">No rules</span>;
  }
  return (
    <div className="flex flex-wrap gap-1 mt-1">
      {rules.map((rule) => (
        <span
          key={rule.id}
          className={`inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded border font-medium ${RULE_TYPE_COLORS[rule.rule_type] ?? RULE_TYPE_COLORS.custom}`}
        >
          <span className={`font-bold ${ACTION_COLORS[rule.action] ?? ''}`}>
            {rule.action.toUpperCase()}
          </span>
          {rule.rule_type.replace('_', ' ')}
        </span>
      ))}
    </div>
  );
}

// ─── Modal wrapper ─────────────────────────────────────────────────────────────

interface ModalProps {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}

function Modal({ title, onClose, children }: ModalProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-neutral-900 border border-neutral-800 rounded-xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-neutral-800 shrink-0">
          <h2 className="text-base font-semibold text-neutral-100">{title}</h2>
          <button
            onClick={onClose}
            className="text-neutral-500 hover:text-neutral-200 text-xl leading-none"
          >
            ×
          </button>
        </div>
        {/* Body */}
        <div className="overflow-y-auto flex-1 px-6 py-4">{children}</div>
      </div>
    </div>
  );
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function PoliciesPage() {
  const { data: policies = [], isLoading: loading } = usePolicies();
  const createMutation = useCreatePolicy();
  const updateMutation = useUpdatePolicy();
  const deleteMutation = useDeletePolicy();

  const [showCreate, setShowCreate] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // ─── Handlers ───────────────────────────────────────────────────────────────

  const handleCreate = async (payload: any) => {
    try {
      await createMutation.mutateAsync(payload);
      toast.success(`Policy "${payload.name}" created with ${payload.rules.length} rule(s).`);
      setShowCreate(false);
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to create policy');
    }
  };

  const handleEdit = async (payload: any) => {
    if (!editingPolicy) return;
    try {
      await updateMutation.mutateAsync({ id: editingPolicy.id, data: payload });
      toast.success(`Policy "${payload.name}" updated.`);
      setEditingPolicy(null);
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to update policy');
    }
  };

  const handleToggleActive = async (policy: Policy) => {
    try {
      await updateMutation.mutateAsync({
        id: policy.id,
        data: { is_active: !policy.is_active },
      });
      toast.success(`Policy ${policy.is_active ? 'disabled' : 'enabled'}`);
    } catch {
      toast.error('Failed to update policy');
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (!window.confirm(`Delete policy "${name}"? This cannot be undone.`)) return;
    try {
      await deleteMutation.mutateAsync(id);
      toast.success('Policy deleted');
      if (expandedId === id) setExpandedId(null);
    } catch {
      toast.error('Failed to delete policy');
    }
  };

  // ─── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Policy Management</h2>
          <p className="text-neutral-400">Define and manage security policies for AI traffic.</p>
        </div>
        <Button
          onClick={() => setShowCreate(true)}
          className="bg-blue-600 hover:bg-blue-700"
          disabled={createMutation.isPending}
        >
          <Plus className="w-4 h-4 mr-2" />
          Create Policy
        </Button>
      </div>

      {/* Policy list */}
      {loading ? (
        <div className="py-12 text-center text-neutral-500">Loading policies…</div>
      ) : policies.length === 0 ? (
        <Card className="bg-neutral-900 border-neutral-800">
          <CardContent className="flex flex-col items-center justify-center py-16 text-neutral-500">
            <ShieldCheck className="w-12 h-12 mb-3 opacity-30" />
            <p className="font-medium">No policies defined yet.</p>
            <p className="text-xs mt-1">Create your first policy to start protecting AI traffic.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-3">
          {(policies as Policy[]).map((policy) => {
            const isExpanded = expandedId === policy.id;
            return (
              <Card
                key={policy.id}
                className={`bg-neutral-900 border transition-colors ${
                  isExpanded ? 'border-blue-500/40' : 'border-neutral-800'
                }`}
              >
                <CardContent className="p-0">
                  {/* Policy row */}
                  <div className="flex items-center justify-between px-5 py-4">
                    <div className="flex items-center gap-4 min-w-0">
                      <div
                        className={`shrink-0 w-9 h-9 rounded-lg flex items-center justify-center ${
                          policy.is_active ? 'bg-blue-600/10' : 'bg-neutral-800'
                        }`}
                      >
                        <ShieldCheck
                          className={`w-4 h-4 ${
                            policy.is_active ? 'text-blue-400' : 'text-neutral-500'
                          }`}
                        />
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <h3 className="font-semibold text-neutral-100 truncate">
                            {policy.name}
                          </h3>
                          <Badge
                            className={
                              policy.is_active
                                ? 'bg-green-500/10 text-green-400 border-green-500/20'
                                : 'bg-neutral-500/10 text-neutral-400 border-neutral-700'
                            }
                          >
                            {policy.is_active ? 'Active' : 'Disabled'}
                          </Badge>
                          {policy.priority > 0 && (
                            <span className="text-[10px] text-neutral-500 font-mono">
                              priority {policy.priority}
                            </span>
                          )}
                        </div>
                        {policy.description && (
                          <p className="text-xs text-neutral-400 mt-0.5 truncate">
                            {policy.description}
                          </p>
                        )}
                        <RuleSummaryBadges rules={policy.rules} />
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-1 shrink-0 ml-4">
                      <button
                        onClick={() => setExpandedId(isExpanded ? null : policy.id)}
                        className="p-1.5 text-neutral-500 hover:text-neutral-200 rounded transition-colors"
                        title={isExpanded ? 'Collapse' : 'View rules'}
                      >
                        <ChevronRight
                          className={`w-4 h-4 transition-transform ${isExpanded ? 'rotate-90' : ''}`}
                        />
                      </button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleToggleActive(policy)}
                        disabled={updateMutation.isPending}
                        className="text-xs text-neutral-400 hover:text-neutral-200"
                      >
                        {policy.is_active ? 'Disable' : 'Enable'}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setEditingPolicy(policy)}
                        className="text-neutral-400 hover:text-blue-400"
                        title="Edit policy"
                      >
                        <Edit className="w-3.5 h-3.5" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleDelete(policy.id, policy.name)}
                        disabled={deleteMutation.isPending}
                        className="text-neutral-400 hover:text-red-400"
                        title="Delete policy"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </div>

                  {/* Expanded: rule details */}
                  {isExpanded && (
                    <div className="border-t border-neutral-800 px-5 py-4 bg-neutral-950/50">
                      {policy.rules.length === 0 ? (
                        <p className="text-xs text-neutral-600 italic">
                          This policy has no rules yet. Click Edit to add rules.
                        </p>
                      ) : (
                        <div className="space-y-2">
                          <p className="text-xs text-neutral-500 font-medium uppercase tracking-wider mb-3">
                            {policy.rules.length} Rule{policy.rules.length !== 1 ? 's' : ''}
                          </p>
                          {policy.rules.map((rule, idx) => (
                            <div
                              key={rule.id}
                              className="flex items-start gap-3 bg-neutral-900 border border-neutral-800 rounded-lg px-4 py-2.5"
                            >
                              <span className="text-xs text-neutral-600 font-mono mt-0.5">
                                {idx + 1}
                              </span>
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span
                                    className={`text-xs font-bold ${ACTION_COLORS[rule.action] ?? ''}`}
                                  >
                                    {rule.action.toUpperCase()}
                                  </span>
                                  <span
                                    className={`text-[10px] px-1.5 py-0.5 rounded border ${RULE_TYPE_COLORS[rule.rule_type] ?? RULE_TYPE_COLORS.custom}`}
                                  >
                                    {rule.rule_type}
                                  </span>
                                  {!rule.is_active && (
                                    <span className="text-[10px] text-neutral-600 italic">
                                      (inactive)
                                    </span>
                                  )}
                                </div>
                                {rule.message && (
                                  <p className="text-xs text-neutral-400 mt-1">{rule.message}</p>
                                )}
                                {Object.keys(rule.conditions).length > 0 && (
                                  <pre className="text-[10px] text-neutral-500 mt-1 font-mono whitespace-pre-wrap">
                                    {JSON.stringify(rule.conditions, null, 2)}
                                  </pre>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Create Modal */}
      {showCreate && (
        <Modal title="Create Policy" onClose={() => setShowCreate(false)}>
          <PolicyForm
            mode="create"
            onSubmit={handleCreate}
            onCancel={() => setShowCreate(false)}
            isPending={createMutation.isPending}
          />
        </Modal>
      )}

      {/* Edit Modal */}
      {editingPolicy && (
        <Modal
          title={`Edit Policy: ${editingPolicy.name}`}
          onClose={() => setEditingPolicy(null)}
        >
          <PolicyForm
            mode="edit"
            initialData={editingPolicy}
            onSubmit={handleEdit}
            onCancel={() => setEditingPolicy(null)}
            isPending={updateMutation.isPending}
          />
        </Modal>
      )}
    </div>
  );
}
