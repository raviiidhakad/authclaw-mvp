"use client";

import { AlertTriangle, FlaskConical, ShieldCheck } from 'lucide-react';
import { Card, CardContent, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { EmptyState } from '@/components/shared/states';

const plannedSurfaces = [
  ['Probe runs', 'Adversarial prompt-injection, data-disclosure, harmful-content, and sycophancy probes.'],
  ['Vulnerability register', 'Severity, owner, status, and evidence-supported remediation posture.'],
  ['Go/no-go posture', 'Release readiness summary derived from probe thresholds and unresolved critical risks.'],
];

export default function RiskPage() {
  return (
    <div className="space-y-6 max-w-[1600px] mx-auto pb-10">
      <div className="flex flex-col md:flex-row items-start md:items-end justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-neutral-100 font-sans flex items-center gap-2">
            <FlaskConical className="w-6 h-6 text-amber-400" />
            Risk & Red Teaming
          </h2>
          <p className="text-sm text-neutral-400 mt-1">Adversarial testing posture and vulnerability tracking. Backend APIs are not enabled in this MVP console.</p>
        </div>
        <Badge variant="outline" className="bg-amber-500/10 text-amber-300 border-amber-500/20">Backend gap</Badge>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        {plannedSurfaces.map(([title, description]) => (
          <Card key={title} className="glass-card">
            <CardContent className="p-5">
              <div className="flex items-center gap-2 text-sm font-semibold text-neutral-100">
                <ShieldCheck className="w-4 h-4 text-neutral-500" />
                {title}
              </div>
              <p className="mt-3 text-sm leading-6 text-neutral-400">{description}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card className="glass-card border-amber-500/20">
        <div className="p-4 border-b border-white/5 bg-black/20 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          <CardTitle className="text-neutral-100 text-base">Safe Empty State</CardTitle>
        </div>
        <CardContent className="p-0">
          <EmptyState
            title="Red-team backend not implemented"
            description="No fake probe runs or vulnerability rows are shown. Add backend APIs for probe runs, vulnerability register, and go/no-go posture before enabling this workspace."
            icon={FlaskConical}
          />
        </CardContent>
      </Card>
    </div>
  );
}
