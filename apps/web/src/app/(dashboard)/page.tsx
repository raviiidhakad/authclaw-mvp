"use client";

import { ShieldCheck, Activity, AlertTriangle, Network } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useDashboardStats, useComplianceDashboard, useGatewayRequests } from '@/hooks/use-data';
import { Skeleton } from '@/components/ui/skeleton';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';

// Build 24-hour activity buckets from gateway request items
function buildChartData(items: any[]): Array<{ hour: string; allowed: number; blocked: number; redacted: number }> {
  const now = new Date();
  const buckets: Record<string, { allowed: number; blocked: number; redacted: number }> = {};

  // Initialise last 12 hours
  for (let i = 11; i >= 0; i--) {
    const d = new Date(now);
    d.setHours(d.getHours() - i, 0, 0, 0);
    const key = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    buckets[key] = { allowed: 0, blocked: 0, redacted: 0 };
  }

  for (const item of items) {
    const d = new Date(item.created_at);
    d.setMinutes(0, 0, 0); // Round down to the hour to match bucket keys
    const key = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (!buckets[key]) continue;
    const s = (item.status || '').toLowerCase();
    if (s === 'success' || s === 'allowed' || s === 'completed') buckets[key].allowed++;
    else if (s === 'blocked') buckets[key].blocked++;
    else buckets[key].redacted++;
  }

  return Object.entries(buckets).map(([hour, counts]) => ({ hour, ...counts }));
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-neutral-900 border border-neutral-700 rounded-lg p-3 text-xs shadow-xl">
        <p className="text-neutral-400 mb-1 font-medium">{label}</p>
        {payload.map((p: any) => (
          <p key={p.name} style={{ color: p.color }} className="capitalize">
            {p.name}: <span className="font-bold">{p.value}</span>
          </p>
        ))}
      </div>
    );
  }
  return null;
};

export default function DashboardPage() {
  const { data: stats, isLoading: statsLoading } = useDashboardStats();
  const { data: compliance, isLoading: compLoading } = useComplianceDashboard();
  const { data: gatewayData, isLoading: gatewayLoading } = useGatewayRequests(0, 200);

  const isLoading = statsLoading || compLoading;

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Overview</h2>
          <p className="text-neutral-400">Loading your AI Security posture...</p>
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Skeleton className="h-32 w-full" />
          <Skeleton className="h-32 w-full" />
          <Skeleton className="h-32 w-full" />
          <Skeleton className="h-32 w-full" />
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
          <Skeleton className="col-span-4 h-[320px] w-full" />
          <Skeleton className="col-span-3 h-[320px] w-full" />
        </div>
      </div>
    );
  }

  const totalRequests = stats?.audit?.total_events || 0;
  const violations = stats?.audit?.events_by_type?.['policy.violation'] || 0;
  const blocked = stats?.audit?.gateway_by_status?.['blocked'] || stats?.audit?.events_by_type?.['gateway.blocked'] || 0;
  const errors = stats?.audit?.gateway_by_status?.['error'] || stats?.audit?.events_by_type?.['gateway.error'] || 0;

  const chartData = buildChartData(gatewayData?.items || []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Overview</h2>
        <p className="text-neutral-400">Your AI Security posture at a glance.</p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="bg-neutral-900 border-neutral-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-neutral-400">Total Requests</CardTitle>
            <Activity className="h-4 w-4 text-neutral-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-neutral-100">{totalRequests}</div>
          </CardContent>
        </Card>

        <Card className="bg-neutral-900 border-neutral-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-neutral-400">Violations Detected</CardTitle>
            <AlertTriangle className="h-4 w-4 text-amber-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-neutral-100">{violations}</div>
          </CardContent>
        </Card>

        <Card className="bg-neutral-900 border-neutral-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-neutral-400">Blocked Requests</CardTitle>
            <ShieldCheck className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-neutral-100">{blocked}</div>
          </CardContent>
        </Card>

        <Card className="bg-neutral-900 border-neutral-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-neutral-400">Active Tenants</CardTitle>
            <Network className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-neutral-100">{stats?.tenants?.total || 1}</div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        {/* Live Gateway Activity Chart */}
        <Card className="col-span-4 bg-neutral-900 border-neutral-800">
          <CardHeader>
            <CardTitle className="text-neutral-100">Gateway Activity</CardTitle>
            <p className="text-xs text-neutral-500">Last 12 hours of AI traffic</p>
          </CardHeader>
          <CardContent>
            {gatewayLoading ? (
              <div className="h-[260px] flex items-center justify-center text-neutral-500 text-sm">
                Loading chart…
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={260}>
                <AreaChart data={chartData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="gradAllowed" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gradBlocked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gradRedacted" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#262626" vertical={false} />
                  <XAxis
                    dataKey="hour"
                    tick={{ fontSize: 10, fill: '#737373' }}
                    axisLine={false}
                    tickLine={false}
                    interval={2}
                  />
                  <YAxis
                    tick={{ fontSize: 10, fill: '#737373' }}
                    axisLine={false}
                    tickLine={false}
                    allowDecimals={false}
                  />
                  <Tooltip content={<CustomTooltip />} />
                  <Legend
                    iconType="circle"
                    iconSize={8}
                    wrapperStyle={{ fontSize: '11px', color: '#a3a3a3', paddingTop: '8px' }}
                  />
                  <Area
                    type="monotone"
                    dataKey="allowed"
                    name="Allowed"
                    stroke="#3b82f6"
                    strokeWidth={2}
                    fill="url(#gradAllowed)"
                    dot={false}
                    activeDot={{ r: 4, strokeWidth: 0 }}
                  />
                  <Area
                    type="monotone"
                    dataKey="blocked"
                    name="Blocked"
                    stroke="#ef4444"
                    strokeWidth={2}
                    fill="url(#gradBlocked)"
                    dot={false}
                    activeDot={{ r: 4, strokeWidth: 0 }}
                  />
                  <Area
                    type="monotone"
                    dataKey="redacted"
                    name="Redacted"
                    stroke="#f59e0b"
                    strokeWidth={2}
                    fill="url(#gradRedacted)"
                    dot={false}
                    activeDot={{ r: 4, strokeWidth: 0 }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        {/* Compliance Posture */}
        <Card className="col-span-3 bg-neutral-900 border-neutral-800">
          <CardHeader>
            <CardTitle className="text-neutral-100">Compliance Posture</CardTitle>
            <p className="text-xs text-neutral-500">Latest framework scores</p>
          </CardHeader>
          <CardContent className="flex flex-col gap-6">
            {['gdpr', 'hipaa', 'soc2'].map((fw) => {
              const fwData = compliance?.[fw];
              const score = fwData?.score ?? 0;
              let color = 'bg-red-500';
              let textColor = 'text-red-500';
              if (score >= 80) {
                color = 'bg-green-500';
                textColor = 'text-green-500';
              } else if (score >= 50) {
                color = 'bg-amber-500';
                textColor = 'text-amber-500';
              }

              const statusLabel = fwData?.status === 'not_calculated'
                ? 'Not Calculated'
                : fwData?.status === 'compliant'
                ? 'Compliant'
                : fwData?.status === 'at_risk'
                ? 'At Risk'
                : 'Non-Compliant';

              return (
                <div key={fw} className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="font-medium text-neutral-300 uppercase">{fw}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-neutral-500">{statusLabel}</span>
                      <span className={`${textColor} font-bold`}>
                        {fwData?.status === 'not_calculated' ? '—' : `${score}%`}
                      </span>
                    </div>
                  </div>
                  <div className="h-2 w-full bg-neutral-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${color} transition-all duration-500`}
                      style={{ width: `${score}%` }}
                    />
                  </div>
                  {fwData?.critical_violations != null && fwData.critical_violations > 0 && (
                    <p className="text-xs text-red-400">
                      {fwData.critical_violations} critical violation{fwData.critical_violations !== 1 ? 's' : ''}
                    </p>
                  )}
                </div>
              );
            })}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
