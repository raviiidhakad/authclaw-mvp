"use client";

import { ShieldCheck, Activity, AlertTriangle, FileText, Download } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useCompliance, useComplianceHistory } from '@/hooks/use-data';
import { apiClient } from '@/lib/api-client';

export default function CompliancePage() {
  const { data: currentScore, isLoading: loading } = useCompliance();
  const { data: historyData } = useComplianceHistory(5, 'gdpr');
  const history = historyData || [];

  const handleExportReport = async () => {
    try {
      // Assuming there is an export endpoint, otherwise just a placeholder
      const response = await apiClient.get('/compliance/export', { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', 'compliance_report.pdf');
      document.body.appendChild(link);
      link.click();
      link.parentNode?.removeChild(link);
    } catch (e) {
      console.error("Export failed", e);
    }
  };

  const score = currentScore?.overall_score || 0;
  
  let scoreColor = 'text-green-500';
  if (score < 70) scoreColor = 'text-red-500';
  else if (score < 90) scoreColor = 'text-amber-500';

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Compliance & Security</h2>
          <p className="text-neutral-400">Monitor your security posture and compliance with major frameworks.</p>
        </div>
        <Button onClick={handleExportReport} variant="outline" className="border-neutral-800 bg-neutral-900 text-neutral-300 hover:bg-neutral-800">
          <Download className="w-4 h-4 mr-2" />
          Export Report
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card className="bg-neutral-900 border-neutral-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-neutral-400">Overall Score</CardTitle>
            <ShieldCheck className={`h-4 w-4 ${scoreColor}`} />
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="animate-pulse h-8 w-16 bg-neutral-800 rounded"></div>
            ) : (
              <div className={`text-3xl font-bold ${scoreColor}`}>{score}/100</div>
            )}
            <p className="text-xs text-neutral-500 mt-1">Based on implemented controls</p>
          </CardContent>
        </Card>

        <Card className="bg-neutral-900 border-neutral-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-neutral-400">Missing Controls</CardTitle>
            <AlertTriangle className="h-4 w-4 text-amber-500" />
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="animate-pulse h-8 w-16 bg-neutral-800 rounded"></div>
            ) : (
              <div className="text-3xl font-bold text-neutral-100">{currentScore?.missing_controls?.length || 0}</div>
            )}
            <p className="text-xs text-neutral-500 mt-1">Require your attention</p>
          </CardContent>
        </Card>

        <Card className="bg-neutral-900 border-neutral-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-neutral-400">Frameworks</CardTitle>
            <FileText className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-neutral-100">3</div>
            <p className="text-xs text-neutral-500 mt-1">SOC2, HIPAA, GDPR</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card className="bg-neutral-900 border-neutral-800">
          <CardHeader>
            <CardTitle className="text-neutral-100">Missing Controls</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="space-y-2">
                <div className="h-10 bg-neutral-800 rounded animate-pulse"></div>
                <div className="h-10 bg-neutral-800 rounded animate-pulse"></div>
              </div>
            ) : currentScore?.missing_controls?.length === 0 ? (
              <div className="text-center py-6 text-neutral-500">
                <ShieldCheck className="w-8 h-8 mx-auto mb-2 opacity-50 text-green-500" />
                <p>All critical controls implemented!</p>
              </div>
            ) : (
              <ul className="space-y-3">
                {currentScore?.missing_controls?.map((control: string, idx: number) => (
                  <li key={idx} className="flex items-start gap-3 p-3 rounded-md bg-neutral-950 border border-neutral-800">
                    <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm font-medium text-neutral-200">{control}</p>
                      <p className="text-xs text-neutral-500">Implement this to improve your score.</p>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card className="bg-neutral-900 border-neutral-800">
          <CardHeader>
            <CardTitle className="text-neutral-100">Score History</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="space-y-2">
                <div className="h-10 bg-neutral-800 rounded animate-pulse"></div>
              </div>
            ) : history.length === 0 ? (
              <div className="text-center py-6 text-neutral-500">
                <Activity className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>No history available.</p>
              </div>
            ) : (
              <div className="relative border-l border-neutral-800 ml-3 space-y-6 pb-2">
                {history.map((record: any, idx: number) => (
                  <div key={idx} className="relative pl-6">
                    <div className="absolute w-3 h-3 bg-blue-500 rounded-full -left-[1.5px] top-1.5 ring-4 ring-neutral-900"></div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-bold text-neutral-200">Score: {record.score ?? record.overall_score}</span>
                        <span className="text-xs text-neutral-500">{new Date(record.calculated_at ?? record.created_at).toLocaleDateString()}</span>
                      </div>
                      <p className="text-xs text-neutral-400 mt-1">
                        {record.policy_failures ?? record.missing_controls?.length ?? 0} policy failures
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
