"use client";

import { useState } from 'react';
import { Clock, Search, Filter, Activity, Download } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { useAuditLogs } from '@/hooks/use-data';
import { apiClient } from '@/lib/api-client';

export default function AuditPage() {
  const [search, setSearch] = useState('');
  const { data, isLoading: loading } = useAuditLogs(0, 100);
  const events = data?.items || [];

  const filteredEvents = events.filter((e: any) => 
    search === '' || 
    e.event_type?.toLowerCase().includes(search.toLowerCase()) ||
    e.action?.toLowerCase().includes(search.toLowerCase()) ||
    e.resource?.toLowerCase().includes(search.toLowerCase())
  );

  const getEventTypeBadge = (type: string) => {
    const colors: Record<string, string> = {
      'gateway.request': 'bg-blue-500/10 text-blue-400 border-blue-500/20',
      'policy.violation': 'bg-red-500/10 text-red-400 border-red-500/20',
      'auth.login': 'bg-green-500/10 text-green-400 border-green-500/20',
      'auth.signup': 'bg-green-500/10 text-green-400 border-green-500/20',
      'policy.created': 'bg-purple-500/10 text-purple-400 border-purple-500/20',
      'admin.provider_created': 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
    };
    return <Badge className={colors[type] || 'bg-neutral-500/10 text-neutral-400 border-neutral-500/20'}>{type}</Badge>;
  };

  const handleExport = async () => {
    try {
      const response = await apiClient.get('/audit/logs/export', { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', 'audit_logs.csv');
      document.body.appendChild(link);
      link.click();
      link.parentNode?.removeChild(link);
    } catch (e) {
      console.error("Export failed", e);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Audit Logs</h2>
          <p className="text-neutral-400">Immutable audit trail of all platform activity.</p>
        </div>
        <Button onClick={handleExport} variant="outline" className="border-neutral-800 bg-neutral-900 text-neutral-300 hover:bg-neutral-800">
          <Download className="w-4 h-4 mr-2" />
          Export CSV
        </Button>
      </div>

      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-neutral-500" />
          <Input
            placeholder="Search events by type, resource, or action..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-10 bg-neutral-900 border-neutral-800 text-neutral-100"
          />
        </div>
        <Button variant="outline" className="border-neutral-800 bg-neutral-900 text-neutral-300 hover:bg-neutral-800">
          <Filter className="w-4 h-4 mr-2" />
          Filters
        </Button>
      </div>

      <Card className="bg-neutral-900 border-neutral-800">
        <CardContent className="p-0">
          {loading ? (
            <div className="flex items-center justify-center py-12 text-neutral-500">Loading...</div>
          ) : filteredEvents.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-neutral-500">
              <Activity className="w-10 h-10 mb-3 opacity-40" />
              <p>No audit events found.</p>
            </div>
          ) : (
            <div className="overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-neutral-800 bg-neutral-800/50">
                    <th className="text-left p-3 text-neutral-400 font-medium">Timestamp</th>
                    <th className="text-left p-3 text-neutral-400 font-medium">Event Type</th>
                    <th className="text-left p-3 text-neutral-400 font-medium">Actor ID</th>
                    <th className="text-left p-3 text-neutral-400 font-medium">Action</th>
                    <th className="text-left p-3 text-neutral-400 font-medium">Resource</th>
                    <th className="text-left p-3 text-neutral-400 font-medium">Details</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEvents.map((event: any, i: number) => (
                    <tr key={event.id || i} className="border-b border-neutral-800 hover:bg-neutral-800/30">
                      <td className="p-3 text-neutral-400 text-xs whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <Clock className="w-3 h-3" />
                          {new Date(event.created_at).toLocaleString()}
                        </div>
                      </td>
                      <td className="p-3">{getEventTypeBadge(event.event_type)}</td>
                      <td className="p-3 text-neutral-300 text-xs">{event.user_id ? event.user_id.substring(0, 8) : 'system'}</td>
                      <td className="p-3 text-neutral-300 text-xs uppercase">{event.action}</td>
                      <td className="p-3 text-neutral-400 text-xs">
                        {event.resource ? `${event.resource}/${event.resource_id?.substring(0, 8) || '*'}` : '—'}
                      </td>
                      <td className="p-3 text-neutral-500 text-xs max-w-xs truncate">
                        {typeof event.metadata === 'object' 
                          ? JSON.stringify(event.metadata).substring(0, 80)
                          : event.metadata || '—'
                        }
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
