'use client';

import { useState } from 'react';
import { useApprovals, useRunAgentScan, useApproveAction, useRejectAction } from '@/hooks/use-data';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Search, Loader2, Play, CheckCircle, XCircle, ShieldCheck } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import { toast } from 'sonner';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

export default function ApprovalsPage() {
  const { data: approvals = [], isLoading } = useApprovals();
  const runScanMutation = useRunAgentScan();
  const approveMutation = useApproveAction();
  const rejectMutation = useRejectAction();

  const [selectedApproval, setSelectedApproval] = useState<any>(null);
  const [showMfaPrompt, setShowMfaPrompt] = useState(false);
  const [mfaCode, setMfaCode] = useState('');

  const handleRunScan = async (target: string) => {
    try {
      toast.info(`Running agent scan on ${target}...`);
      await runScanMutation.mutateAsync(target);
      toast.success('Scan complete. New actions created.');
    } catch (err: any) {
      toast.error('Failed to run scan');
    }
  };

  const handleApproveClick = () => {
    if (!selectedApproval) return;
    setMfaCode('');
    setShowMfaPrompt(true);
  };

  const executeApproval = async () => {
    if (!selectedApproval) return;
    try {
      await approveMutation.mutateAsync({ id: selectedApproval.id, code: mfaCode });
      toast.success('Action approved and executed!');
      setShowMfaPrompt(false);
      setSelectedApproval(null);
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to approve action');
    }
  };

  const handleReject = async () => {
    if (!selectedApproval) return;
    try {
      await rejectMutation.mutateAsync(selectedApproval.id);
      toast.success('Action rejected.');
      setSelectedApproval(null);
    } catch (err) {
      toast.error('Failed to reject action');
    }
  };

  const formatDate = (dateStr: string) => {
    return new Intl.DateTimeFormat('en-US', { 
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' 
    }).format(new Date(dateStr));
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8 animate-in fade-in">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white mb-2">Action Center</h1>
          <p className="text-neutral-400">Agentic remediation and Human-In-The-Loop approvals.</p>
        </div>
        <div className="flex gap-4">
          <Button 
            onClick={() => handleRunScan('AWS')}
            disabled={runScanMutation.isPending}
            className="bg-orange-600 hover:bg-orange-700"
          >
            {runScanMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Play className="w-4 h-4 mr-2" />}
            Scan AWS
          </Button>
          <Button 
            onClick={() => handleRunScan('GitHub')}
            disabled={runScanMutation.isPending}
            className="bg-neutral-800 hover:bg-neutral-700"
          >
            {runScanMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Play className="w-4 h-4 mr-2" />}
            Scan GitHub
          </Button>
        </div>
      </div>

      <Card className="bg-neutral-900 border-neutral-800">
        <CardHeader>
          <CardTitle className="text-neutral-200">Pending Actions</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow className="border-neutral-800 hover:bg-transparent">
                <TableHead className="text-neutral-400">Date</TableHead>
                <TableHead className="text-neutral-400">Title</TableHead>
                <TableHead className="text-neutral-400">Type</TableHead>
                <TableHead className="text-neutral-400">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={4} className="h-24 text-center">
                    <Loader2 className="w-6 h-6 animate-spin mx-auto text-neutral-500" />
                  </TableCell>
                </TableRow>
              ) : approvals.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="h-24 text-center text-neutral-500">
                    No actions pending. Run a scan.
                  </TableCell>
                </TableRow>
              ) : (
                approvals.map((item: any) => (
                  <TableRow 
                    key={item.id} 
                    className="border-neutral-800 hover:bg-neutral-800/50 cursor-pointer"
                    onClick={() => setSelectedApproval(item)}
                  >
                    <TableCell className="text-neutral-300">
                      {formatDate(item.created_at)}
                    </TableCell>

                    <TableCell className="font-medium text-neutral-200">{item.title}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="border-neutral-700 text-neutral-400 uppercase text-xs">
                        {item.action_type}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge className={
                        item.status === 'pending' ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20' :
                        item.status === 'executed' ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' :
                        'bg-red-500/10 text-red-500 border-red-500/20'
                      }>
                        {item.status.toUpperCase()}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={!!selectedApproval} onOpenChange={(open) => !open && setSelectedApproval(null)}>
        <DialogContent className="sm:max-w-[800px] max-h-[90vh] flex flex-col bg-neutral-900 border-neutral-800 text-neutral-200 p-0 overflow-hidden">
          <DialogHeader className="p-6 pb-2 border-b border-neutral-800 bg-neutral-900 shrink-0">
            <DialogTitle className="text-xl font-bold text-white">{selectedApproval?.title}</DialogTitle>
            <div className="sr-only">Review remediation details</div>
            <div className="flex gap-2 mt-2">
              <Badge variant="outline" className="border-neutral-700 text-neutral-400">
                {selectedApproval?.action_type?.toUpperCase()}
              </Badge>
              <Badge className={
                        selectedApproval?.status === 'pending' ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20' :
                        selectedApproval?.status === 'executed' ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' :
                        'bg-red-500/10 text-red-500 border-red-500/20'
                      }>
                {selectedApproval?.status?.toUpperCase()}
              </Badge>
            </div>
          </DialogHeader>
          
          <div className="p-6 space-y-4 flex-1 overflow-y-auto">
            <div>
              <h3 className="text-sm font-medium text-neutral-400 mb-2">Agent Analysis</h3>
              <div className="bg-neutral-950 p-4 rounded-md border border-neutral-800">
                <div className="prose prose-sm prose-invert max-w-none text-neutral-300">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {selectedApproval?.description || ''}
                  </ReactMarkdown>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-sm font-medium text-neutral-400 mb-2">Remediation Plan ({selectedApproval?.action_type})</h3>
              <div className="bg-[#1e1e1e] rounded-md border border-neutral-800 overflow-hidden">
                <div className="bg-[#2d2d2d] px-4 py-2 border-b border-neutral-800 flex items-center text-xs text-neutral-400 font-mono">
                  proposed_changes.{selectedApproval?.action_type === 'terraform' ? 'tf' : 'sh'}
                </div>
                <pre className="p-4 text-sm font-mono text-emerald-400 overflow-x-auto">
                  {selectedApproval?.diff_content}
                </pre>
              </div>
            </div>
          </div>

          <div className="p-4 bg-neutral-950 border-t border-neutral-800 flex justify-end gap-3 shrink-0">
            {selectedApproval?.status === 'pending' ? (
              <>
                <Button 
                  variant="outline" 
                  onClick={handleReject}
                  disabled={rejectMutation.isPending || approveMutation.isPending}
                  className="border-neutral-700 text-neutral-300 hover:bg-red-500/10 hover:text-red-500 hover:border-red-500/30"
                >
                  <XCircle className="w-4 h-4 mr-2" />
                  Reject
                </Button>
                <Button 
                  onClick={handleApproveClick}
                  disabled={rejectMutation.isPending || approveMutation.isPending}
                  className="bg-emerald-600 hover:bg-emerald-700 text-white"
                >
                  <CheckCircle className="w-4 h-4 mr-2" />
                  Approve & Execute
                </Button>
              </>
            ) : (
              <Button onClick={() => setSelectedApproval(null)} variant="secondary" className="bg-neutral-800 hover:bg-neutral-700 text-white">
                Close
              </Button>
            )}
          </div>
        </DialogContent>
      </Dialog>

      <Dialog open={showMfaPrompt} onOpenChange={setShowMfaPrompt}>
        <DialogContent className="sm:max-w-md bg-neutral-900 border-neutral-800 text-neutral-100">
          <DialogHeader>
            <DialogTitle>MFA Verification Required</DialogTitle>
            <DialogDescription className="text-neutral-400">
              Please enter your 6-digit authenticator code to authorize this action.
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col items-center justify-center space-y-4 py-4">
            <div className="w-full">
              <Input
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                placeholder="123456"
                className="bg-neutral-950 border-neutral-800 text-neutral-100 text-center tracking-[0.5em] font-mono text-lg"
                maxLength={6}
                autoFocus
              />
            </div>
          </div>
          <DialogFooter className="bg-transparent border-t-0 p-0">
            <Button variant="ghost" onClick={() => setShowMfaPrompt(false)}>Cancel</Button>
            <Button 
              onClick={executeApproval} 
              disabled={mfaCode.length !== 6 || approveMutation.isPending} 
              className="bg-emerald-600 hover:bg-emerald-700 text-white"
            >
              {approveMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <ShieldCheck className="w-4 h-4 mr-2" />}
              Verify & Approve
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
