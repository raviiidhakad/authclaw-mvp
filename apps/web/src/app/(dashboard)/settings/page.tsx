"use client";

import { useState } from 'react';
import { Plus, Server, Trash2, Eye, EyeOff, Key, ShieldCheck } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import { useProviders, useCreateProvider, useDeleteProvider, useApiKeys, useCreateApiKey, useRevokeApiKey } from '@/hooks/use-data';
import { toast } from 'sonner';
import { useAuth } from '@/hooks/use-auth';
export default function SettingsPage() {
  const { user } = useAuth();
  
  // Providers
  const { data: providers = [], isLoading: loading } = useProviders();
  const createMutation = useCreateProvider();
  const deleteMutation = useDeleteProvider();

  const [showCreate, setShowCreate] = useState(false);
  const [showKeys, setShowKeys] = useState<Record<string, boolean>>({});
  const [newProvider, setNewProvider] = useState({
    name: '',
    provider_type: 'openai',
    api_key: '',
    base_url: '',
  });

  // API Keys
  const { data: apiKeysData, isLoading: apiKeysLoading } = useApiKeys(0, 100);
  const apiKeys = Array.isArray(apiKeysData) ? apiKeysData : (apiKeysData?.items || []);
  const createKeyMutation = useCreateApiKey();
  const revokeKeyMutation = useRevokeApiKey();

  const [showCreateKey, setShowCreateKey] = useState(false);
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);
  const [newApiKey, setNewApiKey] = useState({
    name: '',
    expires_in_days: 0,
  });

  const createApiKey = async () => {
    try {
      const result = await createKeyMutation.mutateAsync(newApiKey);
      toast.success('API Key created');
      setGeneratedKey(result.raw_key); // Display the plain text key once
      setShowCreateKey(false);
      setNewApiKey({ name: '', expires_in_days: 0 });
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to create API key');
    }
  };

  const revokeApiKey = async (id: string) => {
    try {
      await revokeKeyMutation.mutateAsync(id);
      toast.success('API Key revoked');
    } catch {
      toast.error('Failed to revoke API key');
    }
  };

  const createProvider = async () => {
    try {
      const payload = {
        name: newProvider.name,
        type: newProvider.provider_type,
        api_key: newProvider.api_key,
        config: newProvider.base_url ? { base_url: newProvider.base_url } : {},
        is_active: true
      };
      await createMutation.mutateAsync(payload);
      toast.success('Provider created');
      setShowCreate(false);
      setNewProvider({ name: '', provider_type: 'openai', api_key: '', base_url: '' });
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to create provider');
    }
  };

  const deleteProvider = async (id: string) => {
    try {
      await deleteMutation.mutateAsync(id);
      toast.success('Provider deleted');
    } catch {
      toast.error('Failed to delete provider');
    }
  };

  const getProviderIcon = (type: string) => {
    const colors: Record<string, string> = {
      openai: 'bg-green-600/10 text-green-500',
      anthropic: 'bg-orange-600/10 text-orange-500',
      azure_openai: 'bg-blue-600/10 text-blue-500',
    };
    return colors[type] || 'bg-neutral-800 text-neutral-400';
  };

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Settings</h2>
        <p className="text-neutral-400">Manage your organization, providers, and API keys.</p>
      </div>

      {/* Organization Info */}
      <Card className="bg-neutral-900 border-neutral-800">
        <CardHeader>
          <CardTitle className="text-neutral-100">Organization</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-neutral-500 block mb-1">User</label>
              <p className="text-sm text-neutral-200">{user?.first_name} {user?.last_name}</p>
            </div>
            <div>
              <label className="text-xs text-neutral-500 block mb-1">Email</label>
              <p className="text-sm text-neutral-200">{user?.email}</p>
            </div>
            <div>
              <label className="text-xs text-neutral-500 block mb-1">Tenant ID</label>
              <p className="text-sm text-neutral-400 font-mono">{user?.tenant_id}</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* AI Providers */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-neutral-100">AI Providers</h3>
            <p className="text-sm text-neutral-400">Configure your upstream AI provider connections.</p>
          </div>
          <Button onClick={() => setShowCreate(!showCreate)} className="bg-blue-600 hover:bg-blue-700" disabled={createMutation.isPending}>
            <Plus className="w-4 h-4 mr-2" />
            Add Provider
          </Button>
        </div>

        {showCreate && (
          <Card className="bg-neutral-900 border-neutral-800">
            <CardContent className="space-y-4 pt-6">
              <Input
                placeholder="Provider name (e.g., Production OpenAI)"
                value={newProvider.name}
                onChange={(e) => setNewProvider(p => ({ ...p, name: e.target.value }))}
                className="bg-neutral-950 border-neutral-800 text-neutral-100"
              />
              <select
                value={newProvider.provider_type}
                onChange={(e) => setNewProvider(p => ({ ...p, provider_type: e.target.value }))}
                className="w-full rounded-md bg-neutral-950 border border-neutral-800 text-neutral-100 p-2 text-sm"
              >
                <option value="openai">OpenAI</option>
                <option value="anthropic">Anthropic</option>
                <option value="azure_openai">Azure OpenAI</option>
              </select>
              <Input
                type="password"
                placeholder="API Key"
                value={newProvider.api_key}
                onChange={(e) => setNewProvider(p => ({ ...p, api_key: e.target.value }))}
                className="bg-neutral-950 border-neutral-800 text-neutral-100"
              />
              <Input
                placeholder="Base URL (optional, e.g., https://api.openai.com/v1)"
                value={newProvider.base_url}
                onChange={(e) => setNewProvider(p => ({ ...p, base_url: e.target.value }))}
                className="bg-neutral-950 border-neutral-800 text-neutral-100"
              />
              <div className="flex gap-2">
                <Button onClick={createProvider} disabled={createMutation.isPending} className="bg-blue-600 hover:bg-blue-700">Add Provider</Button>
                <Button variant="ghost" onClick={() => setShowCreate(false)} className="text-neutral-400">Cancel</Button>
              </div>
            </CardContent>
          </Card>
        )}

        {loading ? (
          <div className="py-8 text-center text-neutral-500">Loading...</div>
        ) : providers.length === 0 ? (
          <Card className="bg-neutral-900 border-neutral-800">
            <CardContent className="flex flex-col items-center justify-center py-12 text-neutral-500">
              <Server className="w-10 h-10 mb-3 opacity-40" />
              <p>No providers configured.</p>
              <p className="text-xs mt-1">Add an AI provider to start proxying requests.</p>
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-4">
            {providers.map((provider: any) => (
              <Card key={provider.id} className="bg-neutral-900 border-neutral-800">
                <CardContent className="flex items-center justify-between py-4 px-6">
                  <div className="flex items-center gap-4">
                    <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${getProviderIcon(provider.provider_type)}`}>
                      <Server className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="font-semibold text-neutral-100">{provider.name}</h3>
                        <Badge className="bg-green-500/10 text-green-500 border-green-500/20">
                          {provider.is_active ? 'Active' : 'Inactive'}
                        </Badge>
                      </div>
                      <p className="text-sm text-neutral-400">{provider.provider_type}</p>
                      <div className="flex items-center gap-2 mt-1">
                        <Key className="w-3 h-3 text-neutral-500" />
                        <span className="text-xs text-neutral-500 font-mono">
                          {showKeys[provider.id] 
                            ? provider.api_key 
                            : '•'.repeat(20) + (provider.api_key?.slice(-4) || '')}
                        </span>
                        <button 
                          onClick={() => setShowKeys(k => ({ ...k, [provider.id]: !k[provider.id] }))}
                          className="text-neutral-500 hover:text-neutral-300"
                        >
                          {showKeys[provider.id] ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                        </button>
                      </div>
                    </div>
                  </div>
                  <Button 
                    variant="ghost" 
                    size="sm"
                    onClick={() => deleteProvider(provider.id)}
                    disabled={deleteMutation.isPending}
                    className="text-neutral-400 hover:text-red-400"
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>

      {/* API Keys */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-neutral-100">API Keys</h3>
            <p className="text-sm text-neutral-400">Manage API keys to authenticate with AuthClaw gateway.</p>
          </div>
          <Button onClick={() => setShowCreateKey(!showCreateKey)} className="bg-blue-600 hover:bg-blue-700" disabled={createKeyMutation.isPending}>
            <Plus className="w-4 h-4 mr-2" />
            Create API Key
          </Button>
        </div>

        {showCreateKey && (
          <Card className="bg-neutral-900 border-neutral-800">
            <CardContent className="space-y-4 pt-6">
              <Input
                placeholder="Key name (e.g., Production API Key)"
                value={newApiKey.name}
                onChange={(e) => setNewApiKey(k => ({ ...k, name: e.target.value }))}
                className="bg-neutral-950 border-neutral-800 text-neutral-100"
              />
              <Input
                type="number"
                placeholder="Expires in days (optional)"
                value={newApiKey.expires_in_days || ''}
                onChange={(e) => setNewApiKey(k => ({ ...k, expires_in_days: parseInt(e.target.value) || 0 }))}
                className="bg-neutral-950 border-neutral-800 text-neutral-100"
              />
              <div className="flex gap-2">
                <Button onClick={createApiKey} disabled={createKeyMutation.isPending} className="bg-blue-600 hover:bg-blue-700">Create Key</Button>
                <Button variant="ghost" onClick={() => setShowCreateKey(false)} className="text-neutral-400">Cancel</Button>
              </div>
            </CardContent>
          </Card>
        )}

        <Dialog open={!!generatedKey} onOpenChange={(open) => !open && setGeneratedKey(null)}>
          <DialogContent className="sm:max-w-md bg-neutral-900 border-neutral-800 text-neutral-100">
            <DialogHeader>
              <DialogTitle className="text-xl">Save your key</DialogTitle>
              <DialogDescription className="text-neutral-400 pt-2 pb-2">
                Please save your secret key in a safe place since <strong className="text-neutral-200">you won't be able to view it again</strong>. Keep it secure, as anyone with your API key can make requests on your behalf. If you do lose it, you'll need to generate a new one.
              </DialogDescription>
            </DialogHeader>
            <div className="flex items-center space-x-2 my-2">
              <Input
                readOnly
                value={generatedKey || ''}
                className="bg-neutral-950 border-neutral-800 text-neutral-100 font-mono text-sm"
              />
              <Button onClick={() => {
                navigator.clipboard.writeText(generatedKey || '');
                toast.success('API key copied to clipboard');
              }} className="bg-neutral-800 text-neutral-100 hover:bg-neutral-700 border border-neutral-700">
                Copy
              </Button>
            </div>
            <DialogFooter className="mt-2 border-t-0 bg-transparent p-0">
              <Button type="button" onClick={() => setGeneratedKey(null)} className="bg-neutral-200 text-neutral-900 hover:bg-neutral-300">
                Done
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {apiKeysLoading ? (
          <div className="py-8 text-center text-neutral-500">Loading...</div>
        ) : apiKeys.length === 0 ? (
          <Card className="bg-neutral-900 border-neutral-800">
            <CardContent className="flex flex-col items-center justify-center py-12 text-neutral-500">
              <Key className="w-10 h-10 mb-3 opacity-40" />
              <p>No API keys created.</p>
              <p className="text-xs mt-1">Create an API key to access the gateway programmatically.</p>
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-4">
            {apiKeys.map((apiKey: any) => (
              <Card key={apiKey.id} className="bg-neutral-900 border-neutral-800">
                <CardContent className="flex items-center justify-between py-4 px-6">
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-neutral-800 text-neutral-400">
                      <Key className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="font-semibold text-neutral-100">{apiKey.name}</h3>
                        <Badge className="bg-green-500/10 text-green-500 border-green-500/20">
                          {apiKey.is_active ? 'Active' : 'Inactive'}
                        </Badge>
                      </div>
                      <p className="text-sm text-neutral-400 font-mono mt-1">
                        Prefix: {apiKey.key_prefix}...
                      </p>
                      <p className="text-xs text-neutral-500 mt-1">
                        Created: {new Date(apiKey.created_at).toLocaleDateString()}
                        {apiKey.expires_at && ` · Expires: ${new Date(apiKey.expires_at).toLocaleDateString()}`}
                      </p>
                    </div>
                  </div>
                  <Button 
                    variant="ghost" 
                    size="sm"
                    onClick={() => revokeApiKey(apiKey.id)}
                    disabled={revokeKeyMutation.isPending}
                    className="text-neutral-400 hover:text-red-400"
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
