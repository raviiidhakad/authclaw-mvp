"use client";

import { useState } from 'react';
import Link from 'next/link';
import { useAuth } from '@/hooks/use-auth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';

export default function LoginPage() {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      await login({ email, password });
      toast.success('Login successful');
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to login');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-2">
          <label className="text-sm font-medium text-neutral-300">Email Address</label>
          <Input 
            type="email" 
            placeholder="admin@authclaw.io" 
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="bg-neutral-950 border-neutral-800 text-neutral-100 placeholder:text-neutral-600"
            required
          />
        </div>
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label className="text-sm font-medium text-neutral-300">Password</label>
            <Link href="#" className="text-xs text-blue-500 hover:text-blue-400">Forgot password?</Link>
          </div>
          <Input 
            type="password" 
            placeholder="••••••••" 
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="bg-neutral-950 border-neutral-800 text-neutral-100 placeholder:text-neutral-600"
            required
          />
        </div>
        <Button 
          type="submit" 
          disabled={loading}
          className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium"
        >
          {loading ? 'Signing in...' : 'Sign In'}
        </Button>
      </form>
      
      <div className="mt-6 text-center text-sm text-neutral-400">
        Don't have an account?{' '}
        <Link href="/signup" className="text-blue-500 hover:text-blue-400 font-medium">
          Create an organization
        </Link>
      </div>
    </div>
  );
}
