"use client";

import { useState } from 'react';
import Link from 'next/link';
import { useAuth } from '@/hooks/use-auth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';

export default function SignupPage() {
  const { signup } = useAuth();
  const [formData, setFormData] = useState({
    tenant_name: '',
    email: '',
    password: '',
    first_name: '',
    last_name: ''
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      await signup(formData);
      toast.success('Account created successfully');
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to sign up');
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData(prev => ({...prev, [e.target.name]: e.target.value}));
  };

  return (
    <div className="w-full">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-2">
          <label className="text-sm font-medium text-neutral-300">Organization Name</label>
          <Input 
            name="tenant_name"
            placeholder="Acme Corp" 
            value={formData.tenant_name}
            onChange={handleChange}
            className="bg-neutral-950 border-neutral-800 text-neutral-100 placeholder:text-neutral-600"
            required
          />
        </div>
        
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-sm font-medium text-neutral-300">First Name</label>
            <Input 
              name="first_name"
              placeholder="Jane" 
              value={formData.first_name}
              onChange={handleChange}
              className="bg-neutral-950 border-neutral-800 text-neutral-100 placeholder:text-neutral-600"
              required
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium text-neutral-300">Last Name</label>
            <Input 
              name="last_name"
              placeholder="Doe" 
              value={formData.last_name}
              onChange={handleChange}
              className="bg-neutral-950 border-neutral-800 text-neutral-100 placeholder:text-neutral-600"
              required
            />
          </div>
        </div>

        <div className="space-y-2">
          <label className="text-sm font-medium text-neutral-300">Work Email</label>
          <Input 
            type="email"
            name="email"
            placeholder="jane@acme.com" 
            value={formData.email}
            onChange={handleChange}
            className="bg-neutral-950 border-neutral-800 text-neutral-100 placeholder:text-neutral-600"
            required
          />
        </div>

        <div className="space-y-2">
          <label className="text-sm font-medium text-neutral-300">Password</label>
          <Input 
            type="password" 
            name="password"
            placeholder="••••••••" 
            value={formData.password}
            onChange={handleChange}
            className="bg-neutral-950 border-neutral-800 text-neutral-100 placeholder:text-neutral-600"
            required
          />
        </div>

        <Button 
          type="submit" 
          disabled={loading}
          className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium mt-2"
        >
          {loading ? 'Creating account...' : 'Create Account'}
        </Button>
      </form>
      
      <div className="mt-6 text-center text-sm text-neutral-400">
        Already have an account?{' '}
        <Link href="/login" className="text-blue-500 hover:text-blue-400 font-medium">
          Sign In
        </Link>
      </div>
    </div>
  );
}
