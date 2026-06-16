"use client";

import { useEffect, useCallback } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { apiClient } from '@/lib/api-client';
import { clearTokens, getTokens, setTokens } from '@/lib/auth';
import { useAuthStore } from '@/stores/auth-store';

export function useAuth() {
  const router = useRouter();
  const pathname = usePathname();
  const { user, setUser, isLoading, setIsLoading } = useAuthStore();

  const fetchUser = useCallback(async () => {
    try {
      if (!getTokens()?.accessToken) {
        throw new Error('No token');
      }
      const res = await apiClient.get('/auth/me');
      setUser(res.data);
    } catch (err) {
      clearTokens();
      setUser(null);
      if (pathname && !pathname.startsWith('/login') && !pathname.startsWith('/signup')) {
        router.push('/login');
      }
    } finally {
      setIsLoading(false);
    }
  }, [setUser, setIsLoading, pathname, router]);

  useEffect(() => {
    fetchUser();
  }, [fetchUser]);

  const login = async (credentials: any) => {
    const res = await apiClient.post('/auth/login', credentials);
    setTokens({
      accessToken: res.data.access_token,
      refreshToken: res.data.refresh_token,
    });
    await fetchUser();
    router.push('/');
  };

  const signup = async (data: any) => {
    // Map tenant_name to company_name for the backend schema
    const payload = {
      ...data,
      company_name: data.tenant_name
    };
    await apiClient.post('/auth/signup', payload);
    // After signup, automatically login
    await login({ email: data.email, password: data.password });
  };

  const logout = () => {
    clearTokens();
    setUser(null);
    router.push('/login');
  };

  return { user, isLoading, login, signup, logout };
}
