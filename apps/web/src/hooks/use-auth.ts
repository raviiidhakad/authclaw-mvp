"use client";

import { useEffect, useCallback } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { apiClient } from '@/lib/api-client';
import { clearTokens, getTokens, setTokens } from '@/lib/auth';
import { useAuthStore } from '@/stores/auth-store';

type ApiError = {
  message?: string;
  response?: {
    data?: {
      detail?: string;
    };
  };
};

type LoginCredentials = {
  email: string;
  password: string;
};

type SignupPayload = LoginCredentials & {
  tenant_name: string;
  first_name: string;
  last_name: string;
};

function asApiError(error: unknown): ApiError {
  return error instanceof Error ? error : {};
}

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
      return res.data;
    } catch (err: unknown) {
      const apiError = asApiError(err);
      if (apiError.message !== 'No token') {
        console.error("fetchUser error:", apiError.response?.data || apiError.message);
      }
      clearTokens();
      setUser(null);
      if (pathname && !pathname.startsWith('/login') && !pathname.startsWith('/signup')) {
        router.push('/login');
      }
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [setUser, setIsLoading, pathname, router]);

  useEffect(() => {
    // Only fetch if we haven't already, or if we are loading
    if (isLoading) {
      fetchUser().catch(() => {});
    }
  }, [fetchUser, isLoading]);

  const login = async (credentials: LoginCredentials) => {
    const res = await apiClient.post('/auth/login', credentials);
    if (res.data.mfa_required) {
      return { mfaRequired: true, mfaToken: res.data.mfa_token };
    }
    if (!res.data.access_token) {
      throw new Error('Login failed: No access token received.');
    }
    setTokens({
      accessToken: res.data.access_token,
      refreshToken: res.data.refresh_token,
    });
    await fetchUser();
    router.push('/');
    return { mfaRequired: false };
  };

  const verifyMfa = async (mfaToken: string, code: string) => {
    const res = await apiClient.post('/auth/login/mfa', { mfa_token: mfaToken, code });
    if (!res.data.access_token) {
      throw new Error('MFA verification failed: No access token received.');
    }
    setTokens({
      accessToken: res.data.access_token,
      refreshToken: res.data.refresh_token,
    });
    await fetchUser();
    router.push('/');
  };

  const signup = async (data: SignupPayload) => {
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

  return { user, isLoading, login, verifyMfa, signup, logout };
}
