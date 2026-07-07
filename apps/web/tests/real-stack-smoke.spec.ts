import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

const apiBase = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';
const password = 'PhaseC-Smoke-Password-123!';

type AuthSession = {
  email: string;
  token: string;
  tenantId: string;
  providerName: string;
  routeName: string;
  routeId: string;
  forbiddenRouteName?: string;
};

let ownerA: AuthSession;
let ownerB: AuthSession;
let viewerA: { email: string; token: string };

async function postJson(request: APIRequestContext, path: string, data: object, token?: string) {
  const response = await request.post(`${apiBase}${path}`, {
    data,
    headers: token ? { Authorization: `Bearer ${token}` } : undefined,
  });
  return response;
}

async function login(request: APIRequestContext, email: string) {
  const response = await postJson(request, '/auth/login', { email, password });
  expect(response.ok(), await response.text()).toBeTruthy();
  return (await response.json()) as { access_token: string };
}

async function signupOwner(request: APIRequestContext, label: string): Promise<AuthSession> {
  const email = `phase-c-${label}@authclawsmoke.com`;
  const signup = await postJson(request, '/auth/signup', {
    email,
    password,
    first_name: 'Phase',
    last_name: `Smoke ${label}`,
    company_name: `Phase C Smoke ${label}`,
  });
  expect(signup.ok(), await signup.text()).toBeTruthy();
  const user = await signup.json();
  const { access_token: token } = await login(request, email);
  const providerName = `Phase C Provider ${label}`;
  const provider = await postJson(
    request,
    '/providers',
    {
      name: providerName,
      type: 'groq',
      api_key: `phase-c-local-provider-key-${label}`,
      config: { model: 'llama-3.1-8b-instant' },
      is_active: true,
    },
    token,
  );
  expect(provider.ok(), await provider.text()).toBeTruthy();
  const providerBody = await provider.json();
  const routeName = `Phase C Route ${label}`;
  const route = await postJson(
    request,
    '/gateway-routes',
    {
      name: routeName,
      description: 'Phase C real backend smoke route',
      provider_id: providerBody.id,
      is_default: false,
      is_active: true,
      redaction: 'mask',
      config: { model: 'llama-3.1-8b-instant' },
    },
    token,
  );
  expect(route.ok(), await route.text()).toBeTruthy();
  const routeBody = await route.json();
  return { email, token, tenantId: user.tenant_id, providerName, routeName, routeId: routeBody.id };
}

async function createViewer(request: APIRequestContext, owner: AuthSession, label: string) {
  const email = `phase-c-viewer-${label}@authclawsmoke.com`;
  const response = await postJson(
    request,
    '/users',
    { email, password, first_name: 'Viewer', last_name: label, role_name: 'viewer' },
    owner.token,
  );
  expect(response.ok(), await response.text()).toBeTruthy();
  const { access_token: token } = await login(request, email);
  return { email, token };
}

async function loginViaBrowser(page: Page, email: string) {
  await page.goto('/login');
  await page.locator('input[type="email"]').fill(email);
  await page.locator('input[type="password"]').fill(password);
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page.getByText(/System Overview/i)).toBeVisible({ timeout: 20_000 });
}

test.describe.serial('real backend connected smoke', () => {
  test.skip(process.env.AUTHCLAW_REAL_STACK_SMOKE !== '1', 'Requires the real AuthClaw backend and database.');

  test.beforeAll(async ({ request }) => {
    const label = Date.now().toString(36);
    ownerA = await signupOwner(request, `tenant-a-${label}`);
    ownerB = await signupOwner(request, `tenant-b-${label}`);
    viewerA = await createViewer(request, ownerA, label);
  });

  test('browser authenticates and renders real dashboard, gateway, and audit/compliance data', async ({ page }) => {
    const apiCalls: string[] = [];
    page.on('request', (req) => {
      if (req.url().includes('/api/v1/')) apiCalls.push(req.url());
    });

    await loginViaBrowser(page, ownerA.email);
    await expect(page.getByText(ownerA.providerName)).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(/Providers: 1\/1/i)).toBeVisible();

    await page.goto('/gateway-routes');
    await expect(page.getByText(ownerA.routeName)).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(ownerA.providerName)).toBeVisible();
    await expect(page.getByText(/Redaction: mask/i)).toBeVisible();

    await page.goto('/audit');
    await expect(page.getByRole('heading', { level: 2, name: 'Audit & Trust Center' })).toBeVisible();
    await expect(page.getByText(/Chain Status/i)).toBeVisible({ timeout: 20_000 });

    expect(apiCalls.some((url) => url.includes('/auth/login'))).toBeTruthy();
    expect(apiCalls.some((url) => url.includes('/auth/me'))).toBeTruthy();
    expect(apiCalls.some((url) => url.includes('/providers'))).toBeTruthy();
    expect(apiCalls.some((url) => url.includes('/gateway-routes'))).toBeTruthy();
    expect(apiCalls.some((url) => url.includes('/audit/'))).toBeTruthy();
  });

  test('real backend denies viewer writes and cross-tenant route reads', async ({ request }) => {
    ownerA.forbiddenRouteName = `Forbidden Phase C Route ${Date.now().toString(36)}`;
    const deniedCreate = await postJson(
      request,
      '/gateway-routes',
      {
        name: ownerA.forbiddenRouteName,
        provider_id: ownerA.routeId,
        redaction: 'mask',
        config: { model: 'llama-3.1-8b-instant' },
      },
      viewerA.token,
    );
    expect(deniedCreate.status()).toBe(403);

    const tenantARoutes = await request.get(`${apiBase}/gateway-routes`, {
      headers: { Authorization: `Bearer ${ownerA.token}` },
    });
    expect(tenantARoutes.ok(), await tenantARoutes.text()).toBeTruthy();
    const routesBody = await tenantARoutes.text();
    expect(routesBody).not.toContain(ownerA.forbiddenRouteName);

    const crossTenant = await request.get(`${apiBase}/gateway-routes/${ownerB.routeId}`, {
      headers: { Authorization: `Bearer ${ownerA.token}` },
    });
    expect(crossTenant.status()).toBe(404);
    expect(await crossTenant.text()).not.toContain(ownerB.routeName);
  });
});
