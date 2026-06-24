# AuthClaw Gateway MVP External Agent Calls

These Gateway MVP samples show the intended external-agent path without real secrets. If a Groq, OpenAI, Anthropic, or other provider key was pasted into chat history, logs, screenshots, or an issue, treat it as compromised and rotate it before using live validation.

The caller sends an AuthClaw gateway key, not an upstream provider key:

```bash
curl -sS http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer ac_xxx_replace_with_authclaw_gateway_key" \
  -H "Content-Type: application/json" \
  -d '{
    "route": "default",
    "model": "route-model-or-client-model",
    "messages": [
      {
        "role": "user",
        "content": "A demo user entered person@example.test and it should be protected."
      }
    ]
  }'
```

Expected MVP behavior:

- AuthClaw validates the `ac_...` gateway key and resolves its tenant.
- The configured gateway route selects the provider and may override the model.
- Inbound policy/redaction runs before provider egress.
- The upstream provider credential remains server-side and is never sent by the external agent.
- Responses stay OpenAI-compatible for chat-completion clients.

Do not paste Groq, OpenAI, Anthropic, Cohere, Azure, or other provider keys into the AuthClaw gateway key field.
Live provider validation is disabled by default. Only local/manual validation should set `ENABLE_PROVIDER_LIVE_VALIDATION=true`, `ENABLE_GATEWAY_LIVE_E2E=true`, and a local ignored `GROQ_API_KEY`.

## Python OpenAI SDK-Compatible Client

Use the AuthClaw gateway key as the SDK `api_key`, and point `base_url` at AuthClaw:

```python
from openai import OpenAI

client = OpenAI(
    api_key="ac_xxx_replace_with_authclaw_gateway_key",
    base_url="http://localhost:8000/v1",
)

response = client.chat.completions.create(
    model="route-model-or-client-model",
    messages=[
        {
            "role": "user",
            "content": "A demo user entered person@example.test and it should be protected.",
        }
    ],
    extra_body={"route": "default"},
)

print(response.choices[0].message.content)
```

Provider credentials stay server-side in AuthClaw provider settings. External agents should never receive or send upstream provider API keys.

## Node OpenAI-Compatible HTTP Client

Use the AuthClaw gateway key in the `Authorization` header. The upstream provider key remains only in AuthClaw provider settings.

```js
const response = await fetch("http://localhost:8000/v1/chat/completions", {
  method: "POST",
  headers: {
    "Authorization": "Bearer ac_xxx_replace_with_authclaw_gateway_key",
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    route: "default",
    model: "route-model-or-client-model",
    messages: [
      {
        role: "user",
        content: "A demo user entered person@example.test and it should be protected.",
      },
    ],
  }),
});

const data = await response.json();
console.log(data.choices?.[0]?.message?.content ?? data);
```

Route/model guidance:

- Use `route` when the agent should target a named AuthClaw gateway route.
- The route may override `model` to enforce the tenant-approved provider/model.
- Use only `ac_...` or `authclaw_live_xxx` placeholders in docs, tests, and examples.
- Do not log raw prompts, provider credentials, Vault references, or provider error bodies from live validation.
