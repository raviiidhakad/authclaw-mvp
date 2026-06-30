# AuthClaw Python SDK

The AuthClaw Python SDK provides a typed client for the AuthClaw public gateway
API. It is designed for developers integrating agents, tools, and backend
services with AuthClaw-managed policy enforcement.

## Installation

From the repository:

```bash
pip install ./sdk/python
```

When published to a package index:

```bash
pip install authclaw
```

## Authentication

Use an AuthClaw gateway API key. The SDK reads `AUTHCLAW_API_KEY` by default:

```python
from authclaw import AuthClawClient

client = AuthClawClient()
```

You can also pass a key explicitly:

```python
from authclaw import AuthClawClient

client = AuthClawClient(api_key="ac_your_key", base_url="http://localhost:8000")
```

## Configuration

```python
from authclaw import ApiKeyConfigurationContract, AuthClawClient, AuthClawConfig

config = AuthClawConfig.from_contracts(
    ApiKeyConfigurationContract(
        api_key_env_var="AUTHCLAW_API_KEY",
        base_url="http://localhost:8000",
    )
)
client = AuthClawClient(config=config)
```

## Chat Completions

```python
from authclaw import AuthClawClient, ChatCompletionRequestContract, ChatMessage, MessageRole

client = AuthClawClient()
response = client.create_chat_completion(
    ChatCompletionRequestContract(
        model="llama-3.3-70b-versatile",
        messages=(ChatMessage(role=MessageRole.USER, content="Explain zero trust."),),
    )
)

print(response.choices[0].message.content)
```

## Streaming

```python
from authclaw import AuthClawClient, ChatMessage, MessageRole, StreamingRequestContract

client = AuthClawClient()
stream = client.stream_chat_completion(
    StreamingRequestContract(
        model="llama-3.3-70b-versatile",
        messages=(ChatMessage(role=MessageRole.USER, content="Stream a short answer."),),
    )
)

for event in stream:
    print(event.content, end="")
```

## Retries

Retries are configured through `RetryConfigurationContract` and executed through
the SDK transport abstraction. Streaming is not retried after data begins
flowing.

```python
from authclaw import AuthClawClient, AuthClawConfig, RetryConfigurationContract

config = AuthClawConfig.from_contracts(
    retry=RetryConfigurationContract(max_attempts=3)
)
client = AuthClawClient(config=config)
```

## Timeouts

```python
from authclaw import AuthClawClient, TimeoutConfigurationContract

client = AuthClawClient(
    timeout=TimeoutConfigurationContract(
        connect_timeout_seconds=5,
        read_timeout_seconds=30,
    )
)
```

## Error Handling

```python
from authclaw import AuthClawClient, AuthClawError, RateLimitError

client = AuthClawClient()

try:
    client.health()
except RateLimitError:
    print("Rate limited")
except AuthClawError as exc:
    print(f"AuthClaw SDK error: {exc}")
```

## Compatibility

- SDK version: `0.1.0`
- Supported AuthClaw API version: `v1`
- Minimum compatible AuthClaw release: `0.11.0`
- Python: `>=3.11`

## Versioning Policy

The SDK follows semantic versioning. Contract-breaking changes will require a
major version bump.

## Known Limitations

- Async client support is not implemented.
- Automatic reconnection for interrupted streams is not implemented.
- The SDK does not modify or emulate AuthClaw backend policy behavior.
