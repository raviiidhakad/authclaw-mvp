import json
import httpx
from typing import Dict, Any, AsyncGenerator, Tuple
from app.models.provider import Provider
from app.core.providers.base import BaseProviderAdapter
from app.core.encryption import decrypt_value

class AnthropicAdapter(BaseProviderAdapter):
    def validate_configuration(self, config: Dict[str, Any]) -> None:
        pass

    async def get_connection_details(self, provider: Provider) -> Tuple[str, Dict[str, str]]:
        api_key = decrypt_value(provider.api_key_encrypted)
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        return url, headers

    def transform_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        messages = payload.get("messages", [])
        system_msgs = [m["content"] for m in messages if m.get("role") == "system"]
        user_msgs = [m for m in messages if m.get("role") != "system"]
        
        request_payload = {
            "model": payload.get("model", "claude-3-haiku-20240307"),
            "max_tokens": payload.get("max_tokens", 1024),
            "messages": user_msgs,
        }
        if system_msgs:
            request_payload["system"] = " ".join(system_msgs)
            
        if payload.get("stream"):
            request_payload["stream"] = True
            
        return request_payload

    def transform_response(self, response_body: Dict[str, Any]) -> Dict[str, Any]:
        if "content" not in response_body:
            return response_body
            
        text_blocks = [b.get("text", "") for b in response_body.get("content", []) if b.get("type") == "text"]
        return {
            "id": response_body.get("id", ""),
            "object": "chat.completion",
            "model": response_body.get("model", ""),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "\n".join(text_blocks)},
                    "finish_reason": response_body.get("stop_reason", "stop"),
                }
            ],
            "usage": {
                "prompt_tokens": response_body.get("usage", {}).get("input_tokens", 0),
                "completion_tokens": response_body.get("usage", {}).get("output_tokens", 0),
                "total_tokens": (
                    response_body.get("usage", {}).get("input_tokens", 0)
                    + response_body.get("usage", {}).get("output_tokens", 0)
                ),
            },
        }

    async def stream_response(self, response: httpx.Response) -> AsyncGenerator[bytes, None]:
        async for chunk in response.aiter_lines():
            if not chunk or not chunk.startswith("data: "):
                continue
                
            data_str = chunk[len("data: "):].strip()
            if data_str == "[DONE]":
                yield f"data: [DONE]\n\n".encode("utf-8")
                break
                
            try:
                data_json = json.loads(data_str)
            except Exception:
                continue
                
            event_type = data_json.get("type")
            if event_type == "content_block_delta":
                delta = data_json.get("delta", {}).get("text", "")
                if delta:
                    mapped_chunk = {
                        "id": "anthropic-stream",
                        "object": "chat.completion.chunk",
                        "choices": [{"delta": {"content": delta}}]
                    }
                    yield f"data: {json.dumps(mapped_chunk)}\n\n".encode("utf-8")
                    
            elif event_type == "message_stop":
                yield f"data: [DONE]\n\n".encode("utf-8")
                break

    def normalize_error(self, status_code: int, response_body: str) -> Dict[str, Any]:
        try:
            body = json.loads(response_body)
        except Exception:
            body = {"error": {"message": response_body}}
            
        error_info = body.get("error", {})
        return {
            "error": {
                "message": error_info.get("message", "Anthropic provider error"),
                "type": error_info.get("type", "provider_error"),
                "code": str(status_code),
            }
        }
