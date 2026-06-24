import json
import httpx
from typing import Dict, Any, AsyncGenerator, Tuple
from app.models.provider import Provider
from app.core.providers.base import BaseProviderAdapter
from app.services.provider_credentials import retrieve_provider_api_key
from app.services.api_safety import sanitize_text

class CohereAdapter(BaseProviderAdapter):
    def validate_configuration(self, config: Dict[str, Any]) -> None:
        pass

    async def get_connection_details(self, provider: Provider) -> Tuple[str, Dict[str, str]]:
        api_key = await retrieve_provider_api_key(provider)
        url = "https://api.cohere.ai/v1/chat"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        return url, headers

    def transform_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        messages = payload.get("messages", [])
        
        chat_history = []
        user_message = ""
        
        for msg in messages:
            role = msg.get("role", "").upper()
            if role == "ASSISTANT":
                role = "CHATBOT"
            elif role == "SYSTEM":
                role = "SYSTEM"
            else:
                role = "USER"
                
            content = msg.get("content", "")
            
            # The last user message should be the main message
            if msg == messages[-1] and role == "USER":
                user_message = content
            else:
                chat_history.append({"role": role, "message": content})
                
        request_payload = {
            "model": payload.get("model", "command-r"),
            "message": user_message,
            "chat_history": chat_history,
        }
        
        if payload.get("stream"):
            request_payload["stream"] = True
            
        return request_payload

    def transform_response(self, response_body: Dict[str, Any]) -> Dict[str, Any]:
        text = response_body.get("text", "")
        return {
            "id": response_body.get("generation_id", ""),
            "object": "chat.completion",
            "model": "command-r",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": response_body.get("meta", {}).get("billed_units", {}).get("input_tokens", 0),
                "completion_tokens": response_body.get("meta", {}).get("billed_units", {}).get("output_tokens", 0),
                "total_tokens": (
                    response_body.get("meta", {}).get("billed_units", {}).get("input_tokens", 0)
                    + response_body.get("meta", {}).get("billed_units", {}).get("output_tokens", 0)
                ),
            },
        }

    async def stream_response(self, response: httpx.Response) -> AsyncGenerator[bytes, None]:
        async for chunk in response.aiter_lines():
            if not chunk:
                continue
                
            try:
                data_json = json.loads(chunk)
            except Exception:
                continue
                
            event_type = data_json.get("event_type")
            
            if event_type == "text-generation":
                delta = data_json.get("text", "")
                if delta:
                    mapped_chunk = {
                        "id": "cohere-stream",
                        "object": "chat.completion.chunk",
                        "choices": [{"delta": {"content": delta}}]
                    }
                    yield f"data: {json.dumps(mapped_chunk)}\n\n".encode("utf-8")
                    
            elif event_type == "stream-end":
                yield f"data: [DONE]\n\n".encode("utf-8")
                break

    def normalize_error(self, status_code: int, response_body: str) -> Dict[str, Any]:
        try:
            body = json.loads(response_body)
        except Exception:
            body = {"message": response_body}

        if status_code == 401:
            return {
                "error": {
                    "message": "Provider authentication failed. Update the provider credential in Settings.",
                    "type": "provider_auth_error",
                    "code": "invalid_provider_credentials",
                }
            }
            
        return {
            "error": {
                "message": sanitize_text(body.get("message", "Cohere provider error")),
                "type": "provider_error",
                "code": str(status_code),
            }
        }
