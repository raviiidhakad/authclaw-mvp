import pytest
import inspect
from typing import Dict, Any, AsyncGenerator, Tuple

from app.models.provider import ProviderType
from app.core.providers.base import BaseProviderAdapter
from app.core.providers.factory import ProviderAdapterFactory

def test_all_providers_have_adapters():
    """Ensure every ProviderType enum value has a mapped adapter."""
    for provider_type in ProviderType:
        adapter = ProviderAdapterFactory.get_adapter(provider_type)
        assert isinstance(adapter, BaseProviderAdapter)

def test_adapter_contract_signatures():
    """Ensure every adapter strictly implements the required methods with correct signatures."""
    required_methods = {
        "validate_configuration": ["config"],
        "get_connection_details": ["provider"],
        "transform_request": ["payload"],
        "transform_response": ["response_body"],
        "stream_response": ["response"],
        "normalize_error": ["status_code", "response_body"]
    }

    for provider_type in ProviderType:
        adapter = ProviderAdapterFactory.get_adapter(provider_type)
        
        for method_name, expected_params in required_methods.items():
            assert hasattr(adapter, method_name), f"{adapter.__class__.__name__} missing {method_name}"
            
            method = getattr(adapter, method_name)
            sig = inspect.signature(method)
            params = list(sig.parameters.keys())
            
            assert params == expected_params, f"{adapter.__class__.__name__}.{method_name} has signature {params}, expected {expected_params}"

def test_cohere_adapter_request_transform():
    from app.core.providers.adapters.cohere import CohereAdapter
    adapter = CohereAdapter()
    
    payload = {
        "model": "command-r",
        "stream": True,
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello!"}
        ]
    }
    
    transformed = adapter.transform_request(payload)
    
    assert transformed["model"] == "command-r"
    assert transformed["stream"] is True
    assert transformed["message"] == "Hello!"
    assert len(transformed["chat_history"]) == 1
    assert transformed["chat_history"][0]["role"] == "SYSTEM"
    assert transformed["chat_history"][0]["message"] == "You are a helpful assistant."

def test_anthropic_adapter_request_transform():
    from app.core.providers.adapters.anthropic import AnthropicAdapter
    adapter = AnthropicAdapter()
    
    payload = {
        "model": "claude-3-opus",
        "messages": [
            {"role": "system", "content": "You are an assistant."},
            {"role": "user", "content": "Ping!"}
        ]
    }
    
    transformed = adapter.transform_request(payload)
    
    assert transformed["model"] == "claude-3-opus"
    assert transformed["system"] == "You are an assistant."
    assert len(transformed["messages"]) == 1
    assert transformed["messages"][0]["role"] == "user"
