import asyncio
from app.api.v1.endpoints.gateway_routes import GatewayRouteCreate
from pydantic import ValidationError

def test_validation():
    try:
        GatewayRouteCreate(
            name="groq route",
            description="Optional description",
            provider_id=None,
            is_default=True,
            is_active=True,
            redaction="mask",
        )
        print("Validation success")
    except ValidationError as e:
        print("Validation failed:")
        print(e.json())

if __name__ == "__main__":
    test_validation()
