import pytest
from datetime import timedelta
import uuid
from app.core.security import create_access_token
from app.api.dependencies import get_current_user
from app.core.exceptions import UnauthorizedException
from unittest.mock import AsyncMock

@pytest.mark.asyncio
async def test_mfa_challenge_token_rejected_by_api():
    """
    Test that a token with type="mfa_challenge" is rejected by the get_current_user dependency.
    """
    # Create an MFA Challenge Token
    mfa_token = create_access_token(
        subject=str(uuid.uuid4()), 
        expires_delta=timedelta(minutes=5),
        token_type="mfa_challenge"
    )

    db_mock = AsyncMock()

    # Pass it to get_current_user
    with pytest.raises(UnauthorizedException) as excinfo:
        await get_current_user(db=db_mock, token=mfa_token)
    
    assert "Invalid token type for API access" in str(excinfo.value.detail)

from unittest.mock import AsyncMock, MagicMock

@pytest.mark.asyncio
async def test_access_token_accepted_by_api():
    """
    Test that a normal token with type="access" is NOT rejected by the type checker.
    """
    user_id = str(uuid.uuid4())
    access_token = create_access_token(
        subject=user_id, 
        expires_delta=timedelta(minutes=15),
        token_type="access"
    )

    db_mock = AsyncMock()
    # Mock the DB result
    mock_result = MagicMock()
    mock_user = MagicMock()
    mock_user.id = user_id
    mock_user.is_active = True
    mock_result.scalars().first.return_value = mock_user
    db_mock.execute.return_value = mock_result

    # Should not raise UnauthorizedException for token type
    user = await get_current_user(db=db_mock, token=access_token)
    assert str(user.id) == user_id
