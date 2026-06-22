from authlib.integrations.starlette_client import OAuth
from app.core.config import settings

oauth = OAuth()

# Google Configuration
if hasattr(settings, 'GOOGLE_CLIENT_ID') and settings.GOOGLE_CLIENT_ID:
    oauth.register(
        name='google',
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
    )

# Azure AD Configuration
if hasattr(settings, 'AZURE_CLIENT_ID') and settings.AZURE_CLIENT_ID:
    oauth.register(
        name='azure',
        client_id=settings.AZURE_CLIENT_ID,
        client_secret=settings.AZURE_CLIENT_SECRET,
        server_metadata_url=f'https://login.microsoftonline.com/{settings.AZURE_TENANT_ID}/v2.0/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
    )

# Okta Configuration
if hasattr(settings, 'OKTA_CLIENT_ID') and settings.OKTA_CLIENT_ID:
    oauth.register(
        name='okta',
        client_id=settings.OKTA_CLIENT_ID,
        client_secret=settings.OKTA_CLIENT_SECRET,
        server_metadata_url=f'https://{settings.OKTA_DOMAIN}/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
    )
