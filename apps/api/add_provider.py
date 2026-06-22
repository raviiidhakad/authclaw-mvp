import asyncio
import os
from sqlalchemy import select, text, delete
from app.core.database import AsyncSessionLocal
from app.models.user import User
from app.models.provider import Provider, ProviderType
from app.core.encryption import encrypt_value

async def main():
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.email == 'root.test1@gmail.com'))
        user = result.scalars().first()
        if not user:
            print('User not found')
            return

        await session.execute(text(f"SET LOCAL app.current_tenant_id = '{str(user.tenant_id)}'"))
        await session.execute(delete(Provider).where(Provider.tenant_id == user.tenant_id))
        
        api_key = os.getenv('GROQ_API_KEY')
        if not api_key:
            raise SystemExit('Set GROQ_API_KEY before running this helper.')
        provider = Provider(
            tenant_id=user.tenant_id,
            name='Groq Default',
            type=ProviderType.groq,
            api_key_encrypted=encrypt_value(api_key),
            config={'model': 'llama-3.3-70b-versatile', 'base_url': 'https://api.groq.com/openai/v1'}
        )
        session.add(provider)
        await session.commit()
        print('Groq Provider added successfully!')

if __name__ == '__main__':
    asyncio.run(main())
