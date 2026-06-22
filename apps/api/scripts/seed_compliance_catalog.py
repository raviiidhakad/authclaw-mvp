from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.database import AsyncSessionLocal
from app.services.compliance_seed_loader import seed_compliance_catalog


async def main() -> None:
    async with AsyncSessionLocal() as db:
        result = await seed_compliance_catalog(db)
    print(
        "Seeded compliance catalog: "
        f"seed_key={result.seed_key} "
        f"frameworks={result.frameworks} "
        f"controls={result.controls} "
        f"requirements={result.requirements} "
        f"checksum={result.checksum[:12]}"
    )


if __name__ == "__main__":
    asyncio.run(main())
