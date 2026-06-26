from app.core.detection.presidio_engine import PresidioEngine
import asyncio

async def main():
    engine = PresidioEngine()
    await engine.start()
    result = await engine.scan('ravi@gmail.com', {})
    print("Detections:", result.detections)
    print("Sanitized text:", result.sanitized_text)

if __name__ == "__main__":
    asyncio.run(main())
