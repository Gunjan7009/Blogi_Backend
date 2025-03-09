from main import Base, engine
import asyncio

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("✅ Tables created successfully!")
    
asyncio.run(init_db())
