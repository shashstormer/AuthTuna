"""
I generated these migrations using AI and have not tested them well yet so i recommend to run the migrations manually.
"""

import os
import importlib
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection


async def get_current_version(conn: AsyncConnection) -> int:
    """Checks for a schema_version table and returns the current version."""
    try:
        result = await conn.execute(text("SELECT version_num FROM schema_version"))
        version_row = result.scalar_one_or_none()
        return version_row if version_row is not None else 0
    except Exception:
        # If the table doesn't exist, this is a fresh database (version 0).
        await conn.execute(text("CREATE TABLE schema_version (version_num INTEGER NOT NULL PRIMARY KEY);"))
        await conn.execute(text("INSERT INTO schema_version (version_num) VALUES (0);"))
        return 0


async def set_version(conn: AsyncConnection, version: int):
    """Updates the version number in the schema_version table."""
    await conn.execute(text("UPDATE schema_version SET version_num = :version"), {"version": version})


async def run_migrations(engine):
    """
    Checks the database version and automatically applies all pending migration scripts.
    """
    migration_files = sorted(os.listdir(os.path.join(os.path.dirname(__file__), 'versions')))

    async with engine.begin() as conn:
        current_version = await get_current_version(conn)

        for filename in migration_files:
            if not filename.endswith('.py') or filename.startswith('__'):
                continue

            version_num = int(filename.split('_')[0])

            if version_num > current_version:
                print(f"Applying migration: {filename}")
                module_name = f"authtuna.migrations.versions.{filename[:-3]}"
                migration_module = importlib.import_module(module_name)

                await migration_module.upgrade(conn)
                await set_version(conn, version_num)
                print(f"Successfully applied version {version_num}")
                