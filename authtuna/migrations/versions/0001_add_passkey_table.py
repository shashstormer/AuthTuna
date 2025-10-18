# authtuna/migrations/versions/0001_add_passkey_table.py

"""
0.1.8 to 0.1.9
"""
from sqlalchemy import text

async def upgrade(conn):
    """
    Adds the passkey_credentials  relationship to the users table.

    The passkey_credentials table is auto created.

    This is only required if you ran the 0.1.8 library not required if you started using the library from version 0.1.9 onwards as it auto creates this for you.
    """
    await conn.execute(text("CREATE INDEX ix_passkey_credentials_user_id ON passkey_credentials (user_id);"))
