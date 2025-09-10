import time
from typing import Tuple, List

import pyotp
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from authtuna.core.database import DatabaseManager, User, MFAMethod, MFARecoveryCode
from authtuna.core.encryption import encryption_utils
from authtuna.core.exceptions import OperationForbiddenError, InvalidTokenError


class MFAManager:
    """
    Manages all Multi-Factor Authentication (MFA) operations, including TOTP
    and recovery codes, in a fully asynchronous manner.
    """

    def __init__(self, db_manager: DatabaseManager):
        self._db_manager = db_manager

    async def setup_totp(self, user: User, issuer_name: str) -> Tuple[str, str]:
        """
        Generates a new TOTP secret for a user and returns the secret and a
        provisioning URI for QR code generation.

        Args:
            user: The User object to set up TOTP for.
            issuer_name: The name of the application to be displayed in the authenticator app.

        Returns:
            A tuple containing the TOTP secret and the provisioning URI.
        """
        if user.mfa_enabled:
            raise OperationForbiddenError("MFA is already enabled for this user.")

        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name=issuer_name)

        async with self._db_manager.get_db() as db:
            # Remove any previous, unverified TOTP setup attempts
            stmt = delete(MFAMethod).where(MFAMethod.user_id == user.id, MFAMethod.method_type == 'totp')
            await db.execute(stmt)

            # Add the new TOTP method
            mfa_method = MFAMethod(user_id=user.id, method_type='totp', secret=secret, is_verified=False)
            db.add(mfa_method)
            await db.commit()

        return secret, provisioning_uri

    async def verify_and_enable_totp(self, user: User, code: str) -> List[str]:
        """
        Verifies a TOTP code to confirm the setup and enables MFA for the user.
        Generates and returns new recovery codes upon successful verification.

        Args:
            user: The user object.
            code: The 6-digit code from the authenticator app.

        Returns:
            A list of plain-text recovery codes to be shown to the user once.
        """
        async with self._db_manager.get_db() as db:
            stmt = select(MFAMethod).where(MFAMethod.user_id == user.id, MFAMethod.method_type == 'totp')
            mfa_method = (await db.execute(stmt)).scalar_one_or_none()

            if not mfa_method or not mfa_method.secret:
                raise InvalidTokenError("TOTP has not been set up for this user.")
            if mfa_method.is_verified:
                raise OperationForbiddenError("MFA is already verified and enabled.")

            totp = pyotp.TOTP(mfa_method.secret)
            if not totp.verify(code):
                raise InvalidTokenError("Invalid TOTP code.")

            # Mark MFA as verified and enabled
            mfa_method.is_verified = True
            user.mfa_enabled = True
            db.add(user)
            db.add(mfa_method)

            # Generate new recovery codes
            recovery_codes = await self._generate_recovery_codes(user.id, db)

            await db.commit()
            return recovery_codes

    async def _generate_recovery_codes(self, user_id: str, db: AsyncSession, num_codes: int = 10) -> List[str]:
        """Internal helper to generate and store hashed recovery codes."""
        # Delete old codes
        await db.execute(delete(MFARecoveryCode).where(MFARecoveryCode.user_id == user_id))

        plain_codes = [f"{encryption_utils.gen_random_string(3)}-{encryption_utils.gen_random_string(3)}-{encryption_utils.gen_random_string(3)}".upper() for _ in range(num_codes)]

        for code in plain_codes:
            hashed_code = encryption_utils.hash_password(code)
            db.add(MFARecoveryCode(user_id=user_id, hashed_code=hashed_code))

        return plain_codes

    async def verify_recovery_code(self, user: User, code: str, db: AsyncSession) -> bool:
        """
        Verifies a recovery code. If valid, it marks the code as used.

        Returns:
            True if the code is valid, False otherwise.
        """
        if db:
            stmt = select(MFARecoveryCode).where(MFARecoveryCode.user_id == user.id, MFARecoveryCode.is_used == False)
            active_codes = (await db.execute(stmt)).scalars().all()
            for recovery_code in active_codes:
                if encryption_utils.verify_password(code, recovery_code.hashed_code):
                    recovery_code.is_used = True
                    recovery_code.actived_at = time.time()
                    db.add(recovery_code)
                    await db.commit()
                    return True

        async with self._db_manager.get_db() as db:
            stmt = select(MFARecoveryCode).where(MFARecoveryCode.user_id == user.id, MFARecoveryCode.is_used == False)
            active_codes = (await db.execute(stmt)).scalars().all()
            for recovery_code in active_codes:
                if encryption_utils.verify_password(code, recovery_code.hashed_code):
                    recovery_code.is_used = True
                    recovery_code.actived_at = time.time()
                    db.add(recovery_code)
                    await db.commit()
                    return True
        return False

    async def disable_mfa(self, user: User) -> None:
        """Disables MFA for a user and deletes all associated methods and codes."""
        async with self._db_manager.get_db() as db:
            user.mfa_enabled = False
            db.add(user)
            await db.execute(delete(MFAMethod).where(MFAMethod.user_id == user.id))
            await db.execute(delete(MFARecoveryCode).where(MFARecoveryCode.user_id == user.id))
            await db.commit()
