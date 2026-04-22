import asyncio
from authtuna.integrations import auth_service

async def run_mfa_example():
    user_id = "user123"
    
    # 1. Start MFA Setup
    # Generates a secret and a provisioning URL (to be converted to QR code)
    secret, qr_url = await auth_service.mfa.setup_totp(user_id, app_name="MySecureApp")
    print(f"Secret: {secret}")
    print(f"QR URL: {qr_url}")
    
    # 2. Verify and Enable
    # The user scans the QR code and enters the 6-digit code from their app
    success = await auth_service.mfa.verify_and_enable_totp(user_id, "123456")
    if success:
        print("MFA enabled successfully!")
    
    # 3. Validation during login
    # When auth_service.login detects MFA is enabled, it returns is_mfa_required=True
    # Then you call verify_code to finalize the session
    is_valid = await auth_service.mfa.verify_code(user_id, "654321")
    print(f"Code valid: {is_valid}")

if __name__ == "__main__":
    asyncio.run(run_mfa_example())
