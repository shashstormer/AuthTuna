# Pattern: MFA (TOTP) and Recovery Codes

Add a second layer of security using Time-based One-Time Passwords (TOTP) and emergency recovery codes.

## Concept
- **Setup**: User scans a QR code (containing a secret) into an app like Google Authenticator.
- **Verification**: User provides the current 6-digit code during login.
- **Recovery**: One-time-use backup codes for when the user loses their device.

## Implementation

### 1. Setup Flow
Generate the secret and display the QR URL.

```python
# 1. Start setup
setup_data = await auth_service.mfa.setup_totp(user_id, app_name="MyAuthApp")
# Returns: {"secret": "...", "provisioning_url": "otpauth://..."}

# 2. Verify and Enable
# User enters the 6-digit code from their app
await auth_service.mfa.verify_and_enable_totp(user_id, code="123456")
```

### 2. Login Challenge
When a user logs in with a password, check if MFA is enabled.

```python
user = await auth_service.users.get_by_email(email)
if user and await user.check_password(password, ip_address):
    if user.mfa_enabled:
        # Redirect to MFA challenge page
        return {"status": "mfa_required", "user_id": user.id}
    # Standard login
```

### 3. Verification
In the challenge handler, verify the 6-digit code.
Note: You can verify either a TOTP code (via `pyotp`) or a Recovery Code (via `MFAManager`).

```python
# Verifying a Recovery Code
is_valid_recovery = await auth_service.mfa.verify_recovery_code(user, user_input_code)

# Verifying a TOTP Code (Manual logic)
import pyotp
mfa_method = await get_totp_method_for_user(user.id) # Helper to get secret
totp = pyotp.TOTP(mfa_method.secret)
is_valid_totp = totp.verify(user_input_code)
```

## Security Best Practices
- **Never Store Secrets in Plaintext**: AuthTuna handles the hashing and encryption of MFA secrets.
- **Enforcement**: Allow administrators to mandate MFA for specific roles (e.g., `Admin`).
- **Audit**: Log every successful and failed MFA attempt.

## Best Practices
- **Graceful Onboarding**: Allow users to set up MFA *after* their first login rather than forcing it during signup.
- **Clear Instructions**: Explain how to use the QR code and why recovery codes are critical.
