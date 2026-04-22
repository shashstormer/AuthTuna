# Pattern: GDPR Privacy and Crypto-Shredding

Ensure compliance with "Right to be Forgotten" (GDPR Art. 17) using advanced cryptographic erasure.

## Concept
- **PII Encryption**: Encrypts emails and other PII fields at rest using a per-user key.
- **Envelope Encryption**: The user's key is itself encrypted (wrapped) with a master system key.
- **Crypto-Shredding**: Instead of just deleting a row, you destroy the user's encryption key. This makes all previously stored data (even in DB backups) mathematically impossible to recover.

## Implementation

### 1. Enable PII Encryption
Enable the feature in your configuration.

```python
# settings.py
PII_ENCRYPTION_ENABLED = True
ENCRYPT_AUDIT_IP = True
PII_HMAC_KEY = "..." # For deterministic lookup
```

### 2. GDPR Erasure
When a user requests to be forgotten, use `erase_user`.

```python
await auth_service.users.erase_user(
    user_id="user123",
    ip_address=ip
)
```

**What happens internally?**
1.  The user's `EncryptionKey` record is fetched.
2.  The `key_ciphertext` is overwritten with random garbage (e.g., `SHREDDED_...`).
3.  The user's email is anonymized (`erased_user_id@erased.invalid`).
4.  All active sessions and MFA methods are purged.

### 3. Auditing
Audit logs can also be encrypted. If `ENCRYPT_AUDIT_IP` is True, the IP addresses in the audit trail are encrypted using the user's key. When the user is "erased", their audit trail IPs also become unreadable.

## Best Practices
- **HMAC for Lookup**: Use `PII_HMAC_KEY` to allow looking up users by email (via hash) without decrypting every record.
- **Backups**: Remember that crypto-shredding is the only way to "delete" data from existing immutable backups.
- **Encryption Key Safety**: If you lose the Master System Key, *all* user PII data becomes unreadable.
