# Security Policy

The security of **AuthTuna** is a top priority. Thank you for helping to keep AuthTuna secure by responsibly disclosing any vulnerabilities you may find.

---

## 🔒 Supported Versions

| Version | Supported |
|---------|:---------:|
| 0.1.x   |     ❌     |
| 0.2.x   |     ✅     |

Security updates are provided for the latest stable version of AuthTuna.
In 0.1.14 there is a security vulnerability that has been patched in 0.2.0, which allowed an attacker with public key to access and manage whatever was available on user dashboard, it has been fixed by giving user a role called User with global scope and using role checker instead of get_current_user.
---

## 🛡️ Reporting a Vulnerability

- **Do not report security vulnerabilities through public GitHub issues.**
- If you discover a security vulnerability, please email: [shashanka5398@gmail.com](mailto:shashanka5398@gmail.com)
- I will respond promptly, acknowledge your report, and work on a fix. The vulnerability will be publicly disclosed once a patch is available.

Thank you for your help and commitment to improving AuthTuna's security!
