# AuthTuna Architecture

This document visualizes the core architecture and data flows of AuthTuna.

## Core Component Diagram

The `AuthTunaAsync` facade orchestrates various managers that interact with the database and external services.

```mermaid
graph TD
    Client[Client / FastAPI App] --> Integration[Fastapi Integration Layer]
    Integration --> auth_service[AuthTunaAsync Facade]
    
    subgraph Managers
        auth_service --> users[UserManager]
        auth_service --> roles[RoleManager]
        auth_service --> permissions[PermissionManager]
        auth_service --> mfa[MFAManager]
        auth_service --> passkeys[PasskeyManager]
        auth_service --> api[APIKeyManager]
    end
    
    Managers --> DB[(Database / SQLAlchemy)]
    mfa --> Email[Email Service]
    passkeys --> WebAuthn[Browser WebAuthn API]
```

## Technology Stack

- **Framework**: FastAPI (Python 3.8+)
- **ORM**: SQLAlchemy 2.0 (Async)
- **Supported Databases**: 
    - **PostgreSQL** (via `asyncpg`)
    - **SQLite** (via `aiosqlite`)
    - *Note: Other databases are currently not supported.*
- **Encryption**: Fernet (Cryptography) & Argon2/Bcrypt.
- **SSO**: Authlib (OAuth2/OIDC).

## RBAC Data Model

AuthTuna uses a hierarchical RBAC model with support for scoped assignments.

```mermaid
erDiagram
    USER ||--o{ USER_ROLE : has
    ROLE ||--o{ USER_ROLE : assigned_to
    ROLE ||--o{ ROLE_PERMISSION : contains
    PERMISSION ||--o{ ROLE_PERMISSION : granted_to
    
    USER {
        string id
        string username
        string email
        string password_hash
        boolean is_active
    }
    
    ROLE {
        string id
        string name
        int level
    }
    
    USER_ROLE {
        string user_id
        string role_id
        string scope
    }
    
    PERMISSION {
        string id
        string name
    }
```

## Authentication Flow (With MFA)

```mermaid
sequenceDiagram
    participant User
    participant API as FastAPI / AuthTuna
    participant DB as Database
    
    User->>API: Login(username, password)
    API->>DB: Verify Credentials
    DB-->>API: Valid, MFA Enabled?
    
    alt MFA Required
        API-->>User: 403 (MFA_REQUIRED)
        User->>API: VerifyMFA(code)
        API->>DB: Check TOTP
        DB-->>API: Valid
    end
    
    API->>DB: Create Session / Token
    API-->>User: 200 (Session Cookie / JWT)
```

## Scoped Permission Resolution

How AuthTuna resolves permissions across hierarchical scopes.

```mermaid
graph LR
    UserReq[Request: 'res:read' in 'org/team/project'] --> CheckGlobal[Check 'global' scope]
    CheckGlobal -- Not Found --> CheckOrg[Check 'org' scope]
    CheckOrg -- Not Found --> CheckTeam[Check 'org/team' scope]
    CheckTeam -- Not Found --> CheckProject[Check 'org/team/project' scope]
    
    CheckGlobal -- Found --> Granted[Access Granted]
    CheckOrg -- Found --> Granted
    CheckTeam -- Found --> Granted
    CheckProject -- Found --> Granted
    
    CheckProject -- Not Found --> Denied[Access Denied]
```
