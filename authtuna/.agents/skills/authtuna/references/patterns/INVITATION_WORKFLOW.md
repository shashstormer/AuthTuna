# Pattern: Organization Invitation Workflow

Securely invite and onboard users into specific organizations and teams using token-based verification.

## Concept
- **Invitation**: Generates a one-time token linked to an email and a target organization.
- **Onboarding**: The user follows a link, validates the token, and is automatically joined to the organization with a pre-defined role.
- **Auto-Join**: If the user is already logged in, the system can bypass the email step and join them directly.

## Implementation

### 1. Sending an Invitation
Use the `OrganizationManager` to create the invitation.

```python
invite = await auth_service.orgs.invite_to_organization(
    org_id="org_123",
    invitee_email="newuser@example.com",
    role_name="OrgMember", # Role they will get on join
    inviter=admin_user,
    ip_address=ip
)
# This creates a Token in the database with purpose 'org_invite'
```

### 2. Accepting the Invitation
The user clicks a link (e.g., `/auth/org/join?token=...`) which calls the acceptance method.

```python
@app.get("/auth/org/join")
async def join_org(token: str, request: Request):
    try:
        # Validates token and joins the user to the organization
        # Returns (User, Organization)
        user, org = await auth_service.orgs.accept_organization_invite(
            token_id=token, 
            ip_address=request.client.host
        )
        return {"message": f"Successfully joined {org.name}"}
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid or expired invite.")
```

## Advanced Logic: Invites
- **`invite_to_organization`**: For external users or when explicit confirmation is required. If `EMAIL_ENABLED` is False, this method will automatically join the user.

## Audit Trail
Invitations trigger specific audit events:
- `ORG_INVITE_SENT`
- `ORG_INVITE_ACCEPTED`
- `USER_JOINED_ORG`

## Best Practices
- **Token Expiry**: Keep invitation tokens valid for a reasonable period (e.g., 24-48 hours).
- **Graceful Failure**: If the user already belongs to the organization, the system should handle it gracefully without erroring.
- **Role Permissions**: Ensure the `inviter` has the `org:invite_member` permission within the target organization's scope.
