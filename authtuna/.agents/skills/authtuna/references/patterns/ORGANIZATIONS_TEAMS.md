# Pattern: Multi-Tenant Organizations and Teams

AuthTuna provides first-class support for multi-tenant applications where users are grouped into Organizations and sub-teams.

## Concept
- **Organization**: A top-level tenant container.
- **Team**: A logical grouping within an organization.
- **Membership**: Users are linked to Orgs/Teams via association tables.
- **Ownership**: Organizations have a primary owner.

## Implementation

### 1. Creating the Structure
Create an organization and then add teams to it.

```python
# Create Organization
org = await auth_service.orgs.create_organization(
    name="Acme Corp", 
    owner=user_admin, 
    ip_address=ip
)

# Create Team within the Org
team = await auth_service.orgs.create_team(
    name="Engineering", 
    org_id=org.id, 
    creator=user_admin, 
    ip_address=ip
)
```

### 2. Managing Members
Invite users to the organization and assign them roles.

```python
# Invite a user
invite = await auth_service.orgs.invite_to_organization(
    org_id=org.id,
    invitee_email="user@acme.com",
    role_name="OrgMember",
    inviter=user_admin,
    ip_address=ip
)
```

### 3. Membership Verification
Check if a user belongs to an organization or team.

```python
# List all members
members = await auth_service.orgs.get_org_members(org.id)

# List teams in an org
teams = await auth_service.orgs.get_org_teams(org.id)

# List teams a user belongs to
user_teams = await auth_service.orgs.get_user_teams(user_id=uid, org_id=org.id)
```

## Scoping with Organizations
It is common practice to scope roles to organization IDs.

```python
# Assign OrgAdmin role scoped to the org ID
await auth_service.roles.assign_to_user(
    user_id=uid,
    role_name="OrgAdmin",
    scope=f"org/{org.id}"
)
```

## Best Practices
- **Auto-Join**: If a user is already registered, `invite_to_organization` can be configured to auto-join them or send a notification.
- **Audit**: Every membership change is logged in the `AuditEvent` trail.
