"use client";
import React from "react";
import {Prism as SyntaxHighlighter} from 'react-syntax-highlighter';
import {oneDark} from 'react-syntax-highlighter/dist/esm/styles/prism';
import {ArrowRight, Check, Copy, Key, Lock, Settings, Shield, UserCheck, Users} from 'lucide-react';

const CodeBlock = ({code, language}: { code: string; language: string }) => {
    const [copied, setCopied] = React.useState(false);
    const copy = async () => {
        await navigator.clipboard.writeText(code);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };
    return (
        <div className="relative group mb-6">
            <button
                onClick={copy}
                aria-label="Copy code"
                className="absolute top-2 right-2 p-2 rounded bg-zinc-800 text-white opacity-0 group-hover:opacity-100 transition-opacity"
            >
                {copied ? <Check size={16}/> : <Copy size={16}/>}
            </button>
            <SyntaxHighlighter language={language} style={oneDark} customStyle={{borderRadius: 8, margin: 0}}>
                {code}
            </SyntaxHighlighter>
        </div>
    );
};

export default function CreatingRolesPage() {
    return (
        <div className="max-w-[90vw] md:max-w-6xl mx-auto px-4 md:px-6 py-8 pt-16 md:pt-20">
            <div className="text-center mb-8">
                <div className="flex items-center justify-center mb-4">
                    <Shield className="w-8 h-8 text-blue-600 dark:text-blue-400 mr-3"/>
                    <h1 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white">Creating & Managing
                        Roles</h1>
                </div>
                <p className="text-lg text-gray-700 dark:text-gray-300 max-w-3xl mx-auto">
                    Master AuthTuna&#39;s role-based access control system — from basic role creation to advanced
                    permission management
                </p>
            </div>

            <section className="mb-12">
                <div
                    className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 border-l-4 border-blue-500 p-6 rounded-r-lg mb-8">
                    <h2 className="text-xl font-semibold text-blue-900 dark:text-blue-100 mb-3">The Power of Roles</h2>
                    <p className="text-blue-800 dark:text-blue-200">
                        Roles are the cornerstone of AuthTuna&#39;s authorization system. They group permissions
                        together,
                        making it easy to manage what users can do. Unlike individual permissions, roles can be assigned
                        with different scopes, enabling fine-grained access control.
                    </p>
                </div>

                <div className="grid md:grid-cols-3 gap-6 mb-8">
                    <div className="bg-green-50 dark:bg-green-900/20 p-6 rounded-lg">
                        <div className="flex items-center mb-3">
                            <Settings className="w-6 h-6 text-green-600 dark:text-green-400 mr-2"/>
                            <h3 className="text-lg font-semibold text-green-900 dark:text-green-100">Permission
                                Bundles</h3>
                        </div>
                        <p className="text-green-800 dark:text-green-200 text-sm">
                            Roles collect related permissions into manageable groups, making authorization logic cleaner
                            and more maintainable.
                        </p>
                    </div>

                    <div className="bg-purple-50 dark:bg-purple-900/20 p-6 rounded-lg">
                        <div className="flex items-center mb-3">
                            <Key className="w-6 h-6 text-purple-600 dark:text-purple-400 mr-2"/>
                            <h3 className="text-lg font-semibold text-purple-900 dark:text-purple-100">Scoped
                                Assignment</h3>
                        </div>
                        <p className="text-purple-800 dark:text-purple-200 text-sm">
                            Assign roles with specific scopes (like &#34;project:123&#34;) to limit access to particular
                            resources or contexts.
                        </p>
                    </div>

                    <div className="bg-orange-50 dark:bg-orange-900/20 p-6 rounded-lg">
                        <div className="flex items-center mb-3">
                            <Users className="w-6 h-6 text-orange-600 dark:text-orange-400 mr-2"/>
                            <h3 className="text-lg font-semibold text-orange-900 dark:text-orange-100">Hierarchical
                                Grants</h3>
                        </div>
                        <p className="text-orange-800 dark:text-orange-200 text-sm">
                            Higher-level roles can assign lower-level roles, creating natural authority hierarchies.
                        </p>
                    </div>
                </div>
            </section>

            <section className="mb-12">
                <h2 className="text-2xl font-semibold mb-6 flex items-center">
                    <Settings className="w-6 h-6 mr-3 text-gray-600 dark:text-gray-400"/>
                    Creating Roles
                </h2>
                <p className="text-gray-700 dark:text-gray-300 mb-6">
                    Creating a role involves defining its properties and assigning appropriate permissions.
                    AuthTuna supports both hierarchical roles (with levels) and flat organizational roles.
                </p>

                <div className="grid md:grid-cols-2 gap-8 mb-8">
                    <div className="bg-gray-50 dark:bg-gray-900/20 p-6 rounded-lg">
                        <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-gray-100">Role Properties</h3>
                        <div className="space-y-3">
                            <div className="flex justify-between items-center">
                                <span className="font-medium text-gray-700 dark:text-gray-300">name</span>
                                <span className="text-sm text-gray-500 dark:text-gray-400">string (required)</span>
                            </div>
                            <div className="flex justify-between items-center">
                                <span className="font-medium text-gray-700 dark:text-gray-300">description</span>
                                <span className="text-sm text-gray-500 dark:text-gray-400">string (optional)</span>
                            </div>
                            <div className="flex justify-between items-center">
                                <span className="font-medium text-gray-700 dark:text-gray-300">level</span>
                                <span className="text-sm text-gray-500 dark:text-gray-400">int (optional)</span>
                            </div>
                            <div className="flex justify-between items-center">
                                <span className="font-medium text-gray-700 dark:text-gray-300">system</span>
                                <span className="text-sm text-gray-500 dark:text-gray-400">bool (default: False)</span>
                            </div>
                        </div>
                    </div>

                    <div className="bg-blue-50 dark:bg-blue-900/20 p-6 rounded-lg">
                        <h3 className="text-lg font-semibold mb-4 text-blue-900 dark:text-blue-100">Role Types</h3>
                        <div className="space-y-4">
                            <div>
                                <h4 className="font-medium text-blue-800 dark:text-blue-200">Hierarchical Roles</h4>
                                <p className="text-sm text-blue-700 dark:text-blue-300">Have a level (1-100) for admin
                                    hierarchies</p>
                            </div>
                            <div>
                                <h4 className="font-medium text-blue-800 dark:text-blue-200">Organizational Roles</h4>
                                <p className="text-sm text-blue-700 dark:text-blue-300">Flat roles for teams/orgs (level
                                    = 0)</p>
                            </div>
                            <div>
                                <h4 className="font-medium text-blue-800 dark:text-blue-200">System Role</h4>
                                <p className="text-sm text-blue-700 dark:text-blue-300">It is a special role for
                                    performing automated processes</p>
                            </div>
                        </div>
                    </div>
                </div>

                <h3 className="text-lg font-semibold mb-4">Creating a Role</h3>
                <CodeBlock
                    language="python"
                    code={`from authtuna.core.database import db_manager
from authtuna.manager.role import RoleManager

role_manager = RoleManager(db_manager)

# Create a hierarchical admin role
admin_role = await role_manager.create(
    name="ContentModerator",
    description="Can moderate user-generated content",
    level=25
)

# Create an organizational role
team_lead_role = await role_manager.create(
    name="TeamLead",
    description="Leads a development team",
    # Organizational roles have no level they do not use the hierarchical system.
    # this is so that if you create a with level > 0 it will give permission to manage all these roles
    # to to prevent this this uses grant system 2 see down for more details
)`}
                />
            </section>

            <section className="mb-12">
                <h2 className="text-2xl font-semibold mb-6 flex items-center">
                    <Key className="w-6 h-6 mr-3 text-gray-600 dark:text-gray-400"/>
                    Assigning Permissions to Roles
                </h2>
                <p className="text-gray-700 dark:text-gray-300 mb-6">
                    Once created, roles need permissions to be useful. AuthTuna allows fine-grained permission
                    assignment
                    with audit trails and validation.
                </p>

                <div className="bg-yellow-50 dark:bg-yellow-900/20 border-l-4 border-yellow-500 p-6 rounded-r-lg mb-6">
                    <h3 className="font-semibold text-yellow-900 dark:text-yellow-100 mb-2">Permission Assignment</h3>
                    <p className="text-yellow-800 dark:text-yellow-200 text-sm">
                        Permissions are assigned to roles, not directly to users. This creates a clean separation
                        between
                        authorization logic and user management.
                    </p>
                </div>

                <CodeBlock
                    language="python"
                    code={`# Assign permissions to our ContentModerator role
await role_manager.add_permission_to_role(
    role_name="ContentModerator",
    permission_name="content:moderate",
    adder_id=current_user.id  # For audit trail
)

await role_manager.add_permission_to_role(
    role_name="ContentModerator",
    permission_name="users:ban",
    adder_id=current_user.id
)

# Assign permissions to TeamLead role
await role_manager.add_permission_to_role(
    role_name="TeamLead",
    permission_name="team:manage_members",
    adder_id=current_user.id
)`}
                />

                <div className="grid md:grid-cols-2 gap-6 mt-6">
                    <div className="bg-green-50 dark:bg-green-900/20 p-4 rounded-lg">
                        <h4 className="font-semibold text-green-900 dark:text-green-100 mb-2">✅ What Happens</h4>
                        <ul className="text-sm text-green-800 dark:text-green-200 space-y-1">
                            <li>• Permission is validated (must exist)</li>
                            <li>• Duplicate assignments are prevented</li>
                            <li>• Audit log entry is created</li>
                            <li>• Database relationship is established</li>
                        </ul>
                    </div>

                    <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg">
                        <h4 className="font-semibold text-red-900 dark:text-red-100 mb-2">❌ Common Mistakes</h4>
                        <ul className="text-sm text-red-800 dark:text-red-200 space-y-1">
                            <li>• Assigning non-existent permissions</li>
                            <li>• Forgetting audit trail (adder_id)</li>
                            <li>• Not handling duplicate assignments</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section className="mb-12">
                <h2 className="text-2xl font-semibold mb-6 flex items-center">
                    <UserCheck className="w-6 h-6 mr-3 text-gray-600 dark:text-gray-400"/>
                    Assigning Roles to Users
                </h2>
                <p className="text-gray-700 dark:text-gray-300 mb-6">
                    Role assignment is the final step that grants users their permissions. AuthTuna supports scoped
                    assignments
                    and includes comprehensive authorization checks.
                </p>

                <h3 className="text-lg font-semibold mb-4">Basic Role Assignment</h3>
                <CodeBlock
                    language="python"
                    code={`# Assign ContentModerator role globally
await role_manager.assign_to_user(
    user_id="user_123",
    role_name="ContentModerator",
    assigner_id=current_user.id,
    scope="global"  # Applies everywhere
)

# Assign TeamLead role with specific scope
await role_manager.assign_to_user(
    user_id="user_456",
    role_name="TeamLead",
    assigner_id=current_user.id,
    scope="team:frontend"  # Only for frontend team
)`}
                />

                <div className="bg-indigo-50 dark:bg-indigo-900/20 border-l-4 border-indigo-500 p-6 rounded-r-lg mb-6">
                    <h3 className="font-semibold text-indigo-900 dark:text-indigo-100 mb-2">Understanding Scopes</h3>
                    <p className="text-indigo-800 dark:text-indigo-200 text-sm mb-3">
                        Scopes limit where a role applies. Use hierarchical scopes
                        like <code>&#34;org:shash/team:frontend&#34;</code>
                        to create fine-grained permissions.
                    </p>
                    <p className="text-indigo-800 dark:text-indigo-200 text-sm mb-3">
                        This allows anyone with role &#34;TeamLead&#34; with scope `org:shash/team:frontend`,
                        or &#34;TeamLead&#34; with scope `org:shash` to perform the action.
                    </p>
                    <div className="text-sm text-indigo-700 dark:text-indigo-300">
                        <strong>Examples:</strong><br/>
                        • <code>&#34;global&#34;</code> - Applies everywhere<br/>
                        • <code>&#34;org:company-a&#34;</code> - Specific organization<br/>
                        • <code>&#34;project:web-app&#34;</code> - Specific project<br/>
                        • <code>&#34;team:design&#34;</code> - Specific team
                    </div>
                </div>
            </section>

            <section className="mb-12">
                <h2 className="text-2xl font-semibold mb-6 flex items-center">
                    <Lock className="w-6 h-6 mr-3 text-gray-600 dark:text-gray-400"/>
                    Authorization Pathways
                </h2>
                <p className="text-gray-700 dark:text-gray-300 mb-6">
                    AuthTuna uses three authorization pathways to determine if a user can assign roles.
                    This multi-layered approach provides flexibility and security.
                </p>

                <div className="space-y-6">
                    <div className="bg-green-50 dark:bg-green-900/20 p-6 rounded-lg">
                        <div className="flex items-start">
                            <div
                                className="w-8 h-8 bg-green-500 text-white rounded-full flex items-center justify-center mr-4 mt-1">1
                            </div>
                            <div>
                                <h3 className="font-semibold text-green-900 dark:text-green-100 mb-2">Permission
                                    Override</h3>
                                <p className="text-green-800 dark:text-green-200 text-sm mb-2">
                                    Direct permission like <code>&#34;roles:assign:Admin&#34;</code> bypasses other
                                    checks.
                                </p>
                                <CodeBlock
                                    language="python"
                                    code={`# User has "roles:assign:Moderator" permission
await role_manager.assign_to_user(
    user_id="target_user",
    role_name="Moderator",  # Allowed via permission
    assigner_id=current_user.id
)`}
                                />
                            </div>
                        </div>
                    </div>

                    <div className="bg-blue-50 dark:bg-blue-900/20 p-6 rounded-lg">
                        <div className="flex items-start">
                            <ArrowRight className="w-6 h-6 text-blue-600 dark:text-blue-400 mr-3 mt-1"/>
                            <div>
                                <h3 className="font-semibold text-blue-900 dark:text-blue-100 mb-2">Direct Role
                                    Grants</h3>
                                <p className="text-blue-800 dark:text-blue-200 text-sm mb-2">
                                    Roles can be configured to allow assignment of other specific roles.
                                </p>
                                <CodeBlock
                                    language="python"
                                    code={`# Configure that Admin can assign Moderator
await role_manager.grant_relationship(
    granter_role_name="Admin",
    grantable_name="Moderator",
    grantable_manager=role_manager,
    relationship_attr="can_assign_roles"
)`}
                                />
                            </div>
                        </div>
                    </div>

                    <div className="bg-purple-50 dark:bg-purple-900/20 p-6 rounded-lg">
                        <div className="flex items-start">
                            <ArrowRight className="w-6 h-6 text-purple-600 dark:text-purple-400 mr-3 mt-1"/>
                            <div>
                                <h3 className="font-semibold text-purple-900 dark:text-purple-100 mb-2">Level
                                    Hierarchy</h3>
                                <p className="text-purple-800 dark:text-purple-200 text-sm mb-2">
                                    Higher-level roles can assign lower-level roles automatically.
                                </p>
                                <CodeBlock
                                    language="python"
                                    code={`# SuperAdmin (level 100) can assign Admin (level 90)
# Admin (level 90) can assign Moderator (level 50)
# But Moderator (level 50) CANNOT assign Admin (level 90)

await role_manager.assign_to_user(
    user_id="target_user",
    role_name="Moderator",  # Allowed via hierarchy
    assigner_id=admin_user.id
)`}
                                />
                            </div>
                        </div>
                    </div>
                </div>

                <div className="bg-gray-50 dark:bg-gray-900/20 p-4 rounded-lg mt-6">
                    <h3 className="font-semibold text-gray-900 dark:text-gray-100 mb-2">Authorization Logic</h3>
                    <p className="text-gray-700 dark:text-gray-300 text-sm">
                        The three pathways are checked in order with OR logic — if ANY pathway allows the assignment,
                        it&#39;s permitted. This provides maximum flexibility while maintaining security.
                    </p>
                </div>
            </section>

            <section className="mb-12">
                <h2 className="text-2xl font-semibold mb-6">Advanced Role Management</h2>

                <div className="grid md:grid-cols-2 gap-6 mb-6">
                    <div className="bg-teal-50 dark:bg-teal-900/20 p-6 rounded-lg">
                        <h3 className="font-semibold text-teal-900 dark:text-teal-100 mb-3">Querying Role
                            Information</h3>
                        <CodeBlock
                            language="python"
                            code={`# Get all roles
all_roles = await role_manager.get_all_roles()

# Get users with a specific role
users_with_role = await role_manager.get_users_for_role(
    role_name="Admin",
    scope="global"
)

# Get roles a user can assign
assignable_roles = await role_manager.get_assignable_roles_for_user(
    target_user_id="user_123",
    assigning_user=current_user
)`}
                        />
                    </div>

                    <div className="bg-orange-50 dark:bg-orange-900/20 p-6 rounded-lg">
                        <h3 className="font-semibold text-orange-900 dark:text-orange-100 mb-3">Removing Roles</h3>
                        <CodeBlock
                            language="python"
                            code={`# Remove a role from a user
await role_manager.remove_from_user(
    user_id="user_123",
    role_name="ContentModerator",
    remover_id=current_user.id,
    scope="global"
)`}
                        />
                    </div>
                </div>
            </section>

            <section className="mb-12">
                <h2 className="text-2xl font-semibold mb-6">Best Practices</h2>

                <div className="grid md:grid-cols-2 gap-6">
                    <div className="space-y-4">
                        <div className="bg-green-50 dark:bg-green-900/20 p-4 rounded-lg">
                            <h4 className="font-semibold text-green-900 dark:text-green-100 mb-2">✅ Do&#39;s</h4>
                            <ul className="text-sm text-green-800 dark:text-green-200 space-y-1">
                                <li>• Use descriptive role names and descriptions</li>
                                <li>• Leverage scopes for fine-grained control</li>
                                <li>• Set appropriate role levels for hierarchies</li>
                                <li>• Always include audit trails (adder_id)</li>
                                <li>• Use permission overrides for exceptions</li>
                            </ul>
                        </div>

                        <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
                            <h4 className="font-semibold text-blue-900 dark:text-blue-100 mb-2">🔧 Naming
                                Conventions</h4>
                            <ul className="text-sm text-blue-800 dark:text-blue-200 space-y-1">
                                <li>• Use PascalCase for role names</li>
                                <li>• Group related permissions by prefix</li>
                                <li>• Use consistent scope patterns</li>
                                <li>• Document role purposes clearly</li>
                            </ul>
                        </div>
                    </div>

                    <div className="space-y-4">
                        <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg">
                            <h4 className="font-semibold text-red-900 dark:text-red-100 mb-2">❌ Don&#39;ts</h4>
                            <ul className="text-sm text-red-800 dark:text-red-200 space-y-1">
                                <li>• Don&#39;t assign permissions directly to users</li>
                                <li>• Don&#39;t use global scope when specific scope works</li>
                                <li>• Don&#39;t skip authorization checks</li>
                                <li>• Don&#39;t create roles without clear purposes</li>
                                <li>• Don&#39;t forget to handle role removal</li>
                            </ul>
                        </div>

                        <div className="bg-purple-50 dark:bg-purple-900/20 p-4 rounded-lg">
                            <h4 className="font-semibold text-purple-900 dark:text-purple-100 mb-2">🛡️ Security
                                Tips</h4>
                            <ul className="text-sm text-purple-800 dark:text-purple-200 space-y-1">
                                <li>• Regularly audit role assignments</li>
                                <li>• Use principle of least privilege</li>
                                <li>• Monitor role assignment patterns</li>
                                <li>• That&#39;s all for now.</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </section>

            <div
                className="bg-gradient-to-r from-blue-50 to-purple-50 dark:from-blue-900/20 dark:to-purple-900/20 p-6 rounded-lg border border-blue-200 dark:border-blue-800">
                <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-3">Key Takeaways</h2>
                <ul className="text-gray-700 dark:text-gray-300 space-y-2">
                    <li><strong>Roles Bundle Permissions:</strong> Create logical groupings of permissions for easier
                        management
                    </li>
                    <li><strong>Scopes Enable Granularity:</strong> Use scoped role assignments for fine-grained access
                        control
                    </li>
                    <li><strong>Three Authorization Pathways:</strong> Permission overrides, direct grants, and level
                        hierarchies work together
                    </li>
                    <li><strong>Always Audit:</strong> Include user IDs in all role operations for proper audit trails
                    </li>
                    <li><strong>Plan Your Hierarchy:</strong> Design role levels and relationships carefully for
                        maintainable systems
                    </li>
                </ul>
            </div>
        </div>
    )
}