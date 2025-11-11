"use client";
import React from "react";
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { Copy, Check, Shield, Key, Settings, AlertTriangle, CheckCircle, XCircle, Info } from 'lucide-react';

const CodeBlock = ({ code, language }: { code: string; language: string }) => {
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
        {copied ? <Check size={16} /> : <Copy size={16} />}
      </button>
      <SyntaxHighlighter language={language} style={oneDark} customStyle={{ borderRadius: 8, margin: 0 }}>
        {code}
      </SyntaxHighlighter>
    </div>
  );
};

export default function ManagingPermissionsPage() {
  return (
    <div className="max-w-[90vw] md:max-w-6xl mx-auto px-4 md:px-6 py-8 pt-16 md:pt-20">
      <div className="text-center mb-8">
        <div className="flex items-center justify-center mb-4">
          <Key className="w-8 h-8 text-blue-600 dark:text-blue-400 mr-3" />
          <h1 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white">Managing Permissions</h1>
        </div>
        <p className="text-lg text-gray-700 dark:text-gray-300 max-w-3xl mx-auto">
          Master AuthTuna's permission system — the atomic building blocks of your authorization model
        </p>
      </div>

      <section className="mb-12">
        <div className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 border-l-4 border-blue-500 p-6 rounded-r-lg mb-8">
          <h2 className="text-xl font-semibold text-blue-900 dark:text-blue-100 mb-3">The Foundation of Access Control</h2>
          <p className="text-blue-800 dark:text-blue-200">
            Permissions are the granular capabilities that define what actions users can perform in your system.
            They are the atomic units of authorization, representing specific operations like "create a post",
            "delete a user", or "view analytics". Unlike roles, permissions are never assigned directly to users
            — they are always bundled into roles for better management.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-6 mb-8">
          <div className="bg-green-50 dark:bg-green-900/20 p-6 rounded-lg">
            <div className="flex items-center mb-3">
              <Shield className="w-6 h-6 text-green-600 dark:text-green-400 mr-2" />
              <h3 className="text-lg font-semibold text-green-900 dark:text-green-100">Granular Control</h3>
            </div>
            <p className="text-green-800 dark:text-green-200 text-sm">
              Define specific actions users can perform, enabling precise access control down to individual operations.
            </p>
          </div>

          <div className="bg-purple-50 dark:bg-purple-900/20 p-6 rounded-lg">
            <div className="flex items-center mb-3">
              <Settings className="w-6 h-6 text-purple-600 dark:text-purple-400 mr-2" />
              <h3 className="text-lg font-semibold text-purple-900 dark:text-purple-100">Role Composition</h3>
            </div>
            <p className="text-purple-800 dark:text-purple-200 text-sm">
              Permissions are combined into roles, making it easy to manage complex authorization logic through composition.
            </p>
          </div>

          <div className="bg-orange-50 dark:bg-orange-900/20 p-6 rounded-lg">
            <div className="flex items-center mb-3">
              <CheckCircle className="w-6 h-6 text-orange-600 dark:text-orange-400 mr-2" />
              <h3 className="text-lg font-semibold text-orange-900 dark:text-orange-100">Audit Ready</h3>
            </div>
            <p className="text-orange-800 dark:text-orange-200 text-sm">
              Every permission check is logged, providing complete audit trails for security and compliance.
            </p>
          </div>
        </div>
      </section>

      <section className="mb-12">
        <h2 className="text-2xl font-semibold mb-6 flex items-center">
          <Settings className="w-6 h-6 mr-3 text-gray-600 dark:text-gray-400" />
          Creating Permissions
        </h2>
        <p className="text-gray-700 dark:text-gray-300 mb-6">
          Creating permissions involves defining their name and description. AuthTuna validates permissions
          to prevent duplicates and ensures proper naming conventions.
        </p>

        <div className="bg-gray-50 dark:bg-gray-900/20 p-6 rounded-lg mb-6">
          <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-gray-100">Permission Properties</h3>
          <div className="space-y-3">
            <div className="flex justify-between items-center">
              <span className="font-medium text-gray-700 dark:text-gray-300">name</span>
              <span className="text-sm text-gray-500 dark:text-gray-400">string (required)</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="font-medium text-gray-700 dark:text-gray-300">description</span>
              <span className="text-sm text-gray-500 dark:text-gray-400">string (optional)</span>
            </div>
          </div>
        </div>

        <h3 className="text-lg font-semibold mb-4">Creating a Permission</h3>
        <CodeBlock
          language="python"
          code={`from authtuna.integrations import auth_service

permission_manager = auth_service.permissions

# Create a new permission
new_permission = await permission_manager.create(
    name="posts:create",
    description="Allows users to create new blog posts"
)

# Or use get_or_create for idempotent operations
permission, created = await permission_manager.get_or_create(
    name="posts:publish",
    defaults={"description": "Allows publishing posts to make them public"}
)

if created:
    print("Permission was created")
else:
    print("Permission already exists")`}
        />

        <div className="grid md:grid-cols-2 gap-6 mt-6">
          <div className="bg-green-50 dark:bg-green-900/20 p-4 rounded-lg">
            <h4 className="font-semibold text-green-900 dark:text-green-100 mb-2">✅ What Happens</h4>
            <ul className="text-sm text-green-800 dark:text-green-200 space-y-1">
              <li>• Permission name is validated for uniqueness</li>
              <li>• Database record is created with audit trail</li>
              <li>• Permission becomes available for role assignment</li>
              <li>• Transaction is committed atomically</li>
            </ul>
          </div>

          <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg">
            <h4 className="font-semibold text-red-900 dark:text-red-100 mb-2">❌ Common Mistakes</h4>
            <ul className="text-sm text-red-800 dark:text-red-200 space-y-1">
              <li>• Creating duplicate permissions</li>
              <li>• Using inconsistent naming patterns</li>
              <li>• Forgetting descriptive names</li>
              <li>• Not handling creation failures</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="mb-12">
        <h2 className="text-2xl font-semibold mb-6 flex items-center">
          <Info className="w-6 h-6 mr-3 text-gray-600 dark:text-gray-400" />
          Permission Naming Conventions
        </h2>
        <p className="text-gray-700 dark:text-gray-300 mb-6">
          Well-structured permission names make your authorization system maintainable and understandable.
          AuthTuna follows a hierarchical naming pattern that's both readable and scalable.
        </p>

        <div className="bg-blue-50 dark:bg-blue-900/20 border-l-4 border-blue-500 p-6 rounded-r-lg mb-6">
          <h3 className="font-semibold text-blue-900 dark:text-blue-100 mb-2">The Pattern: resource:action</h3>
          <p className="text-blue-800 dark:text-blue-200 text-sm mb-3">
            Use colon-separated hierarchies to organize permissions by resource and action.
            This creates a natural taxonomy that's easy to understand and query.
          </p>
          <div className="text-sm text-blue-700 dark:text-blue-300">
            <strong>Examples:</strong><br/>
            • <code>posts:create</code> - Create blog posts<br/>
            • <code>users:manage</code> - Manage user accounts<br/>
            • <code>reports:view</code> - View analytics reports<br/>
            • <code>org:teams:invite</code> - Invite members to organization teams
          </div>
        </div>

        <div className="grid md:grid-cols-2 gap-6 mb-6">
          <div className="bg-green-50 dark:bg-green-900/20 p-6 rounded-lg">
            <h3 className="font-semibold text-green-900 dark:text-green-100 mb-3">✅ Good Practices</h3>
            <ul className="text-sm text-green-800 dark:text-green-200 space-y-2">
              <li><strong>Use lowercase:</strong> <code>posts:create</code> not <code>Posts:Create</code></li>
              <li><strong>Be specific:</strong> <code>posts:publish</code> not <code>posts:edit</code></li>
              <li><strong>Use hierarchies:</strong> <code>org:teams:manage</code> for nested resources</li>
              <li><strong>Be consistent:</strong> Follow patterns across your application</li>
              <li><strong>Use verbs:</strong> create, read, update, delete, manage, view, etc.</li>
            </ul>
          </div>

          <div className="bg-red-50 dark:bg-red-900/20 p-6 rounded-lg">
            <h3 className="font-semibold text-red-900 dark:text-red-100 mb-3">❌ Anti-Patterns</h3>
            <ul className="text-sm text-red-800 dark:text-red-200 space-y-2">
              <li><strong>Too generic:</strong> <code>admin</code> - what does it allow?</li>
              <li><strong>Mixed case:</strong> <code>Posts:Create</code> - inconsistent</li>
              <li><strong>Too specific:</strong> <code>posts:create:with:image</code> - over-complicated</li>
              <li><strong>UI-focused:</strong> <code>show:admin:panel</code> - describes interface, not capability</li>
            </ul>
          </div>
        </div>

        <div className="bg-yellow-50 dark:bg-yellow-900/20 border-l-4 border-yellow-500 p-6 rounded-r-lg">
          <h3 className="font-semibold text-yellow-900 dark:text-yellow-100 mb-2">Real-World Examples</h3>
          <div className="grid md:grid-cols-2 gap-4 text-sm">
            <div>
              <h4 className="font-medium text-yellow-800 dark:text-yellow-200 mb-2">Blog Platform</h4>
              <ul className="text-yellow-700 dark:text-yellow-300 space-y-1">
                <li>• <code>posts:create</code></li>
                <li>• <code>posts:edit</code></li>
                <li>• <code>posts:publish</code></li>
                <li>• <code>comments:moderate</code></li>
              </ul>
            </div>
            <div>
              <h4 className="font-medium text-yellow-800 dark:text-yellow-200 mb-2">E-commerce</h4>
              <ul className="text-yellow-700 dark:text-yellow-300 space-y-1">
                <li>• <code>products:manage</code></li>
                <li>• <code>orders:view</code></li>
                <li>• <code>inventory:update</code></li>
                <li>• <code>customers:support</code></li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      <section className="mb-12">
        <h2 className="text-2xl font-semibold mb-6 flex items-center">
          <Shield className="w-6 h-6 mr-3 text-gray-600 dark:text-gray-400" />
          Permission Validation & Security
        </h2>
        <p className="text-gray-700 dark:text-gray-300 mb-6">
          AuthTuna includes comprehensive validation and security measures to ensure your permission system
          remains robust and secure.
        </p>

        <div className="space-y-6">
          <div className="bg-green-50 dark:bg-green-900/20 p-6 rounded-lg">
            <div className="flex items-start">
              <div className="w-8 h-8 bg-green-500 text-white rounded-full flex items-center justify-center mr-4 mt-1">1</div>
              <div>
                <h3 className="font-semibold text-green-900 dark:text-green-100 mb-2">Uniqueness Validation</h3>
                <p className="text-green-800 dark:text-green-200 text-sm mb-2">
                  Permission names must be unique across your entire system. AuthTuna prevents duplicate permissions
                  to avoid confusion and security issues.
                </p>
                <CodeBlock
                  language="python"
                  code={`# This will raise ValueError if permission already exists
try:
    permission = await permission_manager.create("posts:create", "Create posts")
except ValueError as e:
    print(f"Permission creation failed: {e}")

# Use get_or_create for safe operations
permission, created = await permission_manager.get_or_create("posts:create")
if not created:
    print("Permission already exists - no action needed")`}
                />
              </div>
            </div>
          </div>

          <div className="bg-blue-50 dark:bg-blue-900/20 p-6 rounded-lg">
            <div className="flex items-start">
              <div className="w-8 h-8 bg-blue-500 text-white rounded-full flex items-center justify-center mr-4 mt-1">2</div>
              <div>
                <h3 className="font-semibold text-blue-900 dark:text-blue-100 mb-2">Audit Trail</h3>
                <p className="text-blue-800 dark:text-blue-200 text-sm mb-2">
                  Every permission creation is logged with timestamps and user information for complete audit trails.
                </p>
                <CodeBlock
                  language="python"
                  code={`# Permission creation automatically logs:
# - Who created the permission
# - When it was created
# - Permission name and description
# - Any errors or validation failures

# View audit logs
audit_logs = await db_manager.get_audit_logs(
    action="PERMISSION_CREATED",
    limit=50
)`}
                />
              </div>
            </div>
          </div>

          <div className="bg-purple-50 dark:bg-purple-900/20 p-6 rounded-lg">
            <div className="flex items-start">
              <div className="w-8 h-8 bg-purple-500 text-white rounded-full flex items-center justify-center mr-4 mt-1">3</div>
              <div>
                <h3 className="font-semibold text-purple-900 dark:text-purple-100 mb-2">Input Sanitization</h3>
                <p className="text-purple-800 dark:text-purple-200 text-sm mb-2">
                  Permission names are validated and sanitized to prevent injection attacks and ensure system stability.
                </p>
                <CodeBlock
                  language="python"
                  code={`# AuthTuna validates permission names:
# - No special characters that could cause issues
# - Reasonable length limits
# - Proper formatting (lowercase, colons, hyphen, underscore allowed)
# - No SQL injection vectors
`}
                />
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="mb-12">
        <h2 className="text-2xl font-semibold mb-6">Permission Lifecycle</h2>
        <p className="text-gray-700 dark:text-gray-300 mb-6">
          Understanding how permissions flow through your system helps you design better authorization logic.
        </p>

        <div className="bg-indigo-50 dark:bg-indigo-900/20 p-6 rounded-lg mb-6">
          <h3 className="font-semibold text-indigo-900 dark:text-indigo-100 mb-4">The Permission Flow</h3>
          <div className="space-y-4">
            <div className="flex items-start">
              <div className="w-6 h-6 bg-indigo-500 text-white rounded-full flex items-center justify-center mr-3 mt-1 text-sm font-bold">1</div>
              <div>
                <h4 className="font-medium text-indigo-800 dark:text-indigo-200">Creation</h4>
                <p className="text-sm text-indigo-700 dark:text-indigo-300">Permissions are created with names and descriptions</p>
              </div>
            </div>
            <div className="flex items-start">
              <div className="w-6 h-6 bg-indigo-500 text-white rounded-full flex items-center justify-center mr-3 mt-1 text-sm font-bold">2</div>
              <div>
                <h4 className="font-medium text-indigo-800 dark:text-indigo-200">Assignment to Roles</h4>
                <p className="text-sm text-indigo-700 dark:text-indigo-300">Permissions are bundled into roles for user assignment</p>
              </div>
            </div>
            <div className="flex items-start">
              <div className="w-6 h-6 bg-indigo-500 text-white rounded-full flex items-center justify-center mr-3 mt-1 text-sm font-bold">3</div>
              <div>
                <h4 className="font-medium text-indigo-800 dark:text-indigo-200">Role Assignment to Users</h4>
                <p className="text-sm text-indigo-700 dark:text-indigo-300">Users receive permissions through role assignments</p>
              </div>
            </div>
            <div className="flex items-start">
              <div className="w-6 h-6 bg-indigo-500 text-white rounded-full flex items-center justify-center mr-3 mt-1 text-sm font-bold">4</div>
              <div>
                <h4 className="font-medium text-indigo-800 dark:text-indigo-200">Permission Checks</h4>
                <p className="text-sm text-indigo-700 dark:text-indigo-300">Application code checks user permissions for operations</p>
              </div>
            </div>
          </div>
        </div>

        <div className="grid md:grid-cols-2 gap-6">
          <div className="bg-teal-50 dark:bg-teal-900/20 p-6 rounded-lg">
            <h3 className="font-semibold text-teal-900 dark:text-teal-100 mb-3">Querying Permissions</h3>
            <CodeBlock
              language="python"
              code={`# Get a permission by name
permission = await permission_manager.get_by_name("posts:create")

# Check if permission exists
if permission:
    print(f"Found: {permission.name} - {permission.description}")
else:
    print("Permission not found")

# Get or create pattern
perm, created = await permission_manager.get_or_create(
    "analytics:view",
    defaults={"description": "View analytics dashboard"}
)`}
            />
          </div>

          <div className="bg-orange-50 dark:bg-orange-900/20 p-6 rounded-lg">
            <h3 className="font-semibold text-orange-900 dark:text-orange-100 mb-3">Integration with Roles</h3>
            <CodeBlock
              language="python"
              code={`# Permissions are assigned to roles, not users
await role_manager.add_permission_to_role(
    role_name="ContentEditor",
    permission_name="posts:create",
    adder_id=current_user.id
)

# Users get permissions through roles
await role_manager.assign_to_user(
    user_id="user_123",
    role_name="ContentEditor",
    assigner_id=admin_user.id
)

# Now user_123 has posts:create permission`}
/>
          </div>
        </div>
      </section>

      <section className="mb-12">
        <h2 className="text-2xl font-semibold mb-6">Best Practices & Security</h2>

        <div className="grid md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div className="bg-green-50 dark:bg-green-900/20 p-4 rounded-lg">
              <h4 className="font-semibold text-green-900 dark:text-green-100 mb-2">✅ Design Principles</h4>
              <ul className="text-sm text-green-800 dark:text-green-200 space-y-1">
                <li>• Use principle of least privilege</li>
                <li>• Keep permissions granular but not microscopic</li>
                <li>• Document permission purposes clearly</li>
                <li>• Plan permission hierarchies upfront</li>
                <li>• Use consistent naming across your app</li>
              </ul>
            </div>

            <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
              <h4 className="font-semibold text-blue-900 dark:text-blue-100 mb-2">🔧 Implementation Tips</h4>
              <ul className="text-sm text-blue-800 dark:text-blue-200 space-y-1">
                <li>• Create permissions during app startup</li>
                <li>• Use get_or_create for safe initialization</li>
                <li>• Validate permissions before use</li>
                <li>• Log permission-related operations</li>
                <li>• Test permission checks thoroughly</li>
              </ul>
            </div>
          </div>

          <div className="space-y-4">
            <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg">
              <h4 className="font-semibold text-red-900 dark:text-red-100 mb-2">❌ Common Pitfalls</h4>
              <ul className="text-sm text-red-800 dark:text-red-200 space-y-1">
                <li>• Creating too many fine-grained permissions</li>
                <li>• Assigning permissions directly to users</li>
                <li>• Using inconsistent naming patterns</li>
                <li>• Forgetting to handle permission failures</li>
                <li>• Not auditing permission changes</li>
              </ul>
            </div>

            <div className="bg-purple-50 dark:bg-purple-900/20 p-4 rounded-lg">
              <h4 className="font-semibold text-purple-900 dark:text-purple-100 mb-2">🛡️ Security Considerations</h4>
              <ul className="text-sm text-purple-800 dark:text-purple-200 space-y-1">
                <li>• Regularly review permission assignments</li>
                <li>• Monitor for privilege escalation attempts</li>
                <li>• Use scopes to limit permission scope</li>
                <li>• Implement permission expiration where needed</li>
                <li>• Audit all permission management operations</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      <div className="bg-gradient-to-r from-blue-50 to-purple-50 dark:from-blue-900/20 dark:to-purple-900/20 p-6 rounded-lg border border-blue-200 dark:border-blue-800">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-3">Key Takeaways</h2>
        <ul className="text-gray-700 dark:text-gray-300 space-y-2">
          <li><strong>Permissions are Atomic:</strong> They represent the smallest units of authorization in your system</li>
          <li><strong>Always Use Roles:</strong> Never assign permissions directly to users — bundle them into roles</li>
          <li><strong>Consistent Naming:</strong> Use hierarchical patterns like <code>resource:action</code> for clarity</li>
          <li><strong>Validate Everything:</strong> AuthTuna prevents duplicates and validates inputs for security</li>
          <li><strong>Audit Everything:</strong> Every permission operation is logged for compliance and debugging</li>
        </ul>
      </div>
    </div>
  );
}