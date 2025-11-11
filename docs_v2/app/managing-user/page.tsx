"use client";
import React from "react";
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { Copy, Check, Users, Shield, Search, UserCheck, UserX, Edit, Trash2, Key } from 'lucide-react';

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

export default function ManagingUserPage() {
  return (
    <div className="max-w-[90vw] md:max-w-6xl mx-auto px-4 md:px-6 py-8 pt-16 md:pt-20">
      <div className="text-center mb-8">
        <div className="flex items-center justify-center mb-4">
          <Users className="w-8 h-8 text-blue-600 dark:text-blue-400 mr-3" />
          <h1 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white">Managing Users</h1>
        </div>
        <p className="text-lg text-gray-700 dark:text-gray-300 max-w-3xl mx-auto">
          Master AuthTuna's user management system — from registration to lifecycle management
        </p>
      </div>

      <section className="mb-12">
        <div className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 border-l-4 border-blue-500 p-6 rounded-r-lg mb-8">
          <h2 className="text-xl font-semibold text-blue-900 dark:text-blue-100 mb-3">The Heart of Your Application</h2>
          <p className="text-blue-800 dark:text-blue-200">
            Users are the foundation of your application's identity system. AuthTuna provides comprehensive
            user management capabilities that handle everything from registration and authentication to
            account lifecycle management, all with built-in security, audit trails, and compliance features.
          </p>
        </div>

        <div className="grid md:grid-cols-4 gap-6 mb-8">
          <div className="bg-green-50 dark:bg-green-900/20 p-6 rounded-lg">
            <div className="flex items-center mb-3">
              <UserCheck className="w-6 h-6 text-green-600 dark:text-green-400 mr-2" />
              <h3 className="text-lg font-semibold text-green-900 dark:text-green-100">User CRUD</h3>
            </div>
            <p className="text-green-800 dark:text-green-200 text-sm">
              Complete create, read, update, delete operations with validation and error handling.
            </p>
          </div>

          <div className="bg-purple-50 dark:bg-purple-900/20 p-6 rounded-lg">
            <div className="flex items-center mb-3">
              <Key className="w-6 h-6 text-purple-600 dark:text-purple-400 mr-2" />
              <h3 className="text-lg font-semibold text-purple-900 dark:text-purple-100">Password Management</h3>
            </div>
            <p className="text-purple-800 dark:text-purple-200 text-sm">
              Secure password handling with hashing, validation, and audit logging.
            </p>
          </div>

          <div className="bg-orange-50 dark:bg-orange-900/20 p-6 rounded-lg">
            <div className="flex items-center mb-3">
              <Shield className="w-6 h-6 text-orange-600 dark:text-orange-400 mr-2" />
              <h3 className="text-lg font-semibold text-orange-900 dark:text-orange-100">Account Control</h3>
            </div>
            <p className="text-orange-800 dark:text-orange-200 text-sm">
              Suspend, unsuspend, and manage user account states with proper authorization.
            </p>
          </div>

          <div className="bg-teal-50 dark:bg-teal-900/20 p-6 rounded-lg">
            <div className="flex items-center mb-3">
              <Search className="w-6 h-6 text-teal-600 dark:text-teal-400 mr-2" />
              <h3 className="text-lg font-semibold text-teal-900 dark:text-teal-100">Advanced Search</h3>
            </div>
            <p className="text-teal-800 dark:text-teal-200 text-sm">
              Powerful filtering and search capabilities for user discovery and management.
            </p>
          </div>
        </div>
      </section>

      <section className="mb-12">
        <h2 className="text-2xl font-semibold mb-6 flex items-center">
          <UserCheck className="w-6 h-6 mr-3 text-gray-600 dark:text-gray-400" />
          Creating & Retrieving Users
        </h2>
        <p className="text-gray-700 dark:text-gray-300 mb-6">
          User creation involves validation, security checks, and audit logging. AuthTuna ensures
          data integrity and provides multiple ways to retrieve user information.
        </p>

        <div className="bg-gray-50 dark:bg-gray-900/20 p-6 rounded-lg mb-6">
          <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-gray-100">User Properties</h3>
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <h4 className="font-medium text-gray-700 dark:text-gray-300 mb-2">Required Fields</h4>
              <ul className="text-sm text-gray-600 dark:text-gray-400 space-y-1">
                <li>• <code>id</code> - Auto-generated unique identifier</li>
                <li>• <code>email</code> - Valid email address</li>
                <li>• <code>username</code> - Unique username</li>
              </ul>
            </div>
            <div>
              <h4 className="font-medium text-gray-700 dark:text-gray-300 mb-2">Optional Fields</h4>
              <ul className="text-sm text-gray-600 dark:text-gray-400 space-y-1">
                <li>• <code>password</code> - User password (hashed)</li>
                <li>• <code>is_active</code> - Account status</li>
                <li>• <code>email_verified</code> - Email verification status</li>
                <li>• Custom fields via kwargs</li>
              </ul>
            </div>
          </div>
        </div>

        <h3 className="text-lg font-semibold mb-4">Creating Users</h3>
        <CodeBlock
          language="python"
          code={`from authtuna.integrations import auth_service

user_manager = auth_service.users

# Create a user with password
new_user = await user_manager.create(
    email="john.doe@example.com",
    username="johndoe",
    password="secure_password_123",
    ip_address="192.168.1.100"
)

# Create a user without password (for OAuth/social login)
oauth_user = await user_manager.create(
    email="jane.smith@example.com",
    username="janesmith",
    ip_address="192.168.1.100"
)

print(f"Created user: {new_user.id}")`}
        />

        <h3 className="text-lg font-semibold mb-4">Retrieving Users</h3>
        <CodeBlock
          language="python"
          code={`# Get user by ID (with roles and permissions)
user = await user_manager.get_by_id("user_123", with_relations=True)

# Get user by email
user_by_email = await user_manager.get_by_email("john.doe@example.com")

# Get user by username
user_by_username = await user_manager.get_by_username("johndoe")

# List users with pagination
users = await user_manager.list(skip=0, limit=50)

# Check if user exists
if user:
    print(f"Found user: {user.username} - {user.email}")
    print(f"Roles: {[role.name for role in user.roles]}")
else:
    print("User not found")`}
        />

        <div className="grid md:grid-cols-2 gap-6 mt-6">
          <div className="bg-green-50 dark:bg-green-900/20 p-4 rounded-lg">
            <h4 className="font-semibold text-green-900 dark:text-green-100 mb-2">✅ Validation & Security</h4>
            <ul className="text-sm text-green-800 dark:text-green-200 space-y-1">
              <li>• Email format validation</li>
              <li>• Username uniqueness checks</li>
              <li>• Password strength requirements</li>
              <li>• Automatic audit logging</li>
              <li>• IP address tracking</li>
            </ul>
          </div>

          <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg">
            <h4 className="font-semibold text-red-900 dark:text-red-100 mb-2">❌ Common Errors</h4>
            <ul className="text-sm text-red-800 dark:text-red-200 space-y-1">
              <li>• Duplicate email/username</li>
              <li>• Invalid email format</li>
              <li>• Weak password</li>
              <li>• Missing required fields</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="mb-12">
        <h2 className="text-2xl font-semibold mb-6 flex items-center">
          <Edit className="w-6 h-6 mr-3 text-gray-600 dark:text-gray-400" />
          Updating & Managing User Accounts
        </h2>
        <p className="text-gray-700 dark:text-gray-300 mb-6">
          AuthTuna provides comprehensive user account management with secure updates,
          password management, and account state control.
        </p>

        <div className="grid md:grid-cols-2 gap-8 mb-6">
          <div className="bg-blue-50 dark:bg-blue-900/20 p-6 rounded-lg">
            <h3 className="font-semibold text-blue-900 dark:text-blue-100 mb-3">Updating User Information</h3>
            <CodeBlock
              language="python"
              code={`# Update user profile information
updated_user = await user_manager.update(
    user_id="user_123",
    update_data={
        "username": "new_username",
        "email_verified": True,
        "last_login": datetime.now()
    },
    ip_address="192.168.1.100"
)

# Only certain fields can be updated
# Protected fields: id, password_hash`}
            />
          </div>

          <div className="bg-green-50 dark:bg-green-900/20 p-6 rounded-lg">
            <h3 className="font-semibold text-green-900 dark:text-green-100 mb-3">Password Management</h3>
            <CodeBlock
              language="python"
              code={`# Set a new password for a user
await user_manager.set_password(
    user_id="user_123",
    new_password="new_secure_password_456",
    ip_address="192.168.1.100"
)

# Passwords are automatically hashed
# Previous passwords are invalidated
# Audit trail is created`}
            />
          </div>
        </div>

        <h3 className="text-lg font-semibold mb-4">Account Suspension & Activation</h3>
        <div className="grid md:grid-cols-2 gap-6 mb-6">
          <div className="bg-red-50 dark:bg-red-900/20 p-6 rounded-lg">
            <h3 className="font-semibold text-red-900 dark:text-red-100 mb-3">Suspending Users</h3>
            <CodeBlock
              language="python"
              code={`# Suspend a user account
suspended_user = await user_manager.suspend_user(
    user_id="user_123",
    admin_id="admin_456",
    reason="Violation of terms of service"
)

# User cannot log in while suspended
# All active sessions are invalidated
# Reason is logged for audit purposes`}
            />
          </div>

          <div className="bg-green-50 dark:bg-green-900/20 p-6 rounded-lg">
            <h3 className="font-semibold text-green-900 dark:text-green-100 mb-3">Reactivating Users</h3>
            <CodeBlock
              language="python"
              code={`# Unsuspend a user account
reactivated_user = await user_manager.unsuspend_user(
    user_id="user_123",
    admin_id="admin_456",
    reason="Appeal approved"
)

# User can log in again
# Account status is restored
# Reactivation is logged`}
            />
          </div>
        </div>
      </section>

      <section className="mb-12">
        <h2 className="text-2xl font-semibold mb-6 flex items-center">
          <Search className="w-6 h-6 mr-3 text-gray-600 dark:text-gray-400" />
          Searching & Filtering Users
        </h2>
        <p className="text-gray-700 dark:text-gray-300 mb-6">
          AuthTuna provides powerful search capabilities for finding users based on various criteria,
          with privacy-conscious options for public search interfaces.
        </p>

        <div className="bg-indigo-50 dark:bg-indigo-900/20 border-l-4 border-indigo-500 p-6 rounded-r-lg mb-6">
          <h3 className="font-semibold text-indigo-900 dark:text-indigo-100 mb-2">Advanced User Search</h3>
          <p className="text-indigo-800 dark:text-indigo-200 text-sm mb-3">
            Search users by identity (email/username), role assignments, scope, and account status.
            All filters use AND logic for precise results.
          </p>
          <CodeBlock
            language="python"
            code={`# Search by identity (email or username)
users = await user_manager.search_users(
    identity="john",  # Matches email or username containing "john"
    skip=0,
    limit=20
)

# Search by role
admin_users = await user_manager.search_users(
    role="Admin",
    is_active=True
)

# Search by scope
project_users = await user_manager.search_users(
    scope="project:web-app"
)

# Combine multiple filters
team_members = await user_manager.search_users(
    role="Developer",
    scope="team:frontend",
    is_active=True
)`}
          />
        </div>

        <div className="bg-yellow-50 dark:bg-yellow-900/20 border-l-4 border-yellow-500 p-6 rounded-r-lg mb-6">
          <h3 className="font-semibold text-yellow-900 dark:text-yellow-100 mb-2">Privacy-Aware Search</h3>
          <p className="text-yellow-800 dark:text-yellow-200 text-sm mb-3">
            For public user search interfaces, use <code>basic_search_users</code> which only returns
            usernames and IDs, protecting email privacy.
          </p>
          <CodeBlock
            language="python"
            code={`# Privacy-safe search for user interfaces
basic_results = await user_manager.basic_search_users(
    identity="john",
    skip=0,
    limit=10
)

# Returns only: [{"user_id": "...", "username": "..."}]
# No email addresses or sensitive information

# Example API endpoint
@app.get("/api/users/search")
async def search_users(query: str, current_user=Depends(get_current_user)):
    # Only admins can search with full details
    if "admin" in [role.name for role in current_user.roles]:
        return await user_manager.search_users(identity=query)
    else:
        return await user_manager.basic_search_users(identity=query)`}
          />
        </div>
      </section>

      <section className="mb-12">
        <h2 className="text-2xl font-semibold mb-6 flex items-center">
          <Trash2 className="w-6 h-6 mr-3 text-gray-600 dark:text-gray-400" />
          User Deletion & Data Management
        </h2>
        <p className="text-gray-700 dark:text-gray-300 mb-6">
          User deletion is a sensitive operation that requires careful handling. AuthTuna provides
          safe deletion with data archiving and audit trails.
        </p>

        <div className="bg-red-50 dark:bg-red-900/20 border-l-4 border-red-500 p-6 rounded-r-lg mb-6">
          <h3 className="font-semibold text-red-900 dark:text-red-100 mb-2">Safe User Deletion</h3>
          <p className="text-red-800 dark:text-red-200 text-sm mb-3">
            Deleting users permanently removes their data, but AuthTuna archives user information
            for compliance and audit purposes.
          </p>
          <CodeBlock
            language="python"
            code={`# Delete a user (with archiving)
await user_manager.delete(
    user_id="user_123",
    ip_address="192.168.1.100"
)

# What happens:
# 1. User data is archived to DeletedUser table
# 2. User is removed from main User table
# 3. All associated data (sessions, role assignments) are cleaned up
# 4. Audit event is logged
# 5. Transaction is committed atomically`}
          />
        </div>

        <div className="bg-blue-50 dark:bg-blue-900/20 p-6 rounded-lg">
          <h3 className="font-semibold text-blue-900 dark:text-blue-100 mb-3">Data Archiving Strategy</h3>
          <div className="grid md:grid-cols-2 gap-4 text-sm">
            <div>
              <h4 className="font-medium text-blue-800 dark:text-blue-200 mb-2">What Gets Archived</h4>
              <ul className="text-blue-700 dark:text-blue-300 space-y-1">
                <li>• User ID and email</li>
                <li>• All user profile data</li>
                <li>• Deletion timestamp</li>
                <li>• Deletion reason (if provided)</li>
              </ul>
            </div>
            <div>
              <h4 className="font-medium text-blue-800 dark:text-blue-200 mb-2">What Gets Removed</h4>
              <ul className="text-blue-700 dark:text-blue-300 space-y-1">
                <li>• Password hashes</li>
                <li>• Active sessions</li>
                <li>• Role assignments</li>
                <li>• Personal tokens</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      <section className="mb-12">
        <h2 className="text-2xl font-semibold mb-6">Audit Trails & Compliance</h2>
        <p className="text-gray-700 dark:text-gray-300 mb-6">
          Every user management operation is automatically logged for security, compliance, and debugging purposes.
        </p>

        <div className="bg-green-50 dark:bg-green-900/20 p-6 rounded-lg mb-6">
          <h3 className="font-semibold text-green-900 dark:text-green-100 mb-3">Comprehensive Audit Logging</h3>
          <div className="space-y-4">
            <div className="flex items-start">
              <div className="w-6 h-6 bg-green-500 text-white rounded-full flex items-center justify-center mr-3 mt-1 text-sm font-bold">✓</div>
              <div>
                <h4 className="font-medium text-green-800 dark:text-green-200">User Creation</h4>
                <p className="text-sm text-green-700 dark:text-green-300">Logs who created the account, IP address, and creation method</p>
              </div>
            </div>
            <div className="flex items-start">
              <div className="w-6 h-6 bg-green-500 text-white rounded-full flex items-center justify-center mr-3 mt-1 text-sm font-bold">✓</div>
              <div>
                <h4 className="font-medium text-green-800 dark:text-green-200">Password Changes</h4>
                <p className="text-sm text-green-700 dark:text-green-300">Tracks password updates with IP addresses and timestamps</p>
              </div>
            </div>
            <div className="flex items-start">
              <div className="w-6 h-6 bg-green-500 text-white rounded-full flex items-center justify-center mr-3 mt-1 text-sm font-bold">✓</div>
              <div>
                <h4 className="font-medium text-green-800 dark:text-green-200">Account State Changes</h4>
                <p className="text-sm text-green-700 dark:text-green-300">Logs suspensions, reactivations, and reasons</p>
              </div>
            </div>
            <div className="flex items-start">
              <div className="w-6 h-6 bg-green-500 text-white rounded-full flex items-center justify-center mr-3 mt-1 text-sm font-bold">✓</div>
              <div>
                <h4 className="font-medium text-green-800 dark:text-green-200">Profile Updates</h4>
                <p className="text-sm text-green-700 dark:text-green-300">Records which fields were changed and by whom</p>
              </div>
            </div>
            <div className="flex items-start">
              <div className="w-6 h-6 bg-green-500 text-white rounded-full flex items-center justify-center mr-3 mt-1 text-sm font-bold">✓</div>
              <div>
                <h4 className="font-medium text-green-800 dark:text-green-200">Account Deletion</h4>
                <p className="text-sm text-green-700 dark:text-green-300">Logs deletion with archiving confirmation</p>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-purple-50 dark:bg-purple-900/20 p-6 rounded-lg">
          <h3 className="font-semibold text-purple-900 dark:text-purple-100 mb-3">Querying Audit Logs</h3>
          <CodeBlock
            language="python"
            code={`# Query audit events for a user
user_events = await db_manager.get_audit_logs(
    user_id="user_123",
    event_types=["USER_UPDATED", "USER_SUSPENDED"],
    limit=50
)

# Query by IP address
ip_events = await db_manager.get_audit_logs(
    ip_address="192.168.1.100",
    since=datetime.now() - timedelta(days=7)
)

# Query by admin actions
admin_actions = await db_manager.get_audit_logs(
    event_types=["USER_SUSPENDED", "USER_UNSUSPENDED", "USER_DELETED"],
    limit=100
)`}
          />
        </div>
      </section>

      <section className="mb-12">
        <h2 className="text-2xl font-semibold mb-6">Best Practices & Security</h2>

        <div className="grid md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div className="bg-green-50 dark:bg-green-900/20 p-4 rounded-lg">
              <h4 className="font-semibold text-green-900 dark:text-green-100 mb-2">✅ Security Best Practices</h4>
              <ul className="text-sm text-green-800 dark:text-green-200 space-y-1">
                <li>• Always validate user input</li>
                <li>• Use strong password requirements</li>
                <li>• Implement account lockout policies</li>
                <li>• Log all administrative actions</li>
                <li>• Use IP-based rate limiting</li>
                <li>• Implement two-factor authentication</li>
              </ul>
            </div>

            <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
              <h4 className="font-semibold text-blue-900 dark:text-blue-100 mb-2">🔧 Implementation Tips</h4>
              <ul className="text-sm text-blue-800 dark:text-blue-200 space-y-1">
                <li>• Use transactions for data consistency</li>
                <li>• Implement proper error handling</li>
                <li>• Cache user data appropriately</li>
                <li>• Use background jobs for bulk operations</li>
                <li>• Implement user data export features</li>
              </ul>
            </div>
          </div>

          <div className="space-y-4">
            <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg">
              <h4 className="font-semibold text-red-900 dark:text-red-100 mb-2">❌ Common Pitfalls</h4>
              <ul className="text-sm text-red-800 dark:text-red-200 space-y-1">
                <li>• Storing sensitive data in plain text</li>
                <li>• Not handling concurrent updates</li>
                <li>• Missing audit trails</li>
                <li>• Weak password policies</li>
                <li>• Not implementing proper session management</li>
                <li>• Ignoring GDPR/privacy requirements</li>
              </ul>
            </div>

            <div className="bg-purple-50 dark:bg-purple-900/20 p-4 rounded-lg">
              <h4 className="font-semibold text-purple-900 dark:text-purple-100 mb-2">🛡️ Compliance Considerations</h4>
              <ul className="text-sm text-purple-800 dark:text-purple-200 space-y-1">
                <li>• Implement data retention policies</li>
                <li>• Support user data export/deletion</li>
                <li>• Maintain comprehensive audit logs</li>
                <li>• Implement proper consent management</li>
                <li>• Support account deactivation</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      <div className="bg-gradient-to-r from-blue-50 to-purple-50 dark:from-blue-900/20 dark:to-purple-900/20 p-6 rounded-lg border border-blue-200 dark:border-blue-800">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-3">Key Takeaways</h2>
        <ul className="text-gray-700 dark:text-gray-300 space-y-2">
          <li><strong>Users are Central:</strong> Everything in AuthTuna revolves around user accounts and their lifecycle</li>
          <li><strong>Security First:</strong> Every operation includes validation, authorization checks, and audit logging</li>
          <li><strong>Data Integrity:</strong> Transactions ensure consistency even during complex operations</li>
          <li><strong>Privacy Matters:</strong> Implement privacy-aware search and data handling practices</li>
          <li><strong>Compliance Ready:</strong> Built-in audit trails and data archiving support regulatory requirements</li>
          <li><strong>Scalable Design:</strong> Efficient queries and pagination support large user bases</li>
        </ul>
      </div>
    </div>
  );
}