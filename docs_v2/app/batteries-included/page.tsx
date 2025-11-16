export default function BatteriesIncludedPage() {
  return (
    <div className={"max-w-[90vw] md:max-w-6xl mx-auto px-4 md:px-6 py-8 pt-16 md:pt-20"}>
      <h1 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white mb-6">Batteries Included</h1>

      <p className="text-base md:text-lg text-gray-700 dark:text-gray-300 mb-8">
        AuthTuna comes with a comprehensive set of features out of the box, allowing you to focus on building your application rather than reinventing authentication.
      </p>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">Core Authentication</h2>
        <ul className="list-disc list-inside text-gray-700 dark:text-gray-300 space-y-2">
          <li><strong>User Registration & Login:</strong> Secure endpoints for user signup, login, and logout with password hashing and JWT tokens.</li>
          <li><strong>Password Reset:</strong> Built-in password reset flow with email verification.</li>
          <li><strong>Email Verification:</strong> Automatic email verification for new users.</li>
          <li><strong>Session Management:</strong> Automatic session handling with secure cookies and token refresh.</li>
        </ul>
        <div className="mt-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">API Endpoints:</h3>
          <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg font-mono text-sm">
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/auth/signup</code> - User registration</div>
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/auth/login</code> - User login</div>
            <div className="mb-2"><strong>POST/GET</strong> <code className="text-blue-600 dark:text-blue-400">/auth/logout</code> - User logout</div>
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/auth/forgot-password</code> - Password reset request</div>
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/auth/reset-password</code> - Password reset</div>
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/auth/change-password</code> - Change password</div>
            <div className="mb-2"><strong>GET/POST</strong> <code className="text-blue-600 dark:text-blue-400">/auth/user-info</code> - Get user information</div>
            <div><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/auth/verify</code> - Email verification</div>
          </div>
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2 mt-4">UI Pages:</h3>
          <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg font-mono text-sm">
            <div className="mb-2"><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/auth/signup</code> - Registration page</div>
            <div className="mb-2"><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/auth/login</code> - Login page</div>
            <div className="mb-2"><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/auth/forgot-password</code> - Forgot password page</div>
            <div><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/auth/reset-password</code> - Reset password page</div>
          </div>
        </div>
        <div className="mt-4">
          <a href="/getting-started" className="text-blue-600 dark:text-blue-400 hover:underline">→ Get Started with AuthTuna</a>
        </div>
      </section>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">Multi-Factor Authentication (MFA)</h2>
        <ul className="list-disc list-inside text-gray-700 dark:text-gray-300 space-y-2">
          <li><strong>TOTP (Time-based One-Time Password):</strong> Support for authenticator apps like Google Authenticator.</li>
          <li><strong>Backup Codes:</strong> One-time use codes for account recovery.</li>
          <li><strong>MFA Enforcement:</strong> Configurable MFA requirements for users.</li>
        </ul>
        <div className="mt-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">API Endpoints:</h3>
          <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg font-mono text-sm">
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/mfa/setup</code> - Setup MFA for user</div>
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/mfa/verify</code> - Verify MFA code</div>
            <div className="mb-2"><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/mfa/qr-code</code> - Get QR code for TOTP setup</div>
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/mfa/validate-login</code> - Validate MFA during login</div>
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/mfa/disable</code> - Disable MFA</div>
            <div><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/mfa/challenge</code> - Get MFA challenge</div>
          </div>
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2 mt-4">UI Pages:</h3>
          <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg font-mono text-sm">
            <div><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/mfa/setup</code> - MFA setup page</div>
          </div>
        </div>
      </section>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">Social Authentication</h2>
        <ul className="list-disc list-inside text-gray-700 dark:text-gray-300 space-y-2">
          <li><strong>OAuth Providers:</strong> Integration with popular providers like Google, GitHub, Facebook, etc.</li>
          <li><strong>Custom Providers:</strong> Easy to add support for additional OAuth providers.</li>
          <li><strong>Social Account Linking:</strong> Link multiple social accounts to a single user.</li>
        </ul>
        <div className="mt-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">API Endpoints:</h3>
          <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg font-mono text-sm">
            <div className="mb-2"><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/social/{`{provider_name}`}/login</code> - Initiate OAuth login</div>
            <div><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/social/{`{provider_name}`}/callback</code> - OAuth callback handler</div>
          </div>
        </div>
      </section>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">Passkey Authentication</h2>
        <ul className="list-disc list-inside text-gray-700 dark:text-gray-300 space-y-2">
          <li><strong>WebAuthn Support:</strong> Passwordless authentication using biometrics or hardware keys.</li>
          <li><strong>Cross-Platform Compatibility:</strong> Works on desktop and mobile devices.</li>
          <li><strong>Secure & User-Friendly:</strong> Eliminates password-related vulnerabilities.</li>
        </ul>
        <div className="mt-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">API Endpoints:</h3>
          <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg font-mono text-sm">
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/passkey/register-options</code> - Generate registration options</div>
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/passkey/register</code> - Register new passkey</div>
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/passkey/login-options</code> - Generate login options</div>
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/passkey/login</code> - Passwordless login</div>
            <div className="mb-2"><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/passkey/</code> - List user passkeys</div>
            <div className="mb-2"><strong>DELETE</strong> <code className="text-blue-600 dark:text-blue-400">/passkey/{`{credential_id_b64}`}</code> - Delete passkey</div>
            <div><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/passkey/mfa-login</code> - Passkey as MFA</div>
          </div>
        </div>
      </section>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">User Management & Admin</h2>
        <ul className="list-disc list-inside text-gray-700 dark:text-gray-300 space-y-2">
          <li><strong>Admin Dashboard:</strong> Web-based admin interface for managing users and permissions.</li>
          <li><strong>Role-Based Access Control (RBAC):</strong> Flexible permission system with roles and permissions.</li>
          <li><strong>User Profiles:</strong> Built-in user profile management.</li>
          <li><strong>Organization Support:</strong> Multi-tenant organization management.</li>
        </ul>
        <div className="mt-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">API Endpoints:</h3>
          <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg font-mono text-sm">
            <div className="mb-2"><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/admin/users/search</code> - Search and filter users</div>
            <div className="mb-2"><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/admin/users/{`{user_id}`}/details-data</code> - Get user details</div>
            <div className="mb-2"><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/admin/users/{`{user_id}`}/audit-log</code> - Get user audit log</div>
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/admin/users/{`{user_id}`}/suspend</code> - Suspend user</div>
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/admin/users/{`{user_id}`}/unsuspend</code> - Unsuspend user</div>
            <div className="mb-2"><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/admin/roles</code> - List all roles</div>
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/admin/roles</code> - Create role</div>
            <div className="mb-2"><strong>DELETE</strong> <code className="text-blue-600 dark:text-blue-400">/admin/roles/{`{role_name}`}</code> - Delete role</div>
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/admin/roles/{`{role_name}`}/permissions</code> - Add permission to role</div>
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/admin/users/roles/assign</code> - Assign role to user</div>
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/admin/users/roles/revoke</code> - Revoke role from user</div>
            <div className="mb-2"><strong>POST</strong> <code className="text-blue-600 dark:text-blue-400">/admin/permissions</code> - Create permission</div>
            <div className="mb-2"><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/admin/roles/{`{role_name}`}/details-data</code> - Get role details</div>
            <div className="mb-2"><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/admin/assignable-roles</code> - Get assignable roles</div>
            <div><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/admin/users/{`{user_id}`}/assignable-roles</code> - Get assignable roles for user</div>
          </div>
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2 mt-4">UI Pages:</h3>
          <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg font-mono text-sm">
            <div className="mb-2"><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/admin/dashboard</code> - Admin dashboard</div>
            <div className="mb-2"><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/admin/users/{`{user_id}`}</code> - User detail page</div>
            <div><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/admin/roles/{`{role_name}`}</code> - Role detail page</div>
          </div>
        </div>
        <div className="mt-4 space-y-1">
          <div><a href="/creating-roles" className="text-blue-600 dark:text-blue-400 hover:underline">→ Creating Roles</a></div>
          <div><a href="/managing-permissions" className="text-blue-600 dark:text-blue-400 hover:underline">→ Managing Permissions</a></div>
          <div><a href="/managing-user" className="text-blue-600 dark:text-blue-400 hover:underline">→ Managing Users</a></div>
        </div>
      </section>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">API & Integrations</h2>
        <ul className="list-disc list-inside text-gray-700 dark:text-gray-300 space-y-2">
          <li><strong>FastAPI Integration:</strong> Seamless integration with FastAPI applications.</li>
          <li><strong>RESTful API:</strong> Complete REST API for all authentication operations.</li>
          <li><strong>Middleware:</strong> Authentication middleware for protecting routes.</li>
          <li><strong>Dependency Injection:</strong> FastAPI dependencies for user authentication in endpoints.</li>
        </ul>
      </section>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">Security & Monitoring</h2>
        <ul className="list-disc list-inside text-gray-700 dark:text-gray-300 space-y-2">
          <li><strong>Rate Limiting:</strong> Built-in rate limiting for login attempts and API calls.</li>
          <li><strong>Audit Logging:</strong> Comprehensive logging of authentication events.</li>
          <li><strong>Encryption:</strong> Secure encryption for sensitive data.</li>
          <li><strong>Brute Force Protection:</strong> Automatic protection against brute force attacks.</li>
        </ul>
      </section>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">UI & Templates</h2>
        <ul className="list-disc list-inside text-gray-700 dark:text-gray-300 space-y-2">
          <li><strong>Responsive UI:</strong> Modern, responsive user interface components.</li>
          <li><strong>Email Templates:</strong> Customizable HTML email templates.</li>
          <li><strong>Theming:</strong> Easy theming and customization options.</li>
          <li><strong>Dashboard:</strong> User dashboard for account management.</li>
        </ul>
        <div className="mt-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">UI Pages:</h3>
          <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg font-mono text-sm">
            <div className="mb-2"><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/ui/dashboard</code> - User dashboard</div>
            <div><strong>GET</strong> <code className="text-blue-600 dark:text-blue-400">/ui/profile</code> - User profile page</div>
          </div>
        </div>
      </section>
    </div>
  );
}