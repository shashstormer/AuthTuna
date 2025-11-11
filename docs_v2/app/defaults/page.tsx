"use client";
import React from "react";
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { Copy, Check, Shield, Users, Key, Settings } from 'lucide-react';

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

export default function DefaultsPage() {
  return (
    <div className="max-w-[90vw] md:max-w-6xl mx-auto px-4 md:px-6 py-8 pt-16 md:pt-20">
      <div className="text-center mb-8">
        <div className="flex items-center justify-center mb-4">
          <Settings className="w-8 h-8 text-blue-600 dark:text-blue-400 mr-3" />
          <h1 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white">Default Provisioning System</h1>
        </div>
        <p className="text-lg text-gray-700 dark:text-gray-300 max-w-3xl mx-auto">
          Understanding AuthTuna&#39;s default users, roles, and permissions — the foundation of your authorization system
        </p>
      </div>

      <section className="mb-12">
        <div className="bg-blue-50 dark:bg-blue-900/20 border-l-4 border-blue-500 p-6 rounded-r-lg mb-8">
          <h2 className="text-xl font-semibold text-blue-900 dark:text-blue-100 mb-3">What is Default Provisioning?</h2>
          <p className="text-blue-800 dark:text-blue-200">
            When AuthTuna starts for the first time, it automatically creates a complete authorization foundation:
            default permissions, roles with proper hierarchies, and system users. This ensures your application
            has a working RBAC (Role-Based Access Control) system from day one.
          </p>
        </div>

        <div className="grid md:grid-cols-2 gap-6 mb-8">
          <div className="bg-green-50 dark:bg-green-900/20 p-6 rounded-lg">
            <div className="flex items-center mb-3">
              <Shield className="w-6 h-6 text-green-600 dark:text-green-400 mr-2" />
              <h3 className="text-lg font-semibold text-green-900 dark:text-green-100">Perfomanze</h3>
            </div>
            <p className="text-green-800 dark:text-green-200 text-sm">
              Provisioning only runs when needed. If system users exist, it skips remaining to avoid waste queries.
              Controlled by <code>TRY_FULL_INITIALIZE_WHEN_SYSTEM_USER_EXISTS_AGAIN</code> setting.
            </p>
          </div>

          <div className="bg-purple-50 dark:bg-purple-900/20 p-6 rounded-lg">
            <div className="flex items-center mb-3">
              <Key className="w-6 h-6 text-purple-600 dark:text-purple-400 mr-2" />
              <h3 className="text-lg font-semibold text-purple-900 dark:text-purple-100">Production Ready</h3>
            </div>
            <p className="text-purple-800 dark:text-purple-200 text-sm">
              Designed for real applications with hierarchical roles, scoped permissions,
              and proper separation between admin and organizational access.
            </p>
          </div>
        </div>
      </section>

      <section className="mb-12">
        <h2 className="text-2xl font-semibold mb-6 flex items-center">
          <Shield className="w-6 h-6 mr-3 text-gray-600 dark:text-gray-400" />
          Default Permissions
        </h2>
        <p className="text-gray-700 dark:text-gray-300 mb-6">
          AuthTuna comes with carefully designed permissions covering administrative access,
          organization management, and team operations. Each permission includes a clear description
          of what it allows.
        </p>

        <div className="overflow-x-auto">
          <table className="min-w-full table-auto border-collapse border border-gray-300 dark:border-gray-600">
            <thead>
              <tr className="bg-gray-100 dark:bg-gray-800">
                <th className="border border-gray-300 dark:border-gray-600 px-4 py-3 text-left font-semibold">Permission</th>
                <th className="border border-gray-300 dark:border-gray-600 px-4 py-3 text-left font-semibold">Description</th>
                <th className="border border-gray-300 dark:border-gray-600 px-4 py-3 text-left font-semibold">Category</th>
              </tr>
            </thead>
            <tbody>
              <tr className="bg-blue-50 dark:bg-blue-900/10">
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3 font-mono text-sm">admin:access:panel</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3">Access the main admin dashboard</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3"><span className="bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 px-2 py-1 rounded text-xs font-medium">Admin</span></td>
              </tr>
              <tr>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3 font-mono text-sm">admin:manage:users</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3">Create, edit, suspend, and delete users</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3"><span className="bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 px-2 py-1 rounded text-xs font-medium">Admin</span></td>
              </tr>
              <tr className="bg-blue-50 dark:bg-blue-900/10">
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3 font-mono text-sm">admin:manage:roles</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3">Create roles and manage role assignment grants</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3"><span className="bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 px-2 py-1 rounded text-xs font-medium">Admin</span></td>
              </tr>
              <tr>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3 font-mono text-sm">admin:manage:permissions</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3">Create permissions and manage permission grant relationships</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3"><span className="bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 px-2 py-1 rounded text-xs font-medium">Admin</span></td>
              </tr>
              <tr className="bg-blue-50 dark:bg-blue-900/10">
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3 font-mono text-sm">roles:assign:SuperAdmin</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3">Permission to assign the SuperAdmin role</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3"><span className="bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 px-2 py-1 rounded text-xs font-medium">Admin</span></td>
              </tr>
              <tr>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3 font-mono text-sm">roles:assign:Admin</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3">Permission to assign the Admin role</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3"><span className="bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 px-2 py-1 rounded text-xs font-medium">Admin</span></td>
              </tr>
              <tr className="bg-blue-50 dark:bg-blue-900/10">
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3 font-mono text-sm">roles:assign:Moderator</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3">Permission to assign the Moderator role</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3"><span className="bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 px-2 py-1 rounded text-xs font-medium">Admin</span></td>
              </tr>
              <tr>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3 font-mono text-sm">roles:assign:User</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3">Permission to assign the User role</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3"><span className="bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 px-2 py-1 rounded text-xs font-medium">Admin</span></td>
              </tr>
              <tr className="bg-green-50 dark:bg-green-900/10">
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3 font-mono text-sm">org:create</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3">Permission to create a new organization</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3"><span className="bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 px-2 py-1 rounded text-xs font-medium">Organization</span></td>
              </tr>
              <tr>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3 font-mono text-sm">org:manage</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3">Permission to edit and delete an organization</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3"><span className="bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 px-2 py-1 rounded text-xs font-medium">Organization</span></td>
              </tr>
              <tr className="bg-green-50 dark:bg-green-900/10">
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3 font-mono text-sm">org:invite_member</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3">Permission to invite new members to an organization</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3"><span className="bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 px-2 py-1 rounded text-xs font-medium">Organization</span></td>
              </tr>
              <tr>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3 font-mono text-sm">org:remove_member</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3">Permission to remove members from an organization</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3"><span className="bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 px-2 py-1 rounded text-xs font-medium">Organization</span></td>
              </tr>
              <tr className="bg-green-50 dark:bg-green-900/10">
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3 font-mono text-sm">team:create</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3">Permission to create a new team within an organization</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3"><span className="bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 px-2 py-1 rounded text-xs font-medium">Team</span></td>
              </tr>
              <tr>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3 font-mono text-sm">team:manage</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3">Permission to edit and delete a team</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3"><span className="bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 px-2 py-1 rounded text-xs font-medium">Team</span></td>
              </tr>
              <tr className="bg-green-50 dark:bg-green-900/10">
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3 font-mono text-sm">team:invite_member</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3">Permission to invite new members to a team</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3"><span className="bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 px-2 py-1 rounded text-xs font-medium">Team</span></td>
              </tr>
              <tr>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3 font-mono text-sm">team:remove_member</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3">Permission to remove members from a team</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3"><span className="bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 px-2 py-1 rounded text-xs font-medium">Team</span></td>
              </tr>
              <tr className="bg-green-50 dark:bg-green-900/10">
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3 font-mono text-sm">team:delete</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3">Permission to delete a team</td>
                <td className="border border-gray-300 dark:border-gray-600 px-4 py-3"><span className="bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 px-2 py-1 rounded text-xs font-medium">Team</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="mb-12">
        <h2 className="text-2xl font-semibold mb-6 flex items-center">
          <Users className="w-6 h-6 mr-3 text-gray-600 dark:text-gray-400" />
          Default Roles & Hierarchy
        </h2>
        <p className="text-gray-700 dark:text-gray-300 mb-6">
          AuthTuna provides a comprehensive role system with both hierarchical admin roles and
          flat organization-based roles. Each role has a level (for hierarchical permissions) and
          comes with pre-assigned permissions.
        </p>

        <div className="grid md:grid-cols-2 gap-8 mb-8">
          <div>
            <h3 className="text-lg font-semibold mb-4 text-red-700 dark:text-red-400">Administrative Roles (Hierarchical)</h3>
            <div className="space-y-4">
              <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg border-l-4 border-red-500">
                <div className="flex justify-between items-start mb-2">
                  <h4 className="font-semibold text-red-900 dark:text-red-100">SuperAdmin (Level 100)</h4>
                  <span className="bg-red-200 dark:bg-red-800 text-red-800 dark:text-red-200 px-2 py-1 rounded text-xs">Highest</span>
                </div>
                <p className="text-red-800 dark:text-red-200 text-sm mb-2">Complete system access including user/role management</p>
                <div className="text-xs text-red-700 dark:text-red-300">
                  <strong>Permissions:</strong> All admin permissions + role assignment powers
                </div>
              </div>

              <div className="bg-orange-50 dark:bg-orange-900/20 p-4 rounded-lg border-l-4 border-orange-500">
                <div className="flex justify-between items-start mb-2">
                  <h4 className="font-semibold text-orange-900 dark:text-orange-100">Admin (Level 90)</h4>
                  <span className="bg-orange-200 dark:bg-orange-800 text-orange-800 dark:text-orange-200 px-2 py-1 rounded text-xs">High</span>
                </div>
                <p className="text-orange-800 dark:text-orange-200 text-sm mb-2">Full administrative access to most features</p>
                <div className="text-xs text-orange-700 dark:text-orange-300">
                  <strong>Permissions:</strong> User/role management, can assign Moderator/Admin roles
                </div>
              </div>

              <div className="bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-lg border-l-4 border-yellow-500">
                <div className="flex justify-between items-start mb-2">
                  <h4 className="font-semibold text-yellow-900 dark:text-yellow-100">Moderator (Level 50)</h4>
                  <span className="bg-yellow-200 dark:bg-yellow-800 text-yellow-800 dark:text-yellow-200 px-2 py-1 rounded text-xs">Medium</span>
                </div>
                <p className="text-yellow-800 dark:text-yellow-200 text-sm mb-2">Can manage users and content</p>
                <div className="text-xs text-yellow-700 dark:text-yellow-300">
                  <strong>Permissions:</strong> User management, basic admin access
                </div>
              </div>
            </div>
          </div>

          <div>
            <h3 className="text-lg font-semibold mb-4 text-green-700 dark:text-green-400">Organization Roles (Flat)</h3>
            <div className="space-y-4">
              <div className="bg-green-50 dark:bg-green-900/20 p-4 rounded-lg border-l-4 border-green-500">
                <div className="flex justify-between items-start mb-2">
                  <h4 className="font-semibold text-green-900 dark:text-green-100">OrgOwner</h4>
                  <span className="bg-green-200 dark:bg-green-800 text-green-800 dark:text-green-200 px-2 py-1 rounded text-xs">Owner</span>
                </div>
                <p className="text-green-800 dark:text-green-200 text-sm mb-2">Full control over an organization</p>
                <div className="text-xs text-green-700 dark:text-green-300">
                  <strong>Permissions:</strong> Manage org, invite/remove members, create/delete teams
                </div>
              </div>

              <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg border-l-4 border-blue-500">
                <div className="flex justify-between items-start mb-2">
                  <h4 className="font-semibold text-blue-900 dark:text-blue-100">OrgAdmin</h4>
                  <span className="bg-blue-200 dark:bg-blue-800 text-blue-800 dark:text-blue-200 px-2 py-1 rounded text-xs">Admin</span>
                </div>
                <p className="text-blue-800 dark:text-blue-200 text-sm mb-2">Can manage organization&#39;s members and teams</p>
                <div className="text-xs text-blue-700 dark:text-blue-300">
                  <strong>Permissions:</strong> Invite/remove members, manage teams
                </div>
              </div>

              <div className="bg-purple-50 dark:bg-purple-900/20 p-4 rounded-lg border-l-4 border-purple-500">
                <div className="flex justify-between items-start mb-2">
                  <h4 className="font-semibold text-purple-900 dark:text-purple-100">TeamLead</h4>
                  <span className="bg-purple-200 dark:bg-purple-800 text-purple-800 dark:text-purple-200 px-2 py-1 rounded text-xs">Lead</span>
                </div>
                <p className="text-purple-800 dark:text-purple-200 text-sm mb-2">Can manage a specific team and its members</p>
                <div className="text-xs text-purple-700 dark:text-purple-300">
                  <strong>Permissions:</strong> Invite/remove team members, manage team
                </div>
              </div>

              <div className="bg-gray-50 dark:bg-gray-900/20 p-4 rounded-lg border-l-4 border-gray-500">
                <div className="flex justify-between items-start mb-2">
                  <h4 className="font-semibold text-gray-900 dark:text-gray-100">User</h4>
                  <span className="bg-gray-200 dark:bg-gray-800 text-gray-800 dark:text-gray-200 px-2 py-1 rounded text-xs">Base</span>
                </div>
                <p className="text-gray-800 dark:text-gray-200 text-sm mb-2">Standard user with basic permissions</p>
                <div className="text-xs text-gray-700 dark:text-gray-300">
                  <strong>Permissions:</strong> Can create organizations (configurable)
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-yellow-50 dark:bg-yellow-900/20 border-l-4 border-yellow-500 p-4 rounded-r-lg">
          <h3 className="font-semibold text-yellow-900 dark:text-yellow-100 mb-2">Role Grant System</h3>
          <p className="text-yellow-800 dark:text-yellow-200 text-sm mb-3">
            Higher-level roles can assign lower-level roles. This creates a natural hierarchy:
          </p>
          <div className="text-sm text-yellow-700 dark:text-yellow-300">
            <strong>SuperAdmin</strong> → Admin, Moderator, OrgOwner, OrgAdmin, TeamLead, OrgMember, User<br/>
            <strong>Admin</strong> → Moderator, OrgOwner, OrgAdmin, TeamLead, OrgMember, User<br/>
            <strong>OrgOwner</strong> → OrgAdmin, TeamLead, OrgMember<br/>
            <strong>OrgAdmin</strong> → TeamLead, OrgMember<br/>
            <strong>TeamLead</strong> → TeamMember
          </div>
        </div>
      </section>

      <section className="mb-12">
        <h2 className="text-2xl font-semibold mb-6 flex items-center">
          <Key className="w-6 h-6 mr-3 text-gray-600 dark:text-gray-400" />
          Default System Users
        </h2>
        <p className="text-gray-700 dark:text-gray-300 mb-6">
          AuthTuna creates three system users by default. The admin users are only created if passwords
          are configured in settings, providing security by default.
        </p>

        <div className="grid md:grid-cols-3 gap-6">
          <div className="bg-red-50 dark:bg-red-900/20 p-6 rounded-lg border border-red-200 dark:border-red-800">
            <div className="flex items-center mb-3">
              <div className="w-10 h-10 bg-red-500 rounded-full flex items-center justify-center mr-3">
                <span className="text-white font-bold text-lg">S</span>
              </div>
              <div>
                <h3 className="font-semibold text-red-900 dark:text-red-100">System</h3>
                <p className="text-sm text-red-700 dark:text-red-300">system@local.host</p>
              </div>
            </div>
            <p className="text-red-800 dark:text-red-200 text-sm mb-3">
              Internal system user for automated processes. Has no password and cannot be logged into directly.
            </p>
            <div className="text-xs text-red-700 dark:text-red-300">
              <strong>Role:</strong> System<br/>
              <strong>ID:</strong> system
            </div>
          </div>

          <div className="bg-blue-50 dark:bg-blue-900/20 p-6 rounded-lg border border-blue-200 dark:border-blue-800">
            <div className="flex items-center mb-3">
              <div className="w-10 h-10 bg-blue-500 rounded-full flex items-center justify-center mr-3">
                <span className="text-white font-bold text-lg">A</span>
              </div>
              <div>
                <h3 className="font-semibold text-blue-900 dark:text-blue-100">SuperAdmin</h3>
                <p className="text-sm text-blue-700 dark:text-blue-300">{`{DEFAULT_SUPERADMIN_EMAIL}`}</p>
              </div>
            </div>
            <p className="text-blue-800 dark:text-blue-200 text-sm mb-3">
              Highest privilege user for system administration. It is always created but cannot be logged in unless <code>DEFAULT_SUPERADMIN_PASSWORD</code> is set when the database is first initialized, they cannot be logged in with passwordless login in and after v0.2.1.
            </p>
            <div className="text-xs text-blue-700 dark:text-blue-300">
              <strong>Roles:</strong> SuperAdmin, User<br/>
              <strong>ID:</strong> default-super-admin
            </div>
          </div>

          <div className="bg-green-50 dark:bg-green-900/20 p-6 rounded-lg border border-green-200 dark:border-green-800">
            <div className="flex items-center mb-3">
              <div className="w-10 h-10 bg-green-500 rounded-full flex items-center justify-center mr-3">
                <span className="text-white font-bold text-lg">A</span>
              </div>
              <div>
                <h3 className="font-semibold text-green-900 dark:text-green-100">Admin</h3>
                <p className="text-sm text-green-700 dark:text-green-300">{`{DEFAULT_ADMIN_EMAIL}`}</p>
              </div>
            </div>
            <p className="text-green-800 dark:text-green-200 text-sm mb-3">
              Standard admin user for day-to-day administration. It is always created but cannot be logged in unless <code>DEFAULT_ADMIN_PASSWORD</code> is set when the database is first initialized, they cannot be logged in with passwordless login in and after v0.2.1.
            </p>
            <div className="text-xs text-green-700 dark:text-green-300">
              <strong>Roles:</strong> Admin, User<br/>
              <strong>ID:</strong> default-admin
            </div>
          </div>
        </div>

        <div className="bg-gray-50 dark:bg-gray-900/20 p-4 rounded-lg mt-6">
          <h3 className="font-semibold text-gray-900 dark:text-gray-100 mb-2">Security Note</h3>
          <p className="text-gray-700 dark:text-gray-300 text-sm">
            By default, admin users are <strong>created</strong> but not <strong>enabled</strong> for login unless passwords are set in the configuration.
            This prevents accidental exposure of admin accounts in development environments.
              Set <code>DEFAULT_SUPERADMIN_PASSWORD</code> and <code>DEFAULT_ADMIN_PASSWORD</code> in
              your settings to enable them.
          </p>
        </div>
      </section>

      <section className="mb-12">
        <h2 className="text-2xl font-semibold mb-6">How Provisioning Works</h2>
        <p className="text-gray-700 dark:text-gray-300 mb-6">
          The provisioning process is idempotent and runs automatically when your AuthTuna application starts.
          Here&#39;s what happens behind the scenes:
        </p>

        <div className="space-y-4">
          <div className="flex items-start">
            <div className="w-8 h-8 bg-blue-500 text-white rounded-full flex items-center justify-center mr-4 mt-1">1</div>
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-gray-100">Check for Existing System</h3>
              <p className="text-gray-700 dark:text-gray-300 text-sm">
                If the system user exists and <code>TRY_FULL_INITIALIZE_WHEN_SYSTEM_USER_EXISTS_AGAIN</code> is False,
                provisioning is skipped entirely.
              </p>
            </div>
          </div>

          <div className="flex items-start">
            <div className="w-8 h-8 bg-blue-500 text-white rounded-full flex items-center justify-center mr-4 mt-1">2</div>
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-gray-100">Create Permissions</h3>
              <p className="text-gray-700 dark:text-gray-300 text-sm">
                All default permissions are created if they don&#39;t exist, ensuring the permission system is complete.
              </p>
            </div>
          </div>

          <div className="flex items-start">
            <div className="w-8 h-8 bg-blue-500 text-white rounded-full flex items-center justify-center mr-4 mt-1">3</div>
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-gray-100">Create Roles</h3>
              <p className="text-gray-700 dark:text-gray-300 text-sm">
                Roles are created with their level, description, and assigned permissions from the role-permission mappings.
              </p>
            </div>
          </div>

          <div className="flex items-start">
            <div className="w-8 h-8 bg-blue-500 text-white rounded-full flex items-center justify-center mr-4 mt-1">4</div>
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-gray-100">Create System Users</h3>
              <p className="text-gray-700 dark:text-gray-300 text-sm">
                System users are created with their predefined roles and credentials (where configured).
              </p>
            </div>
          </div>

          <div className="flex items-start">
            <div className="w-8 h-8 bg-blue-500 text-white rounded-full flex items-center justify-center mr-4 mt-1">5</div>
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-gray-100">Setup Role Grants</h3>
              <p className="text-gray-700 dark:text-gray-300 text-sm">
                Role assignment permissions are configured, allowing higher-level roles to assign lower-level roles.
              </p>
            </div>
          </div>
        </div>

        <div className="mt-8">
          <h3 className="text-lg font-semibold mb-4">Provisioning Code Example</h3>
          <CodeBlock
            language="python"
            code={`from authtuna.core.defaults import provision_defaults
from authtuna.core.database import db_manager

# Run provisioning (typically done automatically on startup)
async with db_manager.get_db() as db:
    await provision_defaults(db)`}
          />
        </div>
      </section>

      <section className="mb-12">
        <h2 className="text-2xl font-semibold mb-6">Customization & Extension</h2>
        <p className="text-gray-700 dark:text-gray-300 mb-6">
          While the defaults provide a solid foundation, you can extend and customize the system to fit your needs.
        </p>

        <div className="grid md:grid-cols-2 gap-6">
          <div className="bg-indigo-50 dark:bg-indigo-900/20 p-6 rounded-lg">
            <h3 className="font-semibold text-indigo-900 dark:text-indigo-100 mb-3">Adding Custom Permissions</h3>
            <p className="text-indigo-800 dark:text-indigo-200 text-sm mb-3">
              Create application-specific permissions for your domain logic.
            </p>
            <CodeBlock
              language="python"
              code={`# Add custom permissions
custom_permissions = {
    "billing:manage": "Manage billing settings",
    "reports:view": "Access analytics reports",
    "api:webhooks": "Configure webhooks"
}

# Create them in your app startup
for name, desc in custom_permissions.items():
    permission = Permission(name=name, description=desc)
    db.add(permission)`}
            />
          </div>

          <div className="bg-teal-50 dark:bg-teal-900/20 p-6 rounded-lg">
            <h3 className="font-semibold text-teal-900 dark:text-teal-100 mb-3">Creating Custom Roles</h3>
            <p className="text-teal-800 dark:text-teal-200 text-sm mb-3">
              Define roles specific to your application&#39;s needs and assign appropriate permissions.
            </p>
            <CodeBlock
              language="python"
              code={`# Create a custom role
analyst_role = Role(
    name="DataAnalyst",
    level=10,
    description="Can access reports and analytics"
)

# Assign permissions
analyst_permissions = ["reports:view", "billing:manage"]
for perm_name in analyst_permissions:
    permission = get_permission_by_name(perm_name)
    analyst_role.permissions.append(permission)`}
            />
          </div>
        </div>
      </section>

      <div className="bg-gradient-to-r from-blue-50 to-purple-50 dark:from-blue-900/20 dark:to-purple-900/20 p-6 rounded-lg border border-blue-200 dark:border-blue-800">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-3">Key Takeaways</h2>
        <ul className="text-gray-700 dark:text-gray-300 space-y-2">
          <li><strong>Production Ready:</strong> The default system provides enterprise-grade RBAC with proper separation of concerns</li>
          <li><strong>Hierarchical & Flat:</strong> Combines hierarchical admin roles with flat organization-based roles</li>
          <li><strong>Secure by Default:</strong> Admin users are disabled unless explicitly configured</li>
          <li><strong>Extensible:</strong> Easy to add custom permissions and roles for your specific use cases</li>
          <li><strong>Idempotent:</strong> Safe to run multiple times without conflicts</li>
        </ul>
      </div>
    </div>
  );
}