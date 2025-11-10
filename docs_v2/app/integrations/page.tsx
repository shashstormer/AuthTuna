"use client";
import React from "react";
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { Copy, Check } from 'lucide-react';

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

export default function FastapiIntegrationDocs() {
  return (
    <div className="max-w-[90vw] md:max-w-4xl mx-auto px-4 md:px-6 py-8 pt-16 md:pt-20">
      <h1 className="text-3xl md:text-4xl font-bold mb-4">FastAPI integration — dependency reference</h1>

      <p className="text-base text-gray-700 dark:text-gray-300 mb-6">
        This page documents the main FastAPI helpers exported by <code className="bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">authtuna.integrations.fastapi_integration</code>.
        Each entry shows the purpose, available options, and copyable examples (cookie sessions and bearer/API-key flows).
      </p>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold mb-3">Quick import</h2>
        <CodeBlock
          language="python"
          code={`from fastapi import FastAPI, Depends, Request

from authtuna.integrations.fastapi_integration import (
    get_current_user,
    get_current_user_optional,
    get_user_ip,
    resolve_token_method,
    PermissionChecker,
    RoleChecker,
)

app = FastAPI()`}
        />
      </section>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold mb-3">Dependency: get_current_user(request, allow_public_key=False)</h2>
        <p className="mb-2 text-gray-700 dark:text-gray-300">
          Returns the authenticated <code>User</code> instance. Supports two authentication methods:
          - COOKIE (session middleware must populate <code>request.state.user_id</code>)
          - BEARER (Authorization: Bearer &lt;api_key&gt;)
        </p>

        <h3 className="text-lg font-medium mt-3 mb-2">Options</h3>
        <ul className="list-disc list-inside text-gray-700 dark:text-gray-300 mb-4">
          <li><strong>allow_public_key</strong> (bool, default False) — if True, publishable API keys (prefix <code>API_KEY_PREFIX_PUBLISHABLE</code>) are allowed; otherwise the function rejects them with 403.</li>
        </ul>

        <h3 className="text-lg font-medium mb-2">Examples</h3>
        <CodeBlock
          language="python"
          code={`# Cookie-backed session (requires session middleware)
@app.get('/dashboard')
async def dashboard(user = Depends(get_current_user)):
    return {"welcome": f"Hello {user.email}"}

# Allow publishable keys for a public endpoint (use carefully)
@app.get('/public-data')
async def public_data(user = Depends(lambda req: get_current_user(req, allow_public_key=True))):
    return {"ok": True}`}
        />

        <p className="text-sm text-gray-600 dark:text-gray-400">Note: the second example shows using a small wrapper to pass the option — you can create a reusable dependency factory in your app for that pattern.</p>
      </section>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold mb-3">Dependency: get_current_user_optional(request)</h2>
        <p className="mb-2 text-gray-700 dark:text-gray-300">Same behavior as <code>get_current_user</code> but returns <code>None</code> when the request is unauthenticated instead of raising an HTTP error. Useful for endpoints that accept both anonymous and authenticated visitors.</p>

        <CodeBlock
          language="python"
          code={`@app.get('/home')
async def home(user = Depends(get_current_user_optional)):
    if user:
        return {"message": f"Welcome back {user.email}"}
    return {"message": "Welcome, please sign in"}`}
        />
      </section>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold mb-3">Dependency: get_user_ip(request)</h2>
        <p className="mb-2 text-gray-700 dark:text-gray-300">Returns the resolved IP address (populated by the session middleware). Use this for logging, rate limiting, or region-locking decisions.</p>

        <CodeBlock
          language="python"
          code={`@app.get('/whoami')
async def whoami(ip: str = Depends(get_user_ip)):
    return {"ip": ip}`}
        />
      </section>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold mb-3">Utility: resolve_token_method(request)</h2>
        <p className="mb-2 text-gray-700 dark:text-gray-300">Returns the token method inferred for the request: <code>"COOKIE"</code>, <code>"BEARER"</code>, or <code>None</code>. It reads <code>request.state.token_method</code> if set by middleware; otherwise you can set it manually during tests.</p>

        <CodeBlock
          language="python"
          code={`def handler(request: Request):
    method = resolve_token_method(request)
    if method == 'COOKIE':
        # UI session
        pass
    elif method == 'BEARER':
        # API key
        pass
    else:
        # unauthenticated
        pass`}
        />
      </section>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold mb-3">PermissionChecker — options & examples</h2>
        <p className="mb-2 text-gray-700 dark:text-gray-300">A dependency factory that enforces permission checks. It supports both COOKIE sessions and BEARER API keys and handles master keys vs scoped keys differently.</p>

        <h3 className="text-lg font-medium mb-2">Constructor options</h3>
        <div className="overflow-x-auto mb-4">
          <table className="min-w-full table-auto border-collapse border border-gray-300 dark:border-gray-600">
            <thead>
              <tr className="bg-gray-100 dark:bg-gray-800">
                <th className="px-4 py-2 text-left">Parameter</th>
                <th className="px-4 py-2 text-left">Type</th>
                <th className="px-4 py-2 text-left">Default</th>
                <th className="px-4 py-2 text-left">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="bg-white dark:bg-gray-800">
                <td className="border px-4 py-2">*permissions</td>
                <td className="border px-4 py-2">str...</td>
                <td className="border px-4 py-2">—</td>
                <td className="border px-4 py-2">Permission strings to check (e.g. 'projects.read')</td>
              </tr>
              <tr>
                <td className="border px-4 py-2">mode</td>
                <td className="border px-4 py-2">'AND' | 'OR'</td>
                <td className="border px-4 py-2">'AND'</td>
                <td className="border px-4 py-2">AND =&gt; all permissions required; OR =&gt; any one required</td>
              </tr>
              <tr className="bg-white dark:bg-gray-800">
                <td className="border px-4 py-2">scope_prefix</td>
                <td className="border px-4 py-2">Optional[str]</td>
                <td className="border px-4 py-2">None</td>
                <td className="border px-4 py-2">If set, used as the prefix when deriving a scope from a path parameter</td>
              </tr>
              <tr>
                <td className="border px-4 py-2">scope_from_path</td>
                <td className="border px-4 py-2">Optional[str]</td>
                <td className="border px-4 py-2">None</td>
                <td className="border px-4 py-2">Name of the path parameter to derive scope from (e.g. 'project_id')</td>
              </tr>
              <tr className="bg-white dark:bg-gray-800">
                <td className="border px-4 py-2">raise_error</td>
                <td className="border px-4 py-2">bool</td>
                <td className="border px-4 py-2">True</td>
                <td className="border px-4 py-2">When False the dependency returns None on failure instead of raising</td>
              </tr>
            </tbody>
          </table>
        </div>

        <h3 className="text-lg font-medium mb-2">Examples</h3>
        <CodeBlock
          language="python"
          code={`# Require a specific permission scoped to path param project_id
@app.get('/projects/{project_id}')
async def read_project(project_id: str, user = Depends(PermissionChecker('projects.read', scope_from_path='project_id'))):
    return {"project_id": project_id}

# Require any of several permissions (OR mode)
@app.post('/projects/{project_id}/action')
async def project_action(project_id: str, user = Depends(PermissionChecker('projects.write', 'projects.admin', mode='OR', scope_from_path='project_id'))):
    return {"ok": True}`}
        />

        <p className="text-sm text-gray-600 dark:text-gray-400">Behavior notes: for BEARER keys, master keys are treated like cookie sessions and evaluate the user's current roles/permissions dynamically; scoped keys are checked against the API key's granted scopes.</p>
      </section>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold mb-3">RoleChecker — options & examples</h2>

        <div className="overflow-x-auto mb-4">
          <table className="min-w-full table-auto border-collapse border border-gray-300 dark:border-gray-600">
            <thead>
              <tr className="bg-gray-100 dark:bg-gray-800">
                <th className="px-4 py-2 text-left">Parameter</th>
                <th className="px-4 py-2 text-left">Type</th>
                <th className="px-4 py-2 text-left">Default</th>
                <th className="px-4 py-2 text-left">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr className="bg-white dark:bg-gray-800">
                <td className="border px-4 py-2">*roles</td>
                <td className="border px-4 py-2">str...</td>
                <td className="border px-4 py-2">—</td>
                <td className="border px-4 py-2">Role names to require (e.g. 'admin')</td>
              </tr>
              <tr>
                <td className="border px-4 py-2">mode</td>
                <td className="border px-4 py-2">'AND' | 'OR'</td>
                <td className="border px-4 py-2">'AND'</td>
                <td className="border px-4 py-2">AND =&gt; all roles required; OR =&gt; any one required</td>
              </tr>
              <tr className="bg-white dark:bg-gray-800">
                <td className="border px-4 py-2">scope_prefix</td>
                <td className="border px-4 py-2">Optional[str]</td>
                <td className="border px-4 py-2">None</td>
                <td className="border px-4 py-2">Same behavior as PermissionChecker</td>
              </tr>
              <tr>
                <td className="border px-4 py-2">scope_from_path</td>
                <td className="border px-4 py-2">Optional[str]</td>
                <td className="border px-4 py-2">None</td>
                <td className="border px-4 py-2">Derive the scope from the named path parameter</td>
              </tr>
              <tr className="bg-white dark:bg-gray-800">
                <td className="border px-4 py-2">raise_error</td>
                <td className="border px-4 py-2">bool</td>
                <td className="border px-4 py-2">True</td>
                <td className="border px-4 py-2">When False the dependency returns None instead of raising</td>
              </tr>
            </tbody>
          </table>
        </div>

        <h3 className="text-lg font-medium mb-2">Examples</h3>
        <CodeBlock
          language="python"
          code={`# Require admin role
@app.post('/admin/only')
async def admin_endpoint(user = Depends(RoleChecker('admin'))):
    return {"ok": True}

# Require either manager OR admin (OR mode)
@app.post('/manage/{org_id}')
async def manage(org_id: str, user = Depends(RoleChecker('manager', 'admin', mode='OR', scope_from_path='org_id'))):
    return {"ok": True}`}
        />
      </section>

      <section className="mb-8">
        <h2 className="text-2xl font-semibold mb-3">Testing & tips</h2>
        <ul className="list-disc list-inside text-gray-700 dark:text-gray-300">
          <li>When unit-testing, you can set <code>request.state.token_method</code>, <code>request.state.user_id</code>, and <code>request.state.user_object</code> manually to emulate middleware behavior.</li>
          <li>If your app is API-only, you can skip middleware and rely on BEARER API keys for authentication and permission checks.</li>
          <li>To allow publishable keys on an endpoint (careful), call <code>get_current_user</code> with <code>allow_public_key=True</code> via a small wrapper dependency.</li>
          <li>Use <code>raise_error=False</code> when you prefer returning <code>None</code> and handling authorization failures inside the route (for custom responses).</li>
        </ul>
      </section>

      <p className="text-sm text-gray-600 dark:text-gray-400">For implementation details see <code className="bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">authtuna/integrations/fastapi_integration.py</code> in the source tree.</p>
    </div>
  );
}
