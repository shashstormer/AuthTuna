"use client";
import React from "react";
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { Copy, Check } from 'lucide-react';

const CodeBlock = ({ code, language }: { code: string; language: string }) => {
  const [copied, setCopied] = React.useState(false);

  const copyToClipboard = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative group">
      <button
        onClick={copyToClipboard}
        className="absolute top-2 right-2 p-2 rounded bg-gray-700 hover:bg-gray-600 text-white opacity-0 group-hover:opacity-100 transition-opacity"
        aria-label="Copy code"
      >
        {copied ? <Check size={16} /> : <Copy size={16} />}
      </button>
      <SyntaxHighlighter
        language={language}
        style={oneDark}
        className="text-sm md:text-base"
        customStyle={{
          margin: 0,
          borderRadius: '0.5rem',
        }}
      >
        {code}
      </SyntaxHighlighter>
    </div>
  );
};

export default function GettingStartedPage() {
  return (
    <div className="max-w-[90vw] md:max-w-4xl mx-auto px-4 md:px-6 py-8 pt-16 md:pt-20">
      <h1 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white mb-6">Getting Started</h1>

      <section className="mb-6 md:mb-8">
        <h2 className="text-xl md:text-2xl font-semibold text-gray-900 dark:text-white mb-4">Installation</h2>
        <p className="text-base md:text-lg text-gray-700 dark:text-gray-300 mb-4">
          Install AuthTuna using pip:
        </p>
        <CodeBlock
          code="pip install authtuna"
          language="bash"
        />
      </section>

      <section className="mb-6 md:mb-8">
        <h2 className="text-xl md:text-2xl font-semibold text-gray-900 dark:text-white mb-4">Configuration</h2>
        <p className="text-base md:text-lg text-gray-700 dark:text-gray-300 mb-4">
          Create a minimal <code className="bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">.env</code> file in your project root:
        </p>
        <CodeBlock
          code={`# .env
API_BASE_URL=http://localhost:8000
# Mandatory encryption keys (generate with Fernet.generate_key().decode())
FERNET_KEYS='["YOUR_PRIMARY_KEY", "YOUR_SECONDARY_KEY"]'`}
          language="bash"
        />
        <p className="text-base md:text-lg text-gray-700 dark:text-gray-300 mb-4 mt-4">
          Generate encryption keys using Python:
        </p>
        <CodeBlock
          code={`from cryptography.fernet import Fernet

# Generate a key
key = Fernet.generate_key().decode()
print(key)`}
          language="python"
        />
      </section>

      <section className="mb-6 md:mb-8">
        <h2 className="text-xl md:text-2xl font-semibold text-gray-900 dark:text-white mb-4">Basic Usage</h2>
        <p className="text-base md:text-lg text-gray-700 dark:text-gray-300 mb-4">
          Here&apos;s a minimal FastAPI application with AuthTuna:
        </p>
        <CodeBlock
          code={`from fastapi import FastAPI, Depends
from fastapi.responses import RedirectResponse
from authtuna import init_app
from authtuna.integrations import get_current_user_optional

app = FastAPI(title="AuthTuna Demo API")

# This single function adds all middleware and routers
init_app(app)

@app.get("/", tags=["Root"])
async def root(user=Depends(get_current_user_optional)):
    """
    Automatically redirects to login page if not authenticated,
    else redirects to the dashboard.
    """
    if user is None:
        return RedirectResponse("/auth/login")
    return RedirectResponse("/ui/dashboard")`}
          language="python"
        />
      </section>

      <section>
        <h2 className="text-xl md:text-2xl font-semibold text-gray-900 dark:text-white mb-4">Next Steps</h2>
        <p className="text-base md:text-lg text-gray-700 dark:text-gray-300 mb-4">
          Now that you have a basic setup, you can explore more features:
        </p>
        <ul className="list-disc list-inside text-base md:text-lg text-gray-700 dark:text-gray-300 space-y-2">
          <li><a href="/rbac-example" className="text-blue-600 hover:text-blue-800 dark:text-blue-400">Sample Example</a> - A complete working example</li>
          <li><a href="/configuration-options" className="text-blue-600 hover:text-blue-800 dark:text-blue-400">Configuration Options</a> - Customize AuthTuna to your needs</li>
          <li><a href="/integrations" className="text-blue-600 hover:text-blue-800 dark:text-blue-400">Dependency Injection</a> - Learn about user dependencies</li>
        </ul>
      </section>
    </div>
  );
}
