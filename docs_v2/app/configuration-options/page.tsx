"use client";
import React from "react";
import {Prism as SyntaxHighlighter} from 'react-syntax-highlighter';
import {oneDark} from 'react-syntax-highlighter/dist/esm/styles/prism';
import {Check, Copy} from 'lucide-react';

const CodeBlock = ({code, language}: { code: string; language: string }) => {
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
                {copied ? <Check size={16}/> : <Copy size={16}/>}
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

export default function ConfigurationOptionsPage() {
    return (
        <div className="max-w-[90vw] md:max-w-6xl mx-auto px-4 md:px-6 py-8 pt-16 md:pt-20">
            <h1 className="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white mb-6">Configuration Options</h1>

            <p className="text-base md:text-lg text-gray-700 dark:text-gray-300 mb-8">
                AuthTuna uses Pydantic settings to manage configuration. All settings can be overridden via environment
                variables or programmatically. Below are all available settings.
            </p>

            <section className="mb-8">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">Application Settings</h2>
                <div className="overflow-x-auto">
                    <table
                        className="min-w-full table-auto border-collapse border border-gray-300 dark:border-gray-600">
                        <thead>
                        <tr className="bg-gray-100 dark:bg-gray-800">
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Setting
                                Name
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Default
                                Value
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Description</th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Remarks</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`APP_NAME`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"AuthTuna"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`The name of your application`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Displayed in UI`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`ALGORITHM`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"HS256"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`JWT encryption algorithm`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{``}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`API_BASE_URL`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Required`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Base URL for the API`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Must be set`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`TRY_FULL_INITIALIZE_WHEN_SYSTEM_USER_EXISTS_AGAIN`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`False`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Retry full initialization if system user exists`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Advanced setting`}</td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </section>

            <section className="mb-8">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">Security Settings</h2>
                <div className="overflow-x-auto">
                    <table
                        className="min-w-full table-auto border-collapse border border-gray-300 dark:border-gray-600">
                        <thead>
                        <tr className="bg-gray-100 dark:bg-gray-800">
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Setting
                                Name
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Default
                                Value
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Description</th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Remarks</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`JWT_SECRET_KEY`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"dev-secret-key-change-in-production"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Secret key for JWT tokens`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Change in production`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`ENCRYPTION_PRIMARY_KEY`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"dev-encryption-key-change-in-production"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Secret to sign Encrypted Cookie`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Change in production`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`ENCRYPTION_SECONDARY_KEYS`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`[]`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`List of secondary encryption keys`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For key rotation`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`FERNET_KEYS`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`[]`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`List of Fernet keys for encryption`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Alternative to primary key`}</td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </section>

            <section className="mb-8">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">Feature Enable/Disable</h2>
                <div className="overflow-x-auto">
                    <table
                        className="min-w-full table-auto border-collapse border border-gray-300 dark:border-gray-600">
                        <thead>
                        <tr className="bg-gray-100 dark:bg-gray-800">
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Setting
                                Name
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Default
                                Value
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Description</th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Remarks</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`MFA_ENABLED`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`True`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Enable Multi-Factor Authentication`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Set to False to disable`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`PASSKEYS_ENABLED`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`True`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Enable passkeys`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Requires WebAuthn setup`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`UI_ENABLED`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`True`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Enable UI routes`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Disable for API-only`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`ADMIN_ROUTES_ENABLED`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`True`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Enable admin routes`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For admin panel`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`PASSWORDLESS_LOGIN_ENABLED`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`True`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Enable passwordless login`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Login via email link`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`ONLY_MIDDLEWARE`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`False`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Use only middleware for secondary servers`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For multi-server setups`}</td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </section>

            <section className="mb-8">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">Default Users and Roles
                    Settings</h2>
                <div className="overflow-x-auto">
                    <table
                        className="min-w-full table-auto border-collapse border border-gray-300 dark:border-gray-600">
                        <thead>
                        <tr className="bg-gray-100 dark:bg-gray-800">
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Setting
                                Name
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Default
                                Value
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Description</th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Remarks</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DEFAULT_SUPERADMIN_PASSWORD`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`None`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Default password for superadmin`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Leave None to disable login`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DEFAULT_ADMIN_PASSWORD`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`None`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Default password for admin`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Leave None to disable login`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DEFAULT_SUPERADMIN_EMAIL`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"superadmin@example.com"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Default superadmin email`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Change for production`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DEFAULT_ADMIN_EMAIL`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"admin@example.com"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Default admin email`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Change for production`}</td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </section>

            <section className="mb-8">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">Database Settings</h2>
                <div className="overflow-x-auto">
                    <table
                        className="min-w-full table-auto border-collapse border border-gray-300 dark:border-gray-600">
                        <thead>
                        <tr className="bg-gray-100 dark:bg-gray-800">
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Setting
                                Name
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Default
                                Value
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Description</th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Remarks</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DEFAULT_DATABASE_URI`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"sqlite+aiosqlite:///./authtuna_dev.db"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Database URI`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Use async URI`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DATABASE_USE_ASYNC_ENGINE`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`True`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Use async engine`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Doesnt matter not read anywhere async only supported`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`AUTO_CREATE_DATABASE`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`True`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Auto-create database tables`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Doesn't need change usually.`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DATABASE_POOL_SIZE`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`20`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Connection pool size`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Adjust based on load`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DATABASE_MAX_OVERFLOW`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`40`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Max overflow connections`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For high concurrency`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DATABASE_POOL_TIMEOUT`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`30`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Pool timeout`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Seconds`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DATABASE_POOL_RECYCLE`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`1800`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Pool recycle time`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Seconds`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DATABASE_POOL_PRE_PING`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`True`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Pre-ping connections`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For connection health`}</td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </section>

            <section className="mb-8">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">Session Settings</h2>
                <div className="overflow-x-auto">
                    <table
                        className="min-w-full table-auto border-collapse border border-gray-300 dark:border-gray-600">
                        <thead>
                        <tr className="bg-gray-100 dark:bg-gray-800">
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Setting
                                Name
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Default
                                Value
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Description</th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Remarks</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`FINGERPRINT_HEADERS`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`["User-Agent", "Accept-Language"]`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Headers for fingerprinting`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For session security by fingerprinting user browser and locking to it`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`SESSION_DB_VERIFICATION_INTERVAL`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`10`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Interval for DB verification`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Seconds between revalidating JWT in session middleware`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`SESSION_LIFETIME_SECONDS`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`604800`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Session lifetime`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`7 days, if unused for this duration it expires`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`SESSION_ABSOLUTE_LIFETIME_SECONDS`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`31536000`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Absolute session lifetime`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`1 year, max validity of a session`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`SESSION_LIFETIME_FROM`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"last_activity"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Lifetime calculation from`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"last_activity" or "creation"`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`SESSION_SAME_SITE`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"LAX"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`SameSite attribute`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For cookies`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`SESSION_SECURE`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`True`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Secure flag`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For HTTPS`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`SESSION_TOKEN_NAME`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"session_token"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Token cookie name`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Cookie name`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`SESSION_COOKIE_DOMAIN`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`None`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Cookie domain`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For subdomains`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`LOCK_SESSION_REGION`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`True`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Lock session to region`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Based on IP geolocation`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DISABLE_RANDOM_STRING`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`False`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Disable random string`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For long-running connections`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`RANDOM_STRING_GRACE`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`300`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Random string grace period`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Seconds`}</td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </section>

            <section className="mb-8">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">Email Settings</h2>
                <div className="overflow-x-auto">
                    <table
                        className="min-w-full table-auto border-collapse border border-gray-300 dark:border-gray-600">
                        <thead>
                        <tr className="bg-gray-100 dark:bg-gray-800">
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Setting
                                Name
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Default
                                Value
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Description</th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Remarks</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`EMAIL_ENABLED`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`False`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Enable email functionality`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Requires SMTP setup`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`SMTP_HOST`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`None`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`SMTP host`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For email sending`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`SMTP_PORT`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`587`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`SMTP port`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Usually 587 or 465`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`SMTP_USERNAME`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`None`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`SMTP username`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For authentication`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`SMTP_PASSWORD`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`None`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`SMTP password`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Secret`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DKIM_PRIVATE_KEY_PATH`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`None`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DKIM private key path`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For email signing`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DKIM_DOMAIN`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`None`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DKIM domain`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For DKIM`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DKIM_SELECTOR`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`None`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DKIM selector`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For DKIM`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DEFAULT_SENDER_EMAIL`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"noreply@example.com"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Default sender email`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Change for production`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`EMAIL_DOMAINS`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`["*"]`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Allowed email domains`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For registration`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`TOKENS_EXPIRY_SECONDS`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`3600`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Token expiry`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`1 hour`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`TOKENS_MAX_COUNT_PER_DAY_PER_USER_PER_ACTION`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`5`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Max tokens per day`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Rate limiting`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`MAIL_STARTTLS`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`True`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Use STARTTLS`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For secure connection`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`MAIL_SSL_TLS`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`False`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Use SSL/TLS`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Alternative to STARTTLS`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`USE_CREDENTIALS`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`True`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Use credentials`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For SMTP auth`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`VALIDATE_CERTS`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`True`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Validate certificates`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For security`}</td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </section>

            <section className="mb-8">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">Template Locations</h2>
                <div className="overflow-x-auto">
                    <table
                        className="min-w-full table-auto border-collapse border border-gray-300 dark:border-gray-600">
                        <thead>
                        <tr className="bg-gray-100 dark:bg-gray-800">
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Setting
                                Name
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Default
                                Value
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Description</th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Remarks</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`EMAIL_TEMPLATE_DIR`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`module_path/templates/email`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Directory for email templates`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`You may override this but you will have to implement all pages`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`HTML_TEMPLATE_DIR`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`module_path/templates/pages`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Directory for HTML pages`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Same as above`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`DASHBOARD_AND_USER_INFO_PAGES_TEMPLATE_DIR`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`module_path/templates/dashboard`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Directory for dashboard templates`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Same as above`}</td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </section>

            <section className="mb-8">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">OAuth Settings</h2>
                <div className="overflow-x-auto">
                    <table
                        className="min-w-full table-auto border-collapse border border-gray-300 dark:border-gray-600">
                        <thead>
                        <tr className="bg-gray-100 dark:bg-gray-800">
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Setting
                                Name
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Default
                                Value
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Description</th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Remarks</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`GOOGLE_CLIENT_ID`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`None`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Google OAuth client ID`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For Google login`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`GOOGLE_CLIENT_SECRET`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`None`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Google OAuth client secret`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Secret`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`GOOGLE_REDIRECT_URI`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`None`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Google OAuth redirect URI`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For OAuth flow`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`GITHUB_CLIENT_ID`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`None`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`GitHub OAuth client ID`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For GitHub login`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`GITHUB_CLIENT_SECRET`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`None`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`GitHub OAuth client secret`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Secret`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`GITHUB_REDIRECT_URI`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`None`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`GitHub OAuth redirect URI`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For OAuth flow`}</td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </section>

            <section className="mb-8">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">WebAuthn Settings</h2>
                <div className="overflow-x-auto">
                    <table
                        className="min-w-full table-auto border-collapse border border-gray-300 dark:border-gray-600">
                        <thead>
                        <tr className="bg-gray-100 dark:bg-gray-800">
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Setting
                                Name
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Default
                                Value
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Description</th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Remarks</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`WEBAUTHN_ENABLED`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`False`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Enable WebAuthn`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For passkeys`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`WEBAUTHN_RP_ID`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"localhost"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Relying Party ID`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Domain for WebAuthn`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`WEBAUTHN_RP_NAME`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"AuthTuna"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Relying Party name`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Display name`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`WEBAUTHN_ORIGIN`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"http://localhost:8000"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Origin URL`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For WebAuthn`}</td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </section>

            <section className="mb-8">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">Authentication Strategies</h2>
                <div className="overflow-x-auto">
                    <table
                        className="min-w-full table-auto border-collapse border border-gray-300 dark:border-gray-600">
                        <thead>
                        <tr className="bg-gray-100 dark:bg-gray-800">
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Setting
                                Name
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Default
                                Value
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Description</th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Remarks</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`STRATEGY`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"AUTO"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Authentication strategy`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"COOKIE", "BEARER", or "AUTO", cookie = browser only, bearer = api only, auto = mixed contexts.`}</td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </section>

            <section className="mb-8">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">API Key Settings</h2>
                <div className="overflow-x-auto">
                    <table
                        className="min-w-full table-auto border-collapse border border-gray-300 dark:border-gray-600">
                        <thead>
                        <tr className="bg-gray-100 dark:bg-gray-800">
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Setting
                                Name
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Default
                                Value
                            </th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Description</th>
                            <th className="border border-gray-300 dark:border-gray-600 px-4 py-2 text-left">Remarks</th>
                        </tr>
                        </thead>
                        <tbody>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`API_KEY_PREFIX_SECRET`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"sk"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Prefix for secret keys`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For API keys`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`API_KEY_PREFIX_PUBLISHABLE`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"pk"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Prefix for publishable keys`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For API keys`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`API_KEY_PREFIX_MASTER`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"mk"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Prefix for master keys`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For API keys`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`API_KEY_PREFIX_OTHER`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"key"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Prefix for other keys`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`For API keys`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`MAX_MASTER_KEYS_PER_USER`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`5`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Max master keys per user`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Limit`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`MAX_API_KEYS_PER_USER`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`100`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Max API keys per user`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Limit`}</td>
                        </tr>
                        <tr>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`MAX_SCOPES_PER_SECRET_KEY`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`0`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Max scopes per secret key`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`0 = unlimited`}</td>
                        </tr>
                        <tr className="bg-gray-50 dark:bg-gray-700">
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`KEY_HASH_ALGORITHM`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"SHA384"`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`Hash algorithm for keys`}</td>
                            <td className="border border-gray-300 dark:border-gray-600 px-4 py-2">{`"SHA256", "SHA384", "SHA512"`}</td>
                        </tr>
                        </tbody>
                    </table>
                </div>
            </section>
            <section className="mb-6 md:mb-8">
                <h2 className="text-xl md:text-2xl font-semibold text-gray-900 dark:text-white mb-4">Setting
                    Configuration Options</h2>
                <p className="text-base md:text-lg text-gray-700 dark:text-gray-300 mb-4">
                    You can set these options in several ways:
                </p>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">1. Environment Variables</h3>
                <p className="text-base md:text-lg text-gray-700 dark:text-gray-300 mb-4">
                    Create a <code className="bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">.env</code> file in your
                    project root:
                </p>
                <CodeBlock
                    code={`# .env
API_BASE_URL=https://yourapp.com
JWT_SECRET_KEY=dein-secure-jwt-secret
FERNET_KEYS=["der key"]
ENCRYPTION_PRIMARY_KEY=dein-encryption-key
MFA_ENABLED=True
DATABASE_POOL_SIZE=50`}
                    language="bash"
                />
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">2. Programmatic Override</h3>
                <p className="text-base md:text-lg text-gray-700 dark:text-gray-300 mb-4">
                    Override settings in your code:
                </p>
                <CodeBlock
                    code={`from authtuna import init_settings

# Override specific settings
init_settings({
    "APP_NAME": "Mein Custom App",
    "MFA_ENABLED": False,
    "DATABASE_POOL_SIZE": 100
}, dont_use_env=False)`}
                    language="python"
                />
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">3. Manual Initialization</h3>
                <p className="text-base md:text-lg text-gray-700 dark:text-gray-300 mb-4">
                    Provide all settings manually (disables environment variable loading):
                </p>
                <CodeBlock
                    code={`from authtuna import init_settings

# Manual settings (no env vars used)
init_settings({
    "API_BASE_URL": "https://myapp.com",
    "JWT_SECRET_KEY": "sekure-key",
    "ENCRYPTION_PRIMARY_KEY": "encryption-key",
    # ... all other required settings
})`}
                    language="python"
                />
            </section>
            <section className="mb-8">
                <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-4">Theme Configuration</h2>
                <p className="text-base md:text-lg text-gray-700 dark:text-gray-300 mb-4">
                    The theme setting is a complex Pydantic model that controls the visual appearance of the AuthTuna
                    UI. It includes colors, fonts, spacing, and other styling options. Due to its complex structure,
                    it&apos;s recommended to override the theme programmatically in your code rather than through
                    environment variables to prevent configuration mistakes.
                </p>
                <p className="text-base md:text-lg text-gray-700 dark:text-gray-300 mb-4">
                    The default theme provides a clean, modern look that works well for most applications. You can
                    customize it by creating a custom theme object and passing it to the settings.
                </p>
                <CodeBlock
                    code={`from authtuna import Theme, init_settings, ThemeMode, settings

new_theme = settings.THEME.dark.model_copy(deep=True)
new_theme.background_start = "#143497"
new_theme.background_end = "#000000"
custom_theme = Theme(
    mode="single", # only light mode vars but just set them to whatever you want they will be used in dark mode also.
    light=new_theme,
)

# Override settings with custom theme
init_settings(THEME=custom_theme, dont_use_env=False)) # remember to keep THEME ALL CAPS otherwise youd be wondering why colorz not changin.`}
                    language="python"
                />
                <p className="text-base md:text-lg text-gray-700 dark:text-gray-300">
                    For a complete list of theme properties, refer to the Theme model in the AuthTuna source code.
                </p>
            </section>
        </div>
    );
}
