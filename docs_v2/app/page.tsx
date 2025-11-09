"use client";
import React from "react";

export default function Home() {
    return (
        <div className={"w-full"}>
            <div className="flex flex-col items-center text-center px-6">
                <div className="mb-8">
                    <h1 className="text-6xl md:text-8xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent mb-4">
                        <span className="text-7xl md:text-9xl">🐟</span> AuthTuna
                    </h1>
                    <p className="text-xl md:text-2xl text-gray-600 dark:text-gray-300">
                        The Auth Framework For FastAPI
                    </p>
                </div>
                <div className="flex flex-col sm:flex-row space-y-4 sm:space-y-0 sm:space-x-4">
                    <a
                        href="/getting-started"
                        className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-4 rounded-lg font-semibold text-lg transition-colors duration-200"
                    >
                        Get Started
                    </a>
                    <a
                        href="https://github.com/shashstormer/authtuna"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 px-8 py-4 rounded-lg font-semibold text-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors duration-200"
                    >
                        View on GitHub
                    </a>
                </div>
            </div>
            <div className="w-full max-w-[88vw] md:max-w-6xl mx-auto px-6 py-16">
                <section className="mb-16">
                    <h2 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
                        Why I made AuthTuna?
                    </h2>
                    <p className="text-lg text-gray-700 dark:text-gray-300 mb-4">
                        AuthTuna was built to address a challenge i have been working with from a long time (4+ years).
                        I had been working with a auth system from 4+ years but its code got wayy to complex and unextendable.
                        It was doing well but i just felt it was not enough as I was having trouble extending rbac implementing other complex flows with that.
                        So i decided to rebuild it from scratch and thought why not just make it open source, simplify usage and take it up another level.
                    </p>
                    <p>
                        So then came about this library. I copied some part of my old codebase for rbac then enhanced the rbac system. Then when i put in mfa i was not happy opening my phone every time i login so i introduced the passkeys system so that i can just use my pc pin without opening the phone and use fingerprint phone.
                    </p>
                </section>
                <section className="mb-16">
                    <h2 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
                        Why should you use AuthTuna?
                    </h2>
                    <p className="text-lg text-gray-700 dark:text-gray-300 mb-4">
                        This library simplifies integrating auth into any application. Previously you could have either used fastapi-users and spent time to extend its capabilities. But this library has enough features to have the highest security and the simplest usage.
                    </p>
                    <p className="text-lg text-gray-700 dark:text-gray-300 mb-4">
                        Let us say you are prototyping something and want a simple login page within 2 lines of code and 2 env vars you can add basic login page and get_current_user dependency in no time. <br/><br/> Or you want to build a complex app with rbac, mfa, passkeys and social login you can do that too with minimal code.
                    </p>
                </section>
                <section className="mb-16">
                    <h2 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
                        Key Features
                    </h2>
                    <div className="grid md:grid-cols-2 gap-8">
                        <div>
                            <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                                Multi-Factor Authentication (MFA)
                            </h3>
                            <p className="text-gray-700 dark:text-gray-300">
                                Enhance security with built-in MFA support with TOTP.
                            </p>
                        </div>
                        <div>
                            <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                                Social Login
                            </h3>
                            <p className="text-gray-700 dark:text-gray-300">
                                Integrate with popular social platforms (curr out of the box supports github and google, extendable).
                            </p>
                        </div>
                        <div>
                            <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                                Passkeys
                            </h3>
                            <p className="text-gray-700 dark:text-gray-300">
                                Support for modern passwordless authentication using
                                WebAuthn and passkeys for improved user experience and
                                security.
                            </p>
                        </div>
                        <div>
                            <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                                Session Management
                            </h3>
                            <p className="text-gray-700 dark:text-gray-300">
                                Robust session handling with customizable expiration, secure
                                cookies, middleware and dependency injection for protecting routes.
                            </p>
                        </div>
                        <div>
                            <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                                Role-Based Access Control (RBAC)
                            </h3>
                            <p className="text-gray-700 dark:text-gray-300">
                                Flexible permission system to manage user roles and access
                                levels within your application.
                            </p>
                        </div>
                        <div>
                            <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                                FastAPI Integration
                            </h3>
                            <p className="text-gray-700 dark:text-gray-300">
                                Designed specifically for FastAPI, leveraging its async
                                capabilities and dependency injection system.
                            </p>
                        </div>
                    </div>
                </section>
                <section>
                </section>
            </div>
        </div>
    );
}
