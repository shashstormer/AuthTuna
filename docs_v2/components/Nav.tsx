"use client";

import React, { useState } from "react";

export type LinkItem = { id: string; label: string; href?: string };

interface NavProps {
  title?: string;
  links: LinkItem[];
}

export default function Nav({ title = "Docs", links }: NavProps) {
  const [open, setOpen] = useState(false);

  return (
    <>
      {/* Desktop sidebar (hidden on small screens) */}
      <aside className="hidden md:flex md:flex-col w-64 h-screen bg-white dark:bg-gray-900 border-r border-gray-200 dark:border-gray-800 p-6">
          <div className="text-2xl font-bold text-zinc-900 dark:text-white mb-6"><a href={"/"}><span className={"text-3xl"}>🐟</span>{title}</a></div>
        <nav className="flex flex-col space-y-2" aria-label="Documentation navigation">
          {links.map((link) => (
            <a
              key={link.id}
              href={link.href ?? `#${link.id}`}
              className="block rounded-md px-3 py-2 text-zinc-700 dark:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-gray-800"
            >
              {link.label}
            </a>
          ))}
        </nav>
        <div className="mt-auto pt-4 border-t border-gray-200 dark:border-gray-800">
          <a
            href="https://github.com/shashstormer/authtuna"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="View on GitHub"
            className="flex items-center space-x-2 text-zinc-700 dark:text-zinc-200 hover:text-zinc-900 dark:hover:text-white"
          >
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
            </svg>
            <span>GitHub</span>
          </a>
        </div>
      </aside>

      {/* Mobile header + collapsible menu (visible on small screens) */}
      <div className="md:hidden">
        <header className="sticky top-0 z-40 flex items-center justify-between p-4 bg-white dark:bg-black border-b border-gray-200 dark:border-gray-800">
          <div className="flex items-center space-x-2">
            <div className="text-lg font-semibold text-zinc-900 dark:text-white"><a href={"/"}><span className={"text-2xl"}>🐟</span>{title}</a></div>
            <a
              href="https://github.com/shashstormer/authtuna"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="View on GitHub"
              className="text-zinc-900 dark:text-white hover:text-zinc-700 dark:hover:text-zinc-300"
            >
              <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
              </svg>
            </a>
          </div>
          <button
            onClick={() => setOpen(!open)}
            aria-expanded={open}
            aria-label="Toggle navigation menu"
            className="p-2 rounded-md text-zinc-900 dark:text-white hover:bg-zinc-100 dark:hover:bg-gray-800"
          >
            {open ? (
              <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            ) : (
              <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            )}
          </button>
        </header>

        <div
          className={`bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800 overflow-hidden transition-all duration-200 ease-in-out ${
            open ? "max-h-96" : "max-h-0"
          }`}
        >
          <nav className="flex flex-col p-4 space-y-2" aria-label="Mobile documentation navigation">
            {links.map((link) => (
              <a
                key={link.id}
                href={link.href ?? `#${link.id}`}
                onClick={() => setOpen(false)}
                className="block rounded-md px-3 py-2 text-zinc-700 dark:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-gray-800"
              >
                {link.label}
              </a>
            ))}
          </nav>
        </div>
      </div>
    </>
  );
}
