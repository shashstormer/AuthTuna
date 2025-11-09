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
        <div className="text-2xl font-bold text-zinc-900 dark:text-white mb-6">{title}</div>
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
      </aside>

      {/* Mobile header + collapsible menu (visible on small screens) */}
      <div className="md:hidden">
        <header className="sticky top-0 z-40 flex items-center justify-between p-4 bg-white dark:bg-black border-b border-gray-200 dark:border-gray-800">
          <div className="text-lg font-semibold text-zinc-900 dark:text-white">{title}</div>
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
