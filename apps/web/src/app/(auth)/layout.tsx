import React from 'react';

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-neutral-950 flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-md bg-neutral-900 border border-neutral-800 rounded-xl shadow-2xl p-8">
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 bg-blue-600 rounded-lg flex items-center justify-center mb-4">
            <span className="text-white font-bold text-xl">AC</span>
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">AuthClaw</h1>
          <p className="text-neutral-400 text-sm mt-1">Enterprise AI Security & Governance</p>
        </div>
        {children}
      </div>
    </div>
  );
}
