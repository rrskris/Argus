"use client";
import { useAuth } from './AuthContext';
import { useTheme } from './ThemeContext';
import { Bell, User, LogOut, Moon, Sun, ArrowLeft, Book } from 'lucide-react';
import { useState } from 'react';

import { useRouter, usePathname } from 'next/navigation';

export default function TopBar() {
    const { user, logout } = useAuth();
    const router = useRouter();
    const { theme, setTheme } = useTheme();
    const [notifications] = useState(3);
    const pathname = usePathname();

    if (pathname === '/login') return null;

    return (
        <header className="h-16 bg-space/90 backdrop-blur-md border-b border-gray-800/50 flex items-center justify-between px-8 sticky top-0 z-40">
            {/* Breadcrumbs or Title */}
            <div className="flex items-center text-sm font-medium text-gray-400 gap-4">
                {pathname !== '/' && (
                    <button
                        onClick={() => router.back()}
                        className="p-1.5 rounded-full hover:bg-white/10 text-neon-blue transition-colors"
                        title="Go Back"
                    >
                        <ArrowLeft size={18} />
                    </button>
                )}
                <div className="flex items-center">
                    <span className="text-neon-blue">Argus</span>
                    <span className="mx-2">/</span>
                    <span className="text-text-secondary">Admin Console</span>
                </div>
            </div>

            {/* Right Actions */}
            <div className="flex items-center gap-6">
                {/* Search (Optional) */}
                <div className="relative hidden md:block">
                    <input
                        type="text"
                        placeholder="Search resources..."
                        className="bg-surface border border-gray-700 rounded-full py-1.5 px-4 text-sm text-gray-300 focus:outline-none focus:border-neon-blue focus:ring-1 focus:ring-neon-blue w-64 transition-all"
                    />
                </div>

                {/* Docs Link */}
                <button
                    onClick={() => router.push('/docs')}
                    className="relative text-gray-400 hover:text-white transition-colors p-1"
                    title="Documentation"
                >
                    <Book size={20} />
                </button>

                {/* Notifications */}
                <button className="relative text-gray-400 hover:text-white transition-colors">
                    <Bell size={20} />
                    {notifications > 0 && (
                        <span className="absolute -top-1 -right-1 flex h-4 w-4 items-center justify-center rounded-full bg-neon-red text-[10px] font-bold text-white">
                            {notifications}
                        </span>
                    )}
                </button>

                {/* Theme Switcher */}
                <div className="relative group ml-4 h-8 flex items-center">
                    <button className="text-gray-400 hover:text-primary transition-colors p-1 rounded-md hover:bg-white/5">
                        <Sun size={20} className="hidden [html[data-theme='light']_&]:block [html[data-theme='solarized-day']_&]:block" />
                        <Moon size={20} className="hidden [html[data-theme='space']_&]:block [html[data-theme='solarized-night']_&]:block" />
                        <div className="hidden [html[data-theme='cyberpunk']_&]:block font-mono text-neon-green text-xs border border-neon-green px-1">CYBER</div>
                    </button>

                    {/* Theme Dropdown */}
                    <div className="absolute right-0 top-full mt-2 w-32 bg-card border border-border-color rounded-lg shadow-xl opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all transform origin-top-right z-50">
                        <div className="p-1 space-y-1">
                            <button onClick={() => setTheme('space')} className={`w-full text-left px-3 py-2 text-sm rounded transition-colors flex items-center gap-2 ${theme === 'space' ? 'text-neon-blue bg-white/5' : 'text-gray-400 hover:text-primary hover:bg-white/5'}`}>
                                <Moon size={14} />
                                <span>Space (Default)</span>
                            </button>
                            <button onClick={() => setTheme('solarized-day')} className={`w-full text-left px-3 py-2 text-sm rounded transition-colors flex items-center gap-2 ${theme === 'solarized-day' ? 'text-neon-blue bg-white/5' : 'text-gray-400 hover:text-primary hover:bg-white/5'}`}>
                                <Sun size={14} />
                                <span>Solarized Day</span>
                            </button>
                            <button onClick={() => setTheme('solarized-night')} className={`w-full text-left px-3 py-2 text-sm rounded transition-colors flex items-center gap-2 ${theme === 'solarized-night' ? 'text-neon-blue bg-white/5' : 'text-gray-400 hover:text-primary hover:bg-white/5'}`}>
                                <Moon size={14} />
                                <span>Solarized Night</span>
                            </button>
                            <button onClick={() => setTheme('cyberpunk')} className={`w-full text-left px-3 py-2 text-sm rounded transition-colors flex items-center gap-2 ${theme === 'cyberpunk' ? 'text-neon-green bg-white/5' : 'text-gray-400 hover:text-primary hover:bg-white/5'}`}>
                                <div className="w-3 h-3 bg-neon-green rounded-sm"></div>
                                <span>Cyberpunk</span>
                            </button>
                        </div>
                    </div>
                </div>

                {/* Profile Dropdown */}
                <div className="relative group ml-6 border-l border-border-color pl-6 h-8 flex items-center">
                    <div className="flex items-center gap-3 cursor-pointer">
                        <div className="text-right hidden sm:block">
                            <div className="text-sm font-medium text-primary">{user?.username || 'Admin User'}</div>
                            <div className="text-xs text-neon-blue">{user?.role || 'Administrator'}</div>
                        </div>
                        <div className="h-9 w-9 rounded-full bg-gradient-to-tr from-neon-blue to-neon-purple p-[1px]">
                            <div className="h-full w-full rounded-full bg-surface flex items-center justify-center">
                                <User size={16} className="text-primary" />
                            </div>
                        </div>
                    </div>

                    {/* Dropdown Menu */}
                    <div className="absolute right-0 top-full mt-2 w-48 bg-card border border-border-color rounded-lg shadow-xl opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all transform origin-top-right z-50">
                        <div className="p-2 space-y-1">
                            <div className="px-3 py-2 text-xs text-text-secondary uppercase tracking-wider font-bold">Account</div>
                            <a href="/settings" className="block px-3 py-2 text-sm text-text-secondary hover:bg-white/5 rounded transition-colors flex items-center gap-2">
                                <span>Settings</span>
                            </a>
                            <div className="border-t border-border-color my-1"></div>
                            <button
                                onClick={logout}
                                className="w-full text-left px-3 py-2 text-sm text-neon-red hover:bg-neon-red/10 rounded transition-colors flex items-center gap-2"
                            >
                                <LogOut size={14} />
                                <span>Sign Out</span>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </header>
    );
}
