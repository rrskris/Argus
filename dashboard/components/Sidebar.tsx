"use client";

import Link from 'next/link';
import { usePathname } from 'next/navigation';

export default function Sidebar() {
    const pathname = usePathname();

    if (pathname === '/login') return null;

    const navItems = [
        { name: 'Dashboard', path: '/', icon: '🏠' },
        { name: 'CVE Scanner', path: '/cve', icon: '🔴' },
        { name: 'Docs', path: '/docs', icon: '📖' },
        { name: 'Settings', path: '/settings', icon: '⚙️' },
    ];

    return (
        <div className="w-64 h-screen bg-space/90 backdrop-blur-md border-r border-gray-800/50 flex flex-col fixed left-0 top-0 pt-4 z-50">
            <div className="p-6 border-b border-gray-800/50">
                <Link href="/" className="block hover:opacity-80 transition-opacity">
                    <h1 className="text-2xl font-bold text-neon-blue tracking-tighter drop-shadow-[0_0_10px_rgba(0,212,255,0.5)]">
                        ARGUS
                    </h1>
                    <p className="text-[10px] text-neon-blue/60 mt-1 font-mono tracking-widest uppercase">
                        Security Visibility
                    </p>
                </Link>
            </div>

            <nav className="flex-1 p-4 space-y-2 mt-4">
                {navItems.map((item) => {
                    const isActive = pathname === item.path;
                    return (
                        <Link
                            key={item.path}
                            href={item.path}
                            className={`flex items-center gap-3 px-4 py-3 rounded-none border-l-2 transition-all group ${isActive
                                ? 'bg-neon-blue/10 text-neon-blue border-neon-blue'
                                : 'border-transparent text-gray-500 hover:text-primary hover:bg-white/5'
                                }`}
                        >
                            <span className={`transition-transform group-hover:scale-110 ${isActive ? 'text-neon-blue drop-shadow-[0_0_5px_rgba(0,212,255,0.5)]' : ''}`}>
                                {item.icon}
                            </span>
                            <span className="font-mono text-sm tracking-wide">{item.name}</span>
                        </Link>
                    );
                })}
            </nav>

        </div>
    );
}
