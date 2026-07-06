"use client";

import React, { createContext, useContext, useEffect, useState } from "react";

type Theme = "space" | "solarized-day" | "solarized-night" | "cyberpunk";

interface ThemeContextType {
    theme: Theme;
    setTheme: (theme: Theme) => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export function ThemeProvider({ children }: { children: React.ReactNode }) {
    const [theme, setTheme] = useState<Theme>("solarized-night");

    useEffect(() => {
        // Load from local storage
        const saved = localStorage.getItem("pro-nds-theme") as Theme;
        if (saved) {
            // One-time hydration from browser-only storage, not derived state.
            // eslint-disable-next-line react-hooks/set-state-in-effect
            setTheme(saved);
            document.documentElement.setAttribute("data-theme", saved);
        } else {
            document.documentElement.setAttribute("data-theme", "solarized-night");
        }
    }, []);

    const changeTheme = (newTheme: Theme) => {
        setTheme(newTheme);
        localStorage.setItem("pro-nds-theme", newTheme);
        document.documentElement.setAttribute("data-theme", newTheme);
    };

    return (
        <ThemeContext.Provider value={{ theme, setTheme: changeTheme }}>
            {children}
        </ThemeContext.Provider>
    );
}

export function useTheme() {
    const context = useContext(ThemeContext);
    if (context === undefined) {
        throw new Error("useTheme must be used within a ThemeProvider");
    }
    return context;
}
