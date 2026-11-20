// File: theme.ts
// Author: Team LARP
// Date: 2026-11-19 (comments revised)
// Version: 0.1.0
// Purpose: Define theme tokens and apply them to the console document.

import { createContext, useContext } from 'react';

// Color tokens for one console theme; they feed both Ant Design and the CSS variables.
export interface ThemeConfig {
  id: string;
  name: string;
  category: string;
  description: string;
  primaryColor: string;
  primaryHover: string;
  bgBase: string;
  bgSurface: string;
  bgPanel: string;
  borderColor: string;
  textMain: string;
  textMuted: string;
  menuSelectedBg: string;
  menuSelectedColor: string;
  tableHeaderBg: string;
  tableHoverBg: string;
  swatches: [string, string, string]; // [primary, panel, base]
}

// Built-in themes keyed by id. 'workspace' is the light theme and 'carbon' is the default dark theme.
export const THEMES: Record<string, ThemeConfig> = {
  workspace: {
    id: 'workspace', name: 'Workspace', category: 'Light',
    description: 'A clear, light workspace with navy navigation and Terminus blue accents',
    primaryColor: '#2563c9', primaryHover: '#1d4faa',
    bgBase: '#f5f6f8', bgSurface: '#ffffff', bgPanel: '#f9fafb',
    borderColor: '#e5e7ed', textMain: '#252936', textMuted: '#737a89',
    menuSelectedBg: '#eaf1fc', menuSelectedColor: '#1d4faa',
    tableHeaderBg: '#fafbfc', tableHoverBg: '#f4f7fd',
    swatches: ['#2563c9', '#ffffff', '#f5f6f8'],
  },
  carbon: {
    id: 'carbon',
    name: 'Carbon Matrix',
    category: 'Minimalist Slate',
    description: 'Slate graphite with clear typography and Terminus blue accents',
    primaryColor: '#78aaff',
    primaryHover: '#a4c6ff',
    bgBase: '#0f1115',
    bgSurface: '#16191f',
    bgPanel: '#1d2129',
    borderColor: '#303744',
    textMain: '#f8fafc',
    textMuted: '#94a3b8',
    menuSelectedBg: '#2c3442',
    menuSelectedColor: '#ffffff',
    tableHeaderBg: '#242a34',
    tableHoverBg: '#2e3542',
    swatches: ['#78aaff', '#1d2129', '#0f1115'],
  },
};

// Publishes the active theme as CSS variables on the document root so stylesheets pick it up.
export function applyThemeVariables(t: ThemeConfig) {
  const root = document.documentElement;
  root.dataset.theme = t.id;
  root.style.setProperty('--bg-base', t.bgBase);
  root.style.setProperty('--bg-surface', t.bgSurface);
  root.style.setProperty('--bg-panel', t.bgPanel);
  root.style.setProperty('--border-color', t.borderColor);
  root.style.setProperty('--primary-color', t.primaryColor);
  root.style.setProperty('--primary-hover', t.primaryHover);
  root.style.setProperty('--text-main', t.textMain);
  root.style.setProperty('--text-muted', t.textMuted);
}

// Theme state shared with the whole console.
export interface ThemeContextValue {
  themeId: string;
  activeTheme: ThemeConfig;
  setThemeId: (id: string) => void;
  availableThemes: ThemeConfig[];
}

// Provided by Root in main.tsx.
export const ThemeContext = createContext<ThemeContextValue | null>(null);

// Returns the theme state; throws if used outside the provider.
export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return ctx;
}
