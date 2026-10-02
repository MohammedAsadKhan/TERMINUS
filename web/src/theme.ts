import { createContext, useContext } from 'react';

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

export const THEMES: Record<string, ThemeConfig> = {
  carbon: {
    id: 'carbon',
    name: 'Carbon Matrix',
    category: 'Minimalist Slate',
    description: 'Ultra-clean slate graphite with pure platinum typography and borders',
    primaryColor: '#e2e8f0',
    primaryHover: '#ffffff',
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
    swatches: ['#e2e8f0', '#1d2129', '#0f1115'],
  },
};

export function applyThemeVariables(t: ThemeConfig) {
  const root = document.documentElement;
  root.style.setProperty('--bg-base', t.bgBase);
  root.style.setProperty('--bg-surface', t.bgSurface);
  root.style.setProperty('--bg-panel', t.bgPanel);
  root.style.setProperty('--border-color', t.borderColor);
  root.style.setProperty('--primary-color', t.primaryColor);
  root.style.setProperty('--primary-hover', t.primaryHover);
  root.style.setProperty('--text-main', t.textMain);
  root.style.setProperty('--text-muted', t.textMuted);
}

export interface ThemeContextValue {
  themeId: string;
  activeTheme: ThemeConfig;
  setThemeId: (id: string) => void;
  availableThemes: ThemeConfig[];
}

export const ThemeContext = createContext<ThemeContextValue | null>(null);

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return ctx;
}
