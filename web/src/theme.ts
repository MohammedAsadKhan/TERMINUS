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
  emerald: {
    id: 'emerald',
    name: 'Emerald Sentinel',
    category: 'Cyber Defense',
    description: 'Classic stealth security operations terminal with phosphor mint accents',
    primaryColor: '#a4dfba',
    primaryHover: '#c1efd1',
    bgBase: '#101717',
    bgSurface: '#141d1b',
    bgPanel: '#17201c',
    borderColor: '#2b3831',
    textMain: '#edf2ec',
    textMuted: '#9caaa5',
    menuSelectedBg: '#23392d',
    menuSelectedColor: '#c1efd1',
    tableHeaderBg: '#1c2725',
    tableHoverBg: '#202e29',
    swatches: ['#a4dfba', '#17201c', '#101717'],
  },
  cobalt: {
    id: 'cobalt',
    name: 'Cobalt Radar',
    category: 'Naval Intelligence',
    description: 'Deep oceanic blues with high-contrast electric cyber telemetry',
    primaryColor: '#38bdf8',
    primaryHover: '#7dd3fc',
    bgBase: '#080f1d',
    bgSurface: '#0e182e',
    bgPanel: '#13223f',
    borderColor: '#223559',
    textMain: '#f0f6fc',
    textMuted: '#94a3b8',
    menuSelectedBg: '#1d3663',
    menuSelectedColor: '#7dd3fc',
    tableHeaderBg: '#182b4d',
    tableHoverBg: '#1f3661',
    swatches: ['#38bdf8', '#13223f', '#080f1d'],
  },
  amber: {
    id: 'amber',
    name: 'Tactical Amber',
    category: 'Industrial Defense',
    description: 'High-contrast solar amber HUD engineered for mission-critical response',
    primaryColor: '#f59e0b',
    primaryHover: '#fbbf24',
    bgBase: '#141009',
    bgSurface: '#1c160e',
    bgPanel: '#251d13',
    borderColor: '#3d2f20',
    textMain: '#fef3c7',
    textMuted: '#a89a84',
    menuSelectedBg: '#3d2b14',
    menuSelectedColor: '#fbbf24',
    tableHeaderBg: '#2d2317',
    tableHoverBg: '#382b1d',
    swatches: ['#f59e0b', '#251d13', '#141009'],
  },
  phantom: {
    id: 'phantom',
    name: 'Phantom Violet',
    category: 'Threat Research',
    description: 'Deep obsidian matrix paired with radioactive ultraviolet accents',
    primaryColor: '#c084fc',
    primaryHover: '#d8b4fe',
    bgBase: '#100a1c',
    bgSurface: '#171026',
    bgPanel: '#201735',
    borderColor: '#352654',
    textMain: '#f5f3ff',
    textMuted: '#a79cb8',
    menuSelectedBg: '#381f5c',
    menuSelectedColor: '#d8b4fe',
    tableHeaderBg: '#271c40',
    tableHoverBg: '#312352',
    swatches: ['#c084fc', '#201735', '#100a1c'],
  },
  crimson: {
    id: 'crimson',
    name: 'Crimson Threat',
    category: 'Red Team Ops',
    description: 'Aggressive tactical red team theme optimized for active breach monitoring',
    primaryColor: '#f43f5e',
    primaryHover: '#fb7185',
    bgBase: '#180b0e',
    bgSurface: '#221014',
    bgPanel: '#2c151b',
    borderColor: '#48232c',
    textMain: '#fff1f2',
    textMuted: '#b89ca2',
    menuSelectedBg: '#481822',
    menuSelectedColor: '#fb7185',
    tableHeaderBg: '#361a22',
    tableHoverBg: '#44202a',
    swatches: ['#f43f5e', '#2c151b', '#180b0e'],
  },
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
