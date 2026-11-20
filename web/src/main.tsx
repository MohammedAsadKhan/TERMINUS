// File: main.tsx
// Author: Team LARP
// Date: 2026-11-19 (comments revised)
// Version: 0.1.0
// Purpose: Mount the React console with routing, query caching, and the dark default theme.

import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { App as AntApp, ConfigProvider, theme } from 'antd';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { ConsoleApp } from './shell';
import { THEMES, ThemeContext, applyThemeVariables } from './theme';
import 'antd/dist/reset.css';
import './styles.css';
import './design.css';
import './workbench.css';
import './investigation-graph.css';
import './workspace.css';

// Shared query cache. Failed requests are not retried automatically, and data is treated as fresh for 15 seconds.
const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 15000 }, mutations: { retry: false } } });

// Top-level providers: theme, Ant Design theme tokens, query cache and routing under the /console base path.
function Root() {
  // Preserve an analyst's explicit choice; first-time sessions start in the SOC's dark theme.
  const [themeId, setThemeIdState] = useState<string>(() => localStorage.getItem('terminus_theme_id') || 'carbon');
  const activeTheme = THEMES[themeId] || THEMES.carbon;

  // Applies and saves a theme only if it is a known theme id.
  const setThemeId = (id: string) => {
    if (THEMES[id]) {
      setThemeIdState(id);
      localStorage.setItem('terminus_theme_id', id);
      applyThemeVariables(THEMES[id]);
    }
  };

  // Re-applies the CSS variables whenever the active theme changes, including on first load.
  useEffect(() => {
    applyThemeVariables(activeTheme);
  }, [activeTheme]);

  return (
    <ThemeContext.Provider value={{ themeId, activeTheme, setThemeId, availableThemes: Object.values(THEMES) }}>
      <ConfigProvider theme={{
        algorithm: activeTheme.id === 'workspace' ? theme.defaultAlgorithm : theme.darkAlgorithm,
        token: {
          colorPrimary: activeTheme.primaryColor,
          colorInfo: activeTheme.primaryColor,
          colorBgBase: activeTheme.bgBase,
          colorBgContainer: activeTheme.bgPanel,
          colorBorder: activeTheme.borderColor,
          colorText: activeTheme.textMain,
          colorTextSecondary: activeTheme.textMuted,
          borderRadius: 6,
          fontFamily: "'Segoe UI', system-ui, sans-serif",
          fontSize: 13,
          controlHeight: 34,
        },
        components: {
          Table: { headerBg: activeTheme.tableHeaderBg, rowHoverBg: activeTheme.tableHoverBg },
          Button: { primaryColor: activeTheme.id === 'workspace' ? '#ffffff' : activeTheme.bgBase, fontWeight: 600 },
          Menu: { itemBg: 'transparent', itemSelectedBg: activeTheme.menuSelectedBg, itemSelectedColor: activeTheme.menuSelectedColor },
        }
      }}>
        <AntApp>
          <QueryClientProvider client={client}>
            <BrowserRouter basename="/console">
              <ConsoleApp />
            </BrowserRouter>
          </QueryClientProvider>
        </AntApp>
      </ConfigProvider>
    </ThemeContext.Provider>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
);
