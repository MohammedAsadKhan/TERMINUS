import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { App as AntApp, ConfigProvider, theme } from 'antd';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { ConsoleApp } from './shell';
import { THEMES, ThemeContext, applyThemeVariables } from './theme';
import 'antd/dist/reset.css';
import './styles.css';

const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 15000 }, mutations: { retry: false } } });

function Root() {
  const [themeId, setThemeIdState] = useState<string>(() => localStorage.getItem('terminus_theme_id') || 'emerald');
  const activeTheme = THEMES[themeId] || THEMES.emerald;

  const setThemeId = (id: string) => {
    if (THEMES[id]) {
      setThemeIdState(id);
      localStorage.setItem('terminus_theme_id', id);
      applyThemeVariables(THEMES[id]);
    }
  };

  useEffect(() => {
    applyThemeVariables(activeTheme);
  }, [activeTheme]);

  return (
    <ThemeContext.Provider value={{ themeId, activeTheme, setThemeId, availableThemes: Object.values(THEMES) }}>
      <ConfigProvider theme={{
        algorithm: theme.darkAlgorithm,
        token: {
          colorPrimary: activeTheme.primaryColor,
          colorInfo: activeTheme.primaryColor,
          colorBgBase: activeTheme.bgBase,
          colorBgContainer: activeTheme.bgPanel,
          colorBorder: activeTheme.borderColor,
          colorText: activeTheme.textMain,
          colorTextSecondary: activeTheme.textMuted,
          borderRadius: 7,
          fontFamily: "'Segoe UI', system-ui, sans-serif",
          fontSize: 13,
          controlHeight: 36,
        },
        components: {
          Table: { headerBg: activeTheme.tableHeaderBg, rowHoverBg: activeTheme.tableHoverBg },
          Button: { primaryColor: activeTheme.bgBase, fontWeight: 600 },
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
