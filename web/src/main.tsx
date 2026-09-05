import React from 'react';
import ReactDOM from 'react-dom/client';
import { App as AntApp, ConfigProvider, theme } from 'antd';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { ConsoleApp } from './shell';
import 'antd/dist/reset.css';
import './styles.css';

const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 15000 }, mutations: { retry: false } } });
ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode><ConfigProvider theme={{ algorithm: theme.darkAlgorithm, token: {
    colorPrimary: '#a4dfba', colorInfo: '#a4dfba', colorBgBase: '#101717', colorBgContainer: '#172020',
    colorBorder: '#303c3a', colorText: '#edf2ec', colorTextSecondary: '#9caaa5', borderRadius: 7,
    fontFamily: "'Segoe UI', system-ui, sans-serif", fontSize: 13, controlHeight: 36,
  }, components: { Table: { headerBg: '#1c2725', rowHoverBg: '#202e29' }, Button: { primaryColor: '#101b14', fontWeight: 600 }, Menu: { itemBg: 'transparent', itemSelectedBg: '#25382d', itemSelectedColor: '#c1efd1' } } }}>
    <AntApp><QueryClientProvider client={client}><BrowserRouter basename="/console"><ConsoleApp /></BrowserRouter></QueryClientProvider></AntApp>
  </ConfigProvider></React.StrictMode>,
);
