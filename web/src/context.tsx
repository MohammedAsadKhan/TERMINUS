// File: context.tsx
// Author: Team LARP
// Date: 2026-11-09
// Version: 0.1.0
// Purpose: Expose the active console session and organization to child views.

import { createContext, useContext } from 'react';
import type { User, OrgDetail, SystemInfo } from './types';

interface Session {
  user: User;
  orgId: string;
  detail?: OrgDetail;
  system?: SystemInfo;
}
export const SessionContext = createContext<Session | null>(null);
export function useSession() {
  const value = useContext(SessionContext);
  if (!value) throw new Error('Session provider missing');
  return value;
}
