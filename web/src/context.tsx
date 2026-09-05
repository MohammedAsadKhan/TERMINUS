import { createContext, useContext } from 'react';
import type { User, OrgDetail, SystemInfo } from './types';

interface Session { user: User; orgId: string; detail?: OrgDetail; system?: SystemInfo }
export const SessionContext = createContext<Session | null>(null);
export function useSession() {
  const value = useContext(SessionContext);
  if (!value) throw new Error('Session provider missing');
  return value;
}
