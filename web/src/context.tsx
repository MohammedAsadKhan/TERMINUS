// File: context.tsx
// Author: Team LARP
// Date: 2026-11-19 (comments revised)
// Version: 0.1.0
// Purpose: Expose the active console session and organization to child views.

import { createContext, useContext } from 'react';
import type { User, OrgDetail, SystemInfo } from './types';

// What every view needs to know about the signed-in session. orgId scopes API calls to one organization;
// detail (role, members, license) and system (platform info) stay undefined until their queries resolve.
interface Session {
  user: User;
  orgId: string;
  detail?: OrgDetail;
  system?: SystemInfo;
}
// Provided by the console shell once a user is signed in.
export const SessionContext = createContext<Session | null>(null);
// Returns the active session; throws if used outside the shell so a view cannot run without a user and organization.
export function useSession() {
  const value = useContext(SessionContext);
  if (!value) throw new Error('Session provider missing');
  return value;
}
