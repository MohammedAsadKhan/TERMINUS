// File: asset-types.ts
// Author: Team LARP
// Date: 2026-11-19 (comments revised)
// Version: 0.1.0
// Purpose: Define asset kinds and the data displayed by the inventory views.

// Asset categories shown in the sidebar and inventory; kind values match the backend asset kinds.
export const ASSET_KINDS = [
  { kind: 'repository', label: 'Repositories', singular: 'repository', hint: 'Repository URL or owner/name' },
  { kind: 'container', label: 'Containers', singular: 'container', hint: 'Image name, digest, or Docker workload' },
  { kind: 'cloud', label: 'Cloud accounts', singular: 'cloud account', hint: 'Provider and account identifier' },
  { kind: 'virtual_machine', label: 'Virtual machines', singular: 'virtual machine', hint: 'Hostname or instance identifier' },
  { kind: 'domain', label: 'Domains', singular: 'domain', hint: 'Domain name' },
  { kind: 'device', label: 'Devices', singular: 'device', hint: 'Hostname or device identifier' },
] as const;

// Union types derived from the list above so the UI and the labels cannot drift apart.
export type AssetKind = typeof ASSET_KINDS[number]['kind'];
// Criticality tiers; tier0 is the most critical.
export type AssetCriticality = 'tier0' | 'tier1' | 'tier2' | 'tier3';
// Whether an asset is reachable from the internet or only internally.
export type AssetExposure = 'internal' | 'internet';

// One inventory record as returned by the assets API for the signed-in organization. Fields marked optional
// are only present for some sources, and coverage is open-ended so new backend states still render.
export interface Asset {
  asset_id: string;
  org_id: string;
  kind: AssetKind;
  name: string;
  locator: string | null;
  notes: string | null;
  source?: string;
  agent_id?: string | null;
  hostname?: string | null;
  criticality?: AssetCriticality | null;
  owner?: string | null;
  environment?: string | null;
  exposure?: AssetExposure | null;
  created_at: string;
  coverage: 'scanned' | 'stale' | 'never_scanned' | 'scan_failed' | 'not_connected' | string;
}

