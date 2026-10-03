export const ASSET_KINDS = [
  { kind: 'repository', label: 'Repositories', singular: 'repository', hint: 'Repository URL or owner/name' },
  { kind: 'container', label: 'Containers', singular: 'container', hint: 'Image name, digest, or Docker workload' },
  { kind: 'cloud', label: 'Cloud accounts', singular: 'cloud account', hint: 'Provider and account identifier' },
  { kind: 'virtual_machine', label: 'Virtual machines', singular: 'virtual machine', hint: 'Hostname or instance identifier' },
  { kind: 'domain', label: 'Domains', singular: 'domain', hint: 'Domain name' },
  { kind: 'device', label: 'Devices', singular: 'device', hint: 'Hostname or device identifier' },
] as const;

export type AssetKind = typeof ASSET_KINDS[number]['kind'];
export interface Asset {
  asset_id: string;
  org_id: string;
  kind: AssetKind;
  name: string;
  locator: string | null;
  notes: string | null;
  created_at: string;
  coverage: 'not_connected';
}
