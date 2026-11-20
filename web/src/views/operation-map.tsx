// File: operation-map.tsx
// Author: Team LARP
// Date: 2026-11-19 (comments revised)
// Version: 0.1.0
// Purpose: Display recorded orchestration tasks and their relationships.

import { Tag } from 'antd';
import { BranchesOutlined } from '@ant-design/icons';
import './operation-map.css';

// A task in the delegation tree; parent is the id of the task that delegated it.
export interface OperationNode {
  id: string; parent?: string | null; label: string; status: string; activity: string;
}

// Shows tasks grouped by delegation depth, coordinator first. Display only: the caller supplies either recorded
// tasks or the scripted simulation, and handles selection.
export default function OperationMap({ nodes, onSelect }: { nodes: OperationNode[]; onSelect: (id: string) => void }) {
  const ids = new Set(nodes.map(node => node.id));
  // Counts how many ancestors exist in this list. The seen set stops a cyclic parent chain from looping, and a parent
  // that is not in the list is treated as no parent.
  function depth(node: OperationNode): number {
    let level = 0; let cursor = node; const seen = new Set([node.id]);
    while (cursor.parent && ids.has(cursor.parent) && !seen.has(cursor.parent)) {
      seen.add(cursor.parent); cursor = nodes.find(item => item.id === cursor.parent)!; level++;
    }
    return level;
  }
  return <div className="operation-map" aria-label="Agent delegation map">
    {[...new Set(nodes.map(depth))].sort((a, b) => a - b).map(level => <div className="operation-map-level" key={level}>
      {nodes.filter(node => depth(node) === level).map(node => <button key={node.id} aria-label={`Inspect delegation node ${node.id}`} className={`operation-map-node state-${node.status}`} onClick={() => onSelect(node.id)}>
        <span className="operation-map-parent">{node.parent ? `Delegated by ${nodes.find(item => item.id === node.parent)?.label || 'recorded parent'}` : 'Operation coordinator'}</span>
        <strong><BranchesOutlined /> {node.label}</strong>
        <Tag color={node.status === 'running' ? 'processing' : node.status === 'completed' ? 'success' : 'default'}>{node.status}</Tag>
        <p>{node.activity}</p>
      </button>)}
    </div>)}
  </div>;
}
