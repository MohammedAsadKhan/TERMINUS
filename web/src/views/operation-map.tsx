import { Tag } from 'antd';
import { BranchesOutlined } from '@ant-design/icons';
import './operation-map.css';

export interface OperationNode {
  id: string; parent?: string | null; label: string; status: string; activity: string;
}

export default function OperationMap({ nodes, onSelect }: { nodes: OperationNode[]; onSelect: (id: string) => void }) {
  const ids = new Set(nodes.map(node => node.id));
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
