import { createContext, useContext, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Alert, Button, Input } from 'antd';
import { Link, useSearchParams } from 'react-router-dom';
import { api, body } from './api';

type Message = { id: string; role: 'analyst' | 'assistant'; text: string; ticketId?: string; tools?: string[] };
type CopilotState = {
  messages: Message[];
  pending: boolean;
  error: string | null;
  send: (prompt: string, ticketId?: string) => Promise<void>;
  clear: () => void;
};

const CopilotContext = createContext<CopilotState | null>(null);

function inlineParts(value: string): ReactNode[] {
  return value.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).map((part, index) => {
    if (part.startsWith('`') && part.endsWith('`')) return <code key={index}>{part.slice(1, -1)}</code>;
    if (part.startsWith('**') && part.endsWith('**')) return <strong key={index}>{part.slice(2, -2)}</strong>;
    return part;
  });
}

export function ChatText({ text }: { text: string }) {
  const blocks: ReactNode[] = [];
  let bullets: string[] = [];
  const flush = () => {
    if (bullets.length) blocks.push(<ul key={`list-${blocks.length}`}>{bullets.map((line, index) => <li key={index}>{inlineParts(line)}</li>)}</ul>);
    bullets = [];
  };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (/^[-*]\s+/.test(line)) { bullets.push(line.replace(/^[-*]\s+/, '')); continue; }
    flush();
    if (!line) continue;
    blocks.push(<p key={`line-${blocks.length}`}>{inlineParts(line.replace(/^#{1,3}\s+/, ''))}</p>);
  }
  flush();
  return <div className="copilot-answer">{blocks}</div>;
}

export function CopilotProvider({ orgId, children }: { orgId: string; children: ReactNode }) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { setMessages([]); setError(null); }, [orgId]);

  async function send(prompt: string, ticketId?: string) {
    const value = prompt.trim();
    if (!value || pending) return;
    setPending(true);
    setError(null);
    setMessages(current => [...current, { id: crypto.randomUUID(), role: 'analyst', text: value, ticketId }]);
    try {
      const result = await api<{ response: string; tools_consulted: string[] }>('/copilot/chat', orgId, body('POST', { prompt: value, ticket_id: ticketId || null }));
      setMessages(current => [...current, { id: crypto.randomUUID(), role: 'assistant', text: result.response, ticketId, tools: result.tools_consulted }]);
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setPending(false);
    }
  }

  return <CopilotContext.Provider value={{ messages, pending, error, send, clear: () => { setMessages([]); setError(null); } }}>{children}</CopilotContext.Provider>;
}

function useCopilot() {
  const state = useContext(CopilotContext);
  if (!state) throw new Error('CopilotProvider is missing');
  return state;
}

export function CopilotPanel({ compact = false, ticketId }: { compact?: boolean; ticketId?: string }) {
  const { messages, pending, error, send, clear } = useCopilot();
  const [draft, setDraft] = useState('');
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => { end.current?.scrollIntoView({ block: 'end', behavior: 'smooth' }); }, [messages.length, pending]);
  function submit() { const value = draft.trim(); if (!value || pending) return; setDraft(''); void send(value, ticketId); }

  return <section className={`copilot-panel ${compact ? 'compact' : ''}`} aria-label="Terminus Copilot">
    <div className="copilot-panel-header"><div><span className="work-overline">ANALYST ASSISTANT</span><h2>Copilot</h2><p>Ask about current incidents and evidence.</p></div><div className="copilot-panel-header-actions">{messages.length > 0 && <Button size="small" type="text" onClick={clear}>Clear</Button>}{compact && <Link to="/copilot">Open full view</Link>}</div></div>
    {ticketId && <div className="copilot-focus">Incident context: <strong>{ticketId}</strong></div>}
    <div className="copilot-messages" role="log" aria-live="polite">
      {messages.length === 0 && <div className="copilot-empty"><h3>Start with a question</h3><p>The assistant can use incidents in your current organization. Check its answers against the source evidence.</p><div className="copilot-suggestions"><button onClick={() => void send('Summarize active incidents by severity.', ticketId)}>Summarize active incidents</button><button onClick={() => void send('Which active incident should I review first, and why?', ticketId)}>Prioritize my queue</button></div></div>}
      {messages.map(item => <div className={`copilot-message ${item.role}`} key={item.id}><span>{item.role === 'analyst' ? 'You' : 'Copilot'}{item.ticketId ? ` · ${item.ticketId}` : ''}</span>{item.role === 'assistant' ? <ChatText text={item.text} /> : <p>{item.text}</p>}{item.tools && item.tools.length > 0 && <small>Used: {Array.from(new Set(item.tools)).join(', ')}</small>}</div>)}
      {pending && <div className="copilot-working">Reviewing incident context…</div>}
      <div ref={end} />
    </div>
    <div className="copilot-composer">{error && <Alert type="error" showIcon title={error} closable />}<Input.TextArea aria-label="Message Copilot" rows={compact ? 2 : 3} placeholder="Ask a question about your incidents…" value={draft} onChange={event => setDraft(event.target.value)} onKeyDown={event => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); submit(); } }} /><div className="copilot-composer-footer"><span>Enter to send · Shift+Enter for a new line</span><Button type="primary" onClick={submit} disabled={!draft.trim()} loading={pending}>Send</Button></div></div>
  </section>;
}

export function CopilotPage() {
  const [params] = useSearchParams();
  const ticketId = params.get('ticket') || undefined;
  return <div className="copilot-page"><div className="work-page-header"><div><h1>Copilot</h1><p>Investigate incidents with a conversation grounded in your organization's current data.</p></div></div><CopilotPanel ticketId={ticketId} /></div>;
}
