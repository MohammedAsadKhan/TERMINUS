import { createContext, useContext, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Alert, Badge, Button, Empty, Input, Popconfirm, Tag, Tooltip } from 'antd';
import {
  ClockCircleOutlined,
  DeleteOutlined,
  HistoryOutlined,
  MessageOutlined,
  PlusOutlined,
  RobotOutlined,
  SendOutlined,
} from '@ant-design/icons';
import { Link, useSearchParams } from 'react-router-dom';
import { api, body } from './api';

export type Message = { id: string; role: 'analyst' | 'assistant'; text: string; ticketId?: string; tools?: string[]; timestamp?: string };

export type CopilotSession = {
  id: string;
  title: string;
  created_at: string;
  updated_at: string;
  ticketId?: string;
  messages: Message[];
};

type CopilotState = {
  sessions: CopilotSession[];
  currentSessionId: string | null;
  messages: Message[];
  pending: boolean;
  error: string | null;
  send: (prompt: string, ticketId?: string) => Promise<void>;
  startNewSession: (ticketId?: string) => void;
  switchSession: (sessionId: string) => void;
  deleteSession: (sessionId: string) => void;
  clearAllSessions: () => void;
  clearCurrentMessages: () => void;
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

function formatRelativeTime(isoStr?: string): string {
  if (!isoStr) return 'Just now';
  const diff = Date.now() - Date.parse(isoStr);
  if (!Number.isFinite(diff) || diff < 60000) return 'Just now';
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return new Date(isoStr).toLocaleDateString([], { month: 'short', day: 'numeric' });
}

export function CopilotProvider({ orgId, children }: { orgId: string; children: ReactNode }) {
  const storageKey = `terminus_copilot_sessions_${orgId}`;
  const [sessions, setSessions] = useState<CopilotSession[]>(() => {
    try {
      const raw = localStorage.getItem(storageKey);
      if (raw) return JSON.parse(raw);
    } catch {
      // Ignore parse failure
    }
    return [];
  });

  const [currentSessionId, setCurrentSessionId] = useState<string | null>(() => {
    return sessions.length > 0 ? sessions[0].id : null;
  });

  const [messages, setMessages] = useState<Message[]>(() => {
    if (sessions.length > 0) return sessions[0].messages;
    return [];
  });

  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Sync sessions to localStorage
  useEffect(() => {
    try {
      localStorage.setItem(storageKey, JSON.stringify(sessions));
    } catch {
      // Ignore quota error
    }
  }, [sessions, storageKey]);

  // Handle org change
  useEffect(() => {
    try {
      const raw = localStorage.getItem(`terminus_copilot_sessions_${orgId}`);
      if (raw) {
        const loaded: CopilotSession[] = JSON.parse(raw);
        setSessions(loaded);
        if (loaded.length > 0) {
          setCurrentSessionId(loaded[0].id);
          setMessages(loaded[0].messages);
        } else {
          setCurrentSessionId(null);
          setMessages([]);
        }
      } else {
        setSessions([]);
        setCurrentSessionId(null);
        setMessages([]);
      }
    } catch {
      setSessions([]);
      setMessages([]);
    }
    setError(null);
  }, [orgId]);

  function startNewSession(ticketId?: string) {
    const newSession: CopilotSession = {
      id: crypto.randomUUID(),
      title: ticketId ? `Incident ${ticketId} Dossier` : 'New Investigation Session',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      ticketId,
      messages: [],
    };
    setSessions(prev => [newSession, ...prev]);
    setCurrentSessionId(newSession.id);
    setMessages([]);
    setError(null);
  }

  function switchSession(sessionId: string) {
    const found = sessions.find(s => s.id === sessionId);
    if (found) {
      setCurrentSessionId(found.id);
      setMessages(found.messages);
      setError(null);
    }
  }

  function deleteSession(sessionId: string) {
    setSessions(prev => {
      const updated = prev.filter(s => s.id !== sessionId);
      if (currentSessionId === sessionId) {
        if (updated.length > 0) {
          setCurrentSessionId(updated[0].id);
          setMessages(updated[0].messages);
        } else {
          setCurrentSessionId(null);
          setMessages([]);
        }
      }
      return updated;
    });
  }

  function clearAllSessions() {
    setSessions([]);
    setCurrentSessionId(null);
    setMessages([]);
    setError(null);
  }

  function clearCurrentMessages() {
    if (!currentSessionId) {
      setMessages([]);
      return;
    }
    setMessages([]);
    setSessions(prev =>
      prev.map(s => (s.id === currentSessionId ? { ...s, messages: [], updated_at: new Date().toISOString() } : s))
    );
  }

  async function send(prompt: string, ticketId?: string) {
    const value = prompt.trim();
    if (!value || pending) return;
    setPending(true);
    setError(null);

    const nowIso = new Date().toISOString();
    const userMsg: Message = {
      id: crypto.randomUUID(),
      role: 'analyst',
      text: value,
      ticketId,
      timestamp: nowIso,
    };

    let activeSessionId = currentSessionId;
    let isBrandNewSession = false;

    if (!activeSessionId) {
      activeSessionId = crypto.randomUUID();
      isBrandNewSession = true;
    }

    const nextMessages = [...messages, userMsg];
    setMessages(nextMessages);

    // Derive concise title
    const shortTitle = value.length > 42 ? `${value.slice(0, 40)}...` : value;

    if (isBrandNewSession) {
      const newSession: CopilotSession = {
        id: activeSessionId,
        title: shortTitle,
        created_at: nowIso,
        updated_at: nowIso,
        ticketId,
        messages: nextMessages,
      };
      setSessions(prev => [newSession, ...prev]);
      setCurrentSessionId(activeSessionId);
    } else {
      setSessions(prev =>
        prev.map(s => {
          if (s.id === activeSessionId) {
            const hasTitle = s.title && s.title !== 'New Investigation Session';
            return {
              ...s,
              title: hasTitle ? s.title : shortTitle,
              messages: nextMessages,
              updated_at: nowIso,
            };
          }
          return s;
        })
      );
    }

    try {
      const result = await api<{ response: string; tools_consulted: string[] }>(
        '/copilot/chat',
        orgId,
        body('POST', { prompt: value, ticket_id: ticketId || null })
      );

      const assistantMsg: Message = {
        id: crypto.randomUUID(),
        role: 'assistant',
        text: result.response,
        ticketId,
        tools: result.tools_consulted,
        timestamp: new Date().toISOString(),
      };

      const finalMessages = [...nextMessages, assistantMsg];
      setMessages(finalMessages);

      setSessions(prev =>
        prev.map(s => (s.id === activeSessionId ? { ...s, messages: finalMessages, updated_at: new Date().toISOString() } : s))
      );
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setPending(false);
    }
  }

  return (
    <CopilotContext.Provider
      value={{
        sessions,
        currentSessionId,
        messages,
        pending,
        error,
        send,
        startNewSession,
        switchSession,
        deleteSession,
        clearAllSessions,
        clearCurrentMessages,
      }}
    >
      {children}
    </CopilotContext.Provider>
  );
}

function useCopilot() {
  const state = useContext(CopilotContext);
  if (!state) throw new Error('CopilotProvider is missing');
  return state;
}

export function CopilotPanel({ compact = false, ticketId }: { compact?: boolean; ticketId?: string }) {
  const {
    sessions,
    currentSessionId,
    messages,
    pending,
    error,
    send,
    startNewSession,
    switchSession,
    deleteSession,
    clearAllSessions,
    clearCurrentMessages,
  } = useCopilot();

  const [draft, setDraft] = useState('');
  const [historyOpen, setHistoryOpen] = useState(false);
  const end = useRef<HTMLDivElement>(null);
  const scrollContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    end.current?.scrollIntoView({ block: 'end', behavior: 'smooth' });
  }, [messages.length, pending]);

  function submit() {
    const value = draft.trim();
    if (!value || pending) return;
    setDraft('');
    void send(value, ticketId);
  }

  return (
    <section className={`copilot-panel ${compact ? 'compact' : ''}`} aria-label="Terminus Copilot">
      {/* Header with Title and Slide-out History Button */}
      <div className="copilot-panel-header">
        <div className="copilot-header-brand">
          <RobotOutlined style={{ color: 'var(--accent)', fontSize: 17 }} />
          <div className="copilot-title-group">
            <span className="copilot-eyebrow">AI SOC INVESTIGATION</span>
            <h2 className="copilot-main-title">Copilot Assistant</h2>
          </div>
        </div>

        <div className="copilot-panel-header-actions">
          <Tooltip title="Start fresh conversation session">
            <Button
              size="small"
              icon={<PlusOutlined />}
              onClick={() => {
                startNewSession(ticketId);
                setHistoryOpen(false);
              }}
            >
              New
            </Button>
          </Tooltip>

          <Button
            size="small"
            icon={<HistoryOutlined />}
            className={historyOpen ? 'active-history-btn' : ''}
            onClick={() => setHistoryOpen(!historyOpen)}
          >
            History {sessions.length > 0 && <Badge count={sessions.length} size="small" style={{ marginLeft: 4 }} />}
          </Button>

          {messages.length > 0 && (
            <Button size="small" type="text" onClick={clearCurrentMessages}>
              Clear
            </Button>
          )}

          {compact && <Link to="/copilot">Open full view</Link>}
        </div>
      </div>

      {ticketId && (
        <div className="copilot-focus">
          Incident context: <strong>{ticketId}</strong>
        </div>
      )}

      {/* Main Relative Wrap for Scrollable Messages + Slide-Out History Drawer */}
      <div className="copilot-content-wrap">
        {/* Scrollable Chat Messages Container with mousewheel support */}
        <div className="copilot-messages" ref={scrollContainerRef} role="log" aria-live="polite">
          {messages.length === 0 && (
            <div className="copilot-empty">
              <RobotOutlined style={{ fontSize: 32, color: 'var(--accent)', opacity: 0.8, marginBottom: 10 }} />
              <h3>Autonomous SOC Assistant</h3>
              <p>
                Grounded on live Wazuh telemetry, MITRE ATT&amp;CK correlation, and active containment guardrails across your workspace.
              </p>
              <div className="copilot-suggestions">
                <button type="button" onClick={() => void send('Summarize active incidents by severity.', ticketId)}>
                  Summarize active incidents
                </button>
                <button type="button" onClick={() => void send('Which active incident should I review first, and why?', ticketId)}>
                  Prioritize my queue
                </button>
                <button type="button" onClick={() => void send('Verify why dc01.corp.internal cannot be isolated.', ticketId)}>
                  Check Tier-0 guardrails
                </button>
              </div>
            </div>
          )}

          {messages.map(item => (
            <div className={`copilot-message ${item.role}`} key={item.id}>
              <span className="copilot-message-author">
                {item.role === 'analyst' ? 'You (SOC Lead)' : 'TERMINUS Copilot'}
                {item.ticketId ? ` · ${item.ticketId}` : ''}
                {item.timestamp && <small className="copilot-msg-time">{formatRelativeTime(item.timestamp)}</small>}
              </span>
              {item.role === 'assistant' ? <ChatText text={item.text} /> : <p>{item.text}</p>}
              {item.tools && item.tools.length > 0 && (
                <div className="copilot-tools-tag-row">
                  <small>Consulted Evidence:</small>
                  {Array.from(new Set(item.tools)).map(t => (
                    <Tag key={t} color="geekblue" style={{ fontSize: 9.5, margin: 0, padding: '0 4px' }}>
                      {t}
                    </Tag>
                  ))}
                </div>
              )}
            </div>
          ))}

          {pending && (
            <div className="copilot-working">
              <span className="copilot-spinner-pulse" />
              <span>Analyzing live incident dossier &amp; querying threat intelligence...</span>
            </div>
          )}

          <div ref={end} />
        </div>

        {/* Slide-Out Chat History Drawer with Smooth Slide Animation */}
        <div className={`copilot-history-drawer ${historyOpen ? 'open' : ''}`}>
          <div className="history-drawer-header">
            <div className="history-header-title">
              <HistoryOutlined style={{ color: 'var(--accent)' }} />
              <strong>Session History</strong>
            </div>
            <div className="history-header-actions">
              <Button
                size="small"
                type="primary"
                icon={<PlusOutlined />}
                onClick={() => {
                  startNewSession(ticketId);
                  setHistoryOpen(false);
                }}
              >
                New Chat
              </Button>
              <Button size="small" type="text" onClick={() => setHistoryOpen(false)}>
                ✕
              </Button>
            </div>
          </div>

          <div className="history-drawer-list">
            {sessions.length === 0 ? (
              <Empty description="No saved sessions" image={Empty.PRESENTED_IMAGE_SIMPLE} style={{ marginTop: 40 }} />
            ) : (
              sessions.map(s => {
                const isSelected = s.id === currentSessionId;
                return (
                  <div
                    key={s.id}
                    className={`history-session-item ${isSelected ? 'selected' : ''}`}
                    onClick={() => {
                      switchSession(s.id);
                      setHistoryOpen(false);
                    }}
                  >
                    <div className="history-item-top">
                      <div className="history-item-title-wrap">
                        {isSelected && <span className="history-active-indicator" />}
                        <strong className="history-item-title">{s.title || 'Untitled Session'}</strong>
                      </div>
                      <Popconfirm
                        title="Delete this session?"
                        onConfirm={e => {
                          e?.stopPropagation();
                          deleteSession(s.id);
                        }}
                        onCancel={e => e?.stopPropagation()}
                        okText="Delete"
                        cancelText="Cancel"
                        okButtonProps={{ danger: true }}
                      >
                        <Button
                          size="small"
                          type="text"
                          danger
                          icon={<DeleteOutlined />}
                          className="history-delete-btn"
                          onClick={e => e.stopPropagation()}
                        />
                      </Popconfirm>
                    </div>

                    <div className="history-item-meta">
                      <span>
                        <ClockCircleOutlined /> {formatRelativeTime(s.updated_at || s.created_at)}
                      </span>
                      <span>
                        <MessageOutlined /> {s.messages.length} msg{s.messages.length === 1 ? '' : 's'}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {sessions.length > 0 && (
            <div className="history-drawer-footer">
              <Popconfirm
                title="Clear all chat history?"
                description="This will permanently delete all stored investigation sessions."
                onConfirm={clearAllSessions}
                okText="Clear All"
                cancelText="Cancel"
                okButtonProps={{ danger: true }}
              >
                <Button size="small" danger block icon={<DeleteOutlined />}>
                  Clear All History
                </Button>
              </Popconfirm>
            </div>
          )}
        </div>
      </div>

      {/* Input Composer Footer */}
      <div className="copilot-composer">
        {error && <Alert type="error" showIcon title={error} closable style={{ marginBottom: 8 }} />}
        <Input.TextArea
          aria-label="Message Copilot"
          rows={compact ? 2 : 3}
          placeholder="Ask a question about your incidents or query threat telemetry…"
          value={draft}
          onChange={event => setDraft(event.target.value)}
          onKeyDown={event => {
            if (event.key === 'Enter' && !event.shiftKey) {
              event.preventDefault();
              submit();
            }
          }}
        />
        <div className="copilot-composer-footer">
          <span>Enter to send · Shift+Enter for a new line</span>
          <Button type="primary" icon={<SendOutlined />} onClick={submit} disabled={!draft.trim()} loading={pending}>
            Send
          </Button>
        </div>
      </div>
    </section>
  );
}

export function CopilotPage() {
  const [params] = useSearchParams();
  const ticketId = params.get('ticket') || undefined;
  return (
    <div className="copilot-page">
      <div className="work-page-header">
        <div>
          <h1>Copilot</h1>
          <p>Investigate incidents with a conversation grounded in your organization's current data.</p>
        </div>
      </div>
      <CopilotPanel ticketId={ticketId} />
    </div>
  );
}
