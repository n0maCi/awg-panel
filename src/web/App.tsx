import { type FormEvent, useCallback, useEffect, useRef, useState } from 'react';
import {
  ArchiveRestore, Check, Copy, Download, KeyRound, LogOut, Plus, QrCode,
  Shield, Trash2, UserRound, Users, X,
} from 'lucide-react';
import type { DashboardData, PeerView } from '../shared/types';
import { api, ApiError, download } from './api';

type Notice = { kind: 'success' | 'error'; text: string } | null;

function Logo() {
  return <div className="logo" aria-label="AmneziaWG">
    <span className="brand-mark" aria-hidden="true"><i /><i /><i /><i /></span>
    <span>AmneziaWG</span>
  </div>;
}

function Login({ onSuccess }: { onSuccess: () => void }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError('');
    try {
      await api.login(password);
      onSuccess();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Не удалось войти');
    } finally {
      setLoading(false);
    }
  }

  return <main className="login-shell">
    <div className="login-glow" />
    <section className="login-card">
      <Logo />
      <div className="login-icon"><KeyRound size={28} /></div>
      <h1>Добро пожаловать</h1>
      <p>Введите пароль администратора, чтобы управлять конфигурациями.</p>
      <form onSubmit={submit}>
        <label htmlFor="password">Пароль</label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          placeholder="••••••••••••"
          autoFocus
          autoComplete="current-password"
        />
        {error && <div className="form-error">{error}</div>}
        <button className="primary wide" disabled={loading || !password}>
          {loading ? 'Проверяем…' : 'Войти'}
        </button>
      </form>
      <div className="secure-note"><Shield size={14} /> Сессия хранится только в защищённой cookie</div>
    </section>
  </main>;
}

function Modal({ children, onClose, label }: { children: React.ReactNode; onClose: () => void; label: string }) {
  useEffect(() => {
    const close = (event: KeyboardEvent) => event.key === 'Escape' && onClose();
    window.addEventListener('keydown', close);
    return () => window.removeEventListener('keydown', close);
  }, [onClose]);
  return <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
    <section className="modal" role="dialog" aria-modal="true" aria-label={label}>
      <button className="icon-button modal-close" onClick={onClose} aria-label="Закрыть"><X size={19} /></button>
      {children}
    </section>
  </div>;
}

function CreatePeerModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => Promise<void> }) {
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  async function submit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError('');
    try {
      await api.createPeer(name);
      await onCreated();
      onClose();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Не удалось создать конфигурацию');
    } finally {
      setLoading(false);
    }
  }
  return <Modal onClose={onClose} label="Новая конфигурация">
    <div className="modal-heading"><div className="modal-icon"><Plus size={22} /></div><div><h2>Новая конфигурация</h2><p>Ключи и адрес будут созданы автоматически.</p></div></div>
    <form onSubmit={submit}>
      <label htmlFor="peer-name">Название</label>
      <input id="peer-name" value={name} onChange={(event) => setName(event.target.value)} placeholder="Например, iPhone" autoFocus maxLength={64} />
      {error && <div className="form-error">{error}</div>}
      <div className="modal-actions"><button type="button" className="secondary" onClick={onClose}>Отмена</button><button className="primary" disabled={!name.trim() || loading}>{loading ? 'Создаём…' : 'Создать'}</button></div>
    </form>
  </Modal>;
}

function QrModal({ peer, onClose }: { peer: PeerView; onClose: () => void }) {
  return <Modal onClose={onClose} label={`QR-код ${peer.name}`}>
    <div className="qr-heading"><span className="eyebrow">БЫСТРОЕ ПОДКЛЮЧЕНИЕ</span><h2>{peer.name}</h2><p>Отсканируйте код в приложении AmneziaWG.</p></div>
    <div className="qr-frame"><img src={`/api/peers/${peer.id}/qr`} alt={`QR-код конфигурации ${peer.name}`} /></div>
    <button className="secondary wide" onClick={onClose}>Готово</button>
  </Modal>;
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} Б`;
  const units = ['КБ', 'МБ', 'ГБ', 'ТБ'];
  let current = value / 1024;
  let index = 0;
  while (current >= 1024 && index < units.length - 1) { current /= 1024; index += 1; }
  return `${current.toFixed(current >= 10 ? 0 : 1)} ${units[index]}`;
}

function formatRelativeHandshake(value: string | null): string {
  if (!value) return 'ещё не подключался';
  const elapsed = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 1000));
  if (elapsed < 10) return 'только что';
  if (elapsed < 60) return `${elapsed} сек. назад`;
  const minutes = Math.floor(elapsed / 60);
  if (minutes < 60) return `${minutes} мин. назад`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} ч. назад`;
  const days = Math.floor(hours / 24);
  return `${days} дн. назад`;
}

function PeerRow({ peer, busy, locked, onToggle, onDelete, onQr, onDownload }: {
  peer: PeerView; busy: boolean; locked: boolean; onToggle: () => void; onDelete: () => void; onQr: () => void; onDownload: () => void;
}) {
  return <div className={`peer-row ${!peer.enabled ? 'disabled' : ''}`}>
    <div className="peer-main">
      <span className="peer-avatar-wrap">
        <span className="peer-avatar"><UserRound size={27} strokeWidth={2.4} /></span>
        {peer.enabled && peer.online && <span className="online-indicator" title="В сети" />}
      </span>
      <div className="peer-copy">
        <strong>{peer.name}</strong>
        <span className="peer-meta">
          <span>{peer.address}</span>
          {peer.enabled && <><i>·</i><span>↓ {formatBytes(peer.receivedBytes)}/с</span><i>·</i><span>↑ {formatBytes(peer.sentBytes)}/с</span><i>·</i><span>{formatRelativeHandshake(peer.latestHandshakeAt)}</span></>}
          {!peer.enabled && <><i>·</i><span>доступ отключён</span></>}
        </span>
      </div>
    </div>
    <div className="peer-actions">
      <button className={`peer-toggle ${peer.enabled ? 'enabled' : ''}`} onClick={onToggle} disabled={busy || locked} aria-label={peer.enabled ? `Отключить ${peer.name}` : `Включить ${peer.name}`} title={locked ? 'Изменения доступны на primary-узле' : peer.enabled ? 'Отключить' : 'Включить'}><span /></button>
      <button className="icon-button" onClick={onQr} disabled={busy || !peer.enabled} aria-label={`QR-код ${peer.name}`} title="QR-код"><QrCode size={21} /></button>
      <button className="icon-button" onClick={onDownload} disabled={busy || !peer.enabled} aria-label={`Скачать ${peer.name}`} title="Скачать конфигурацию"><Download size={21} /></button>
      <button className="icon-button danger" onClick={onDelete} disabled={busy || locked} aria-label={`Удалить ${peer.name}`} title={locked ? 'Изменения доступны на primary-узле' : 'Удалить'}><Trash2 size={18} /></button>
    </div>
  </div>;
}

function Dashboard({ onLogout }: { onLogout: () => void }) {
  const [data, setData] = useState<DashboardData | null>(null);
  const [notice, setNotice] = useState<Notice>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [qrPeer, setQrPeer] = useState<PeerView | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const restoreInput = useRef<HTMLInputElement>(null);

  const load = useCallback(async () => {
    try {
      setData(await api.dashboard());
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) onLogout();
      else setNotice({ kind: 'error', text: error instanceof Error ? error.message : 'Не удалось загрузить данные' });
    }
  }, [onLogout]);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 10_000);
    return () => window.clearInterval(timer);
  }, [load]);

  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(null), 4500);
    return () => window.clearTimeout(timer);
  }, [notice]);

  async function action(id: string, operation: () => Promise<unknown>, message: string) {
    setBusy(id);
    try {
      await operation();
      await load();
      setNotice({ kind: 'success', text: message });
    } catch (error) {
      setNotice({ kind: 'error', text: error instanceof Error ? error.message : 'Операция не выполнена' });
    } finally { setBusy(null); }
  }

  async function restore(file: File) {
    try {
      const backup = JSON.parse(await file.text()) as unknown;
      await action('restore', () => api.restore(backup), 'Бэкап восстановлен. Endpoint обновлён для этого сервера.');
    } catch (error) {
      setNotice({ kind: 'error', text: error instanceof Error ? error.message : 'Некорректный файл бэкапа' });
    }
    if (restoreInput.current) restoreInput.current.value = '';
  }

  async function copyPublicKey() {
    if (!data) return;
    await navigator.clipboard.writeText(data.interface.publicKey);
    setNotice({ kind: 'success', text: 'Публичный ключ скопирован' });
  }

  if (!data) return <div className="loading-screen"><div className="spinner" /><span>Подключаемся к интерфейсу…</span></div>;

  const enabled = data.peers.filter((peer) => peer.enabled).length;
  const readOnly = data.cluster.readOnly;
  const interfaceStatus = data.interface.status === 'up' ? 'Работает' : data.interface.status === 'down' ? 'Остановлен' : 'Режим проверки';
  return <div className="app-shell">
    <header>
      <Logo />
      <div className="header-actions">
        <span className={`header-status ${data.interface.status}`}><i />{interfaceStatus}</span>
        <button className="logout-button" onClick={async () => { await api.logout(); onLogout(); }} aria-label="Выйти"><span>Выйти</span><LogOut size={17} /></button>
      </div>
    </header>

    <main className="dashboard">
      <section className="clients-panel">
        <div className="clients-toolbar">
          <div className="clients-heading">
            <div className="title-line"><h1>Клиенты</h1><span className="count-badge">{enabled}/{data.peers.length}</span></div>
            <div className="interface-meta">
              <span className={`interface-dot ${data.interface.status}`} />
              <strong>{data.interface.name}</strong>
              <span>AWG {data.interface.version}</span>
              <span>{data.interface.address}</span>
              <span>{data.interface.endpoint}</span>
              {data.cluster.role !== 'standalone' && <span
                className={`cluster-role ${data.cluster.role} ${data.cluster.lastError ? 'degraded' : ''}`}
                title={data.cluster.lastError ?? (data.cluster.lastSyncAt ? `Последняя синхронизация: ${new Date(data.cluster.lastSyncAt).toLocaleString('ru-RU')}` : 'Ожидание первой синхронизации')}
              >Кластер: {data.cluster.role}{data.cluster.lastError ? ' · ошибка' : ''}</span>}
              <button onClick={copyPublicKey} title="Скопировать публичный ключ" aria-label="Скопировать публичный ключ"><Copy size={14} /></button>
            </div>
          </div>
          <div className="toolbar-actions">
            <button className="toolbar-button" onClick={() => restoreInput.current?.click()} disabled={busy === 'restore' || readOnly} title={readOnly ? 'Восстановление выполняется на primary-узле' : undefined}><ArchiveRestore size={19} /><span>Восстановить</span></button>
            <button className="toolbar-button" onClick={() => void action('backup', () => download('/api/backup', 'awg-panel.awgbak'), 'Бэкап сохранён')} disabled={busy === 'backup'}><Download size={19} /><span>Резервная копия</span></button>
            <button className="toolbar-button create" onClick={() => setCreateOpen(true)} disabled={readOnly} title={readOnly ? 'Создание выполняется на primary-узле' : undefined}><Plus size={20} /><span>Создать</span></button>
          </div>
        </div>
        {data.peers.length === 0 ? <div className="empty-state"><div><Users size={27} /></div><h3>Пока нет конфигураций</h3><p>{readOnly ? 'Replica ожидает синхронизацию с primary-узлом.' : 'Создайте первую и добавьте её в приложение AmneziaWG.'}</p><button className="secondary" onClick={() => setCreateOpen(true)} disabled={readOnly}><Plus size={17} /> Создать</button></div> :
          <div className="peer-list">{data.peers.map((peer) => <PeerRow key={peer.id} peer={peer} busy={busy === peer.id} locked={readOnly} onQr={() => setQrPeer(peer)} onDownload={() => void action(peer.id, () => download(`/api/peers/${peer.id}/config`, `${peer.name}.conf`), 'Конфигурация скачана')} onToggle={() => void action(peer.id, () => api.togglePeer(peer.id), peer.enabled ? 'Конфигурация отключена' : 'Конфигурация включена')} onDelete={() => { if (window.confirm(`Удалить «${peer.name}»? Восстановить ключи можно будет только из бэкапа.`)) void action(peer.id, () => api.deletePeer(peer.id), 'Конфигурация удалена'); }} />)}</div>}
      </section>
      <input ref={restoreInput} className="hidden" type="file" accept=".awgbak,.json,application/json" onChange={(event) => { const file = event.target.files?.[0]; if (file) void restore(file); }} />
      <footer><span>AmneziaWG Panel</span><span>Конфигурации и ключи хранятся локально на сервере</span></footer>
    </main>

    {createOpen && <CreatePeerModal onClose={() => setCreateOpen(false)} onCreated={load} />}
    {qrPeer && <QrModal peer={qrPeer} onClose={() => setQrPeer(null)} />}
    {notice && <div className={`toast ${notice.kind}`}>{notice.kind === 'success' ? <Check size={18} /> : <X size={18} />}{notice.text}</div>}
  </div>;
}

export function App() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  useEffect(() => { api.session().then(({ authenticated: value }) => setAuthenticated(value)).catch(() => setAuthenticated(false)); }, []);
  if (authenticated === null) return <div className="loading-screen"><div className="spinner" /></div>;
  return authenticated ? <Dashboard onLogout={() => setAuthenticated(false)} /> : <Login onSuccess={() => setAuthenticated(true)} />;
}
