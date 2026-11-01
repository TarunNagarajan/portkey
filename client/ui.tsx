import { useEffect, useId, useState } from 'react';
import type { MembershipStatus, RoomStatus } from '../shared/rooms.js';

const paths = {
  rooms: 'M4 4h7v7H4z M13 4h7v7h-7z M4 13h7v7H4z M13 13h7v7h-7z',
  plus: 'M12 5v14 M5 12h14',
  arrow: 'M5 12h14 M14 7l5 5-5 5',
  search: 'M21 21l-5-5 M18 10.5a7.5 7.5 0 1 1-15 0 7.5 7.5 0 0 1 15 0',
  copy: 'M9 9h12v12H9z M15 9V3H3v12h6',
  shield: 'M12 3l8 3v6c0 5-8 9-8 9s-8-4-8-9V6z M8 12l3 3 5-6',
  clock: 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0 M12 7v5l3 2',
  key: 'M20 6a5 5 0 1 0-9.6 2.1L4 14.5V19h4.5l1-1v-2h2v-2h2l1.4-1.4A5 5 0 0 0 20 6z M16.5 6.5h.01',
};

export function Icon({ name }: { name: keyof typeof paths }) {
  return (
    <svg
      viewBox="0 0 24 24"
      width="18"
      height="18"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={paths[name]} />
    </svg>
  );
}

/* The mark: a door with the keyhole knocked out of it. */
export function BrandMark({ size = 26 }: { size?: number }) {
  const id = `mark-${useId().replace(/[^a-zA-Z0-9]/g, '')}`;
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <mask id={id}>
        <rect width="24" height="24" fill="#fff" />
        <circle cx="12" cy="9.7" r="3" fill="#000" />
        <rect x="10.7" y="10.4" width="2.6" height="7.4" rx="1.3" fill="#000" />
      </mask>
      <rect x="3" y="1.5" width="18" height="21" rx="2.4" mask={`url(#${id})`} />
    </svg>
  );
}

export function StatusBadge({ status }: { status: RoomStatus | MembershipStatus }) {
  return (
    <span className={`status-badge ${status}`}>
      <span className="status-dot" />
      {status}
    </span>
  );
}

function remainingText(ms: number) {
  if (ms <= 0) return 'Deadline passed';
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 60) return `${minutes}m left`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h ${minutes % 60}m left`;
  return `${Math.floor(hours / 24)}d ${hours % 24}h left`;
}

/**
 * The live thing: how much of this room's window is left, measured against the
 * deadline the server gave. Plain fallback is the written deadline next to it.
 */
export function Lifetime({ from, to }: { from: string; to: string }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(timer);
  }, []);
  const start = new Date(from).getTime();
  const end = new Date(to).getTime();
  const left = end - now;
  const share = Math.max(0, Math.min(1, left / Math.max(1, end - start)));
  return (
    <div className="lifetime">
      <div className="lifetime-track" aria-hidden="true">
        <span style={{ width: `${Math.round(share * 100)}%` }} />
      </div>
      <p className="lifetime-text">
        <strong>{remainingText(left)}</strong> · ends {formatDate(to)}
      </p>
    </div>
  );
}

export function formatDate(value: string) {
  return new Date(value).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

export function formatDistance(meters: number) {
  if (meters < 1000) return `${Math.round(meters)} m`;
  const km = meters / 1000;
  return km >= 10 ? `${Math.round(km)} km` : `${km.toFixed(1)} km`;
}
