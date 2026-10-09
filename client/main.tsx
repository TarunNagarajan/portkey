import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { startSession } from './api.js';
import { Home } from './Home.js';
import { JoinPage } from './JoinPage.js';
import { RoomPage } from './RoomPage.js';
import { Icon } from './ui.js';
import './styles.css';

function App() {
  const [ready, setReady] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    void startSession()
      .then(() => setReady(true))
      .catch((error) => setError(error.message));
  }, []);
  const path = window.location.pathname;
  const room = path.match(/^\/rooms\/([a-f0-9-]+)$/i);
  const join = path.match(/^\/join\/([A-Za-z0-9_-]+)$/);
  return (
    <div className="app-layout">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <aside className="sidebar">
        <a className="brand" href="/">
          <span className="brand-mark">P</span>Portkey
        </a>
        <p className="nav-label">WORKSPACE</p>
        <nav aria-label="Workspace navigation">
          <a className={!join ? 'nav-item selected' : 'nav-item'} href="/">
            <Icon name="rooms" />
            Your rooms
          </a>
          <a className="nav-item" href="/#new-room">
            <Icon name="plus" />
            Create a room
          </a>
        </nav>
        <div className="sidebar-note">
          <Icon name="shield" />
          <strong>Access stays with this browser.</strong>
          <p>Keep this browser’s cookies to retain access to your rooms.</p>
        </div>
      </aside>
      <div className="workspace">
        <div className="topbar">
          <span>
            Workspace <span className="breadcrumb-divider">/</span>{' '}
            {join ? 'Join room' : room ? 'Room overview' : 'Rooms'}
          </span>
          {ready && (
            <span className="session-indicator">
              <span className="status-dot" />
              Session active
            </span>
          )}
        </div>
        <main id="main">
          {error ? (
            <p role="alert" className="error">
              {error} <button onClick={() => window.location.reload()}>Retry</button>
            </p>
          ) : !ready ? (
            <p role="status">Starting your session…</p>
          ) : room ? (
            <RoomPage id={room[1]} />
          ) : join ? (
            <JoinPage code={join[1]} />
          ) : path === '/' ? (
            <Home />
          ) : (
            <h1>Page not found.</h1>
          )}
        </main>
        <footer>
          <span>Portkey</span>
          <span>Access managed by the organizer.</span>
        </footer>
      </div>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(<App />);
