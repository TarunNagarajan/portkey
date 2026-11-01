import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { startSession } from './api.js';
import { RecoverRoom } from './Recovery.js';
import { Home } from './Home.js';
import { JoinPage } from './JoinPage.js';
import { RoomPage } from './RoomPage.js';
import { BrandMark } from './ui.js';
import './styles.css';

function App() {
  const [online, setOnline] = useState(navigator.onLine);
  useEffect(() => {
    const changed = () => setOnline(navigator.onLine);
    window.addEventListener('online', changed); window.addEventListener('offline', changed);
    return () => { window.removeEventListener('online', changed); window.removeEventListener('offline', changed); };
  }, []);
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
    <div className="frame">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="bar">
        <div className="shell">
          <a className="brand" href="/">
            <BrandMark size={22} />
            Portkey
          </a>
          <nav className="bar-links" aria-label="Workspace">
            <a aria-current={join ? undefined : 'page'} href="/">
              Your rooms
            </a>
            <a href="/#new-room">Create a room</a>
            <a href="/recover">Recover room</a>
          </nav>
          {ready && (
            <p className="bar-note">
              <span className="square pulse" aria-hidden="true" />
              Session held in this browser
            </p>
          )}
        </div>
      </header>
      <main id="main" className="board shell">
        {!online && <p className="notice span-12" role="status">You are offline. Saved uploads remain in this browser. Reconnect to resume.</p>}
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
        ) : path === '/recover' ? (<RecoverRoom />
        ) : path === '/' ? (
          <Home />
        ) : (
          <h1>Page not found.</h1>
        )}
      </main>
      <footer className="foot">
        <div className="shell">
          <div className="foot-line">
            <p className="foot-mark">
              <BrandMark size={18} />
              Portkey — rooms that open by invitation
            </p>
            <nav className="foot-links" aria-label="Footer">
              <a href="/">Your rooms</a>
              <a href="/#new-room">Create a room</a>
            </nav>
            <p className="foot-year">2026</p>
          </div>
          <p className="foot-credits" data-ui>
            Pictures: “Set old keys hanging wall” by Markus Spiske (CC0, rawpixel) · “Entrance to
            the East Block of the Parliament of Canada in Ottawa” by Hayden Soloviev (CC BY 4.0,
            Wikimedia Commons) · “Igreja do Curral das Freiras: Azulejo, Tiles” by Celsoazevedo
            (CC BY 4.0, Wikimedia Commons) · “Einsteckschloss-Animation” by Andreas Gortan
            (CC BY-SA 4.0, Wikimedia Commons).
          </p>
        </div>
      </footer>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(<App />);
