import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { startSession } from './api.js';
import { Home } from './Home.js';
import { JoinPage } from './JoinPage.js';
import { RoomPage } from './RoomPage.js';
import './styles.css';

function App() {
  const [ready, setReady] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    void startSession().then(() => setReady(true)).catch(error => setError(error.message));
  }, []);
  const path = window.location.pathname;
  const room = path.match(/^\/rooms\/([a-f0-9-]+)$/i);
  const join = path.match(/^\/join\/([A-Za-z0-9_-]+)$/);
  return <div className="shell"><nav><a className="brand" href="/">Portkey</a><a href="/">Your rooms</a></nav>
    <main>{error ? <p role="alert" className="error">{error} <button onClick={() => window.location.reload()}>Retry</button></p> : !ready ? <p role="status">Starting your session…</p> :
      room ? <RoomPage id={room[1]} /> : join ? <JoinPage code={join[1]} /> : path === '/' ? <Home /> : <h1>Page not found.</h1>}</main>
    <footer>Portkey · Room management prototype</footer>
  </div>;
}

createRoot(document.getElementById('root')!).render(<App />);
