import React, { useState, useEffect } from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'

const CORRECT_PIN = import.meta.env.VITE_PIN || '284729';

function PinGate({ children }) {
  const [unlocked, setUnlocked] = useState(false);
  const [pin, setPin] = useState('');
  const [error, setError] = useState(false);
  const [shake, setShake] = useState(false);

  useEffect(() => {
    if (sessionStorage.getItem('vargate_unlocked') === 'yes') {
      setUnlocked(true);
    }
  }, []);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (pin === CORRECT_PIN) {
      sessionStorage.setItem('vargate_unlocked', 'yes');
      setUnlocked(true);
    } else {
      setError(true);
      setShake(true);
      setPin('');
      setTimeout(() => setShake(false), 500);
      setTimeout(() => setError(false), 2000);
    }
  };

  const handleKeyPress = (digit) => {
    if (pin.length < 6) {
      const newPin = pin + digit;
      setPin(newPin);
      setError(false);
      if (newPin.length === 6) {
        setTimeout(() => {
          if (newPin === CORRECT_PIN) {
            sessionStorage.setItem('vargate_unlocked', 'yes');
            setUnlocked(true);
          } else {
            setError(true);
            setShake(true);
            setPin('');
            setTimeout(() => setShake(false), 500);
            setTimeout(() => setError(false), 2000);
          }
        }, 150);
      }
    }
  };

  const handleDelete = () => {
    setPin(pin.slice(0, -1));
    setError(false);
  };

  if (unlocked) return children;

  const digits = ['1','2','3','4','5','6','7','8','9','','0','⌫'];

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #0a0e1a 0%, #0f172a 40%, #1a1040 100%)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
    }}>
      <style>{`
        @keyframes shake {
          0%, 100% { transform: translateX(0); }
          20% { transform: translateX(-8px); }
          40% { transform: translateX(8px); }
          60% { transform: translateX(-6px); }
          80% { transform: translateX(6px); }
        }
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes pulse {
          0%, 100% { opacity: 0.4; }
          50% { opacity: 1; }
        }
        .pin-btn:hover { background: rgba(255,255,255,0.12) !important; }
        .pin-btn:active { background: rgba(255,255,255,0.2) !important; transform: scale(0.95); }
      `}</style>

      <div style={{
        animation: 'fadeIn 0.6s ease-out',
        textAlign: 'center',
        padding: '48px 40px',
        borderRadius: '24px',
        background: 'rgba(255,255,255,0.03)',
        border: '1px solid rgba(255,255,255,0.06)',
        backdropFilter: 'blur(20px)',
        width: '340px',
      }}>
        {/* Logo */}
        <div style={{
          fontSize: '14px',
          fontWeight: 700,
          letterSpacing: '4px',
          textTransform: 'uppercase',
          color: 'rgba(255,255,255,0.3)',
          marginBottom: '8px',
        }}>VARGATE</div>

        <div style={{
          fontSize: '22px',
          fontWeight: 600,
          color: '#e2e8f0',
          marginBottom: '8px',
        }}>Audit Dashboard</div>

        <div style={{
          fontSize: '13px',
          color: 'rgba(255,255,255,0.35)',
          marginBottom: '36px',
        }}>Enter PIN to continue</div>

        {/* PIN dots */}
        <div style={{
          display: 'flex',
          justifyContent: 'center',
          gap: '12px',
          marginBottom: '32px',
          animation: shake ? 'shake 0.4s ease-out' : 'none',
        }}>
          {[0,1,2,3,4,5].map(i => (
            <div key={i} style={{
              width: '14px',
              height: '14px',
              borderRadius: '50%',
              border: `2px solid ${error ? '#ef4444' : pin.length > i ? '#6366f1' : 'rgba(255,255,255,0.2)'}`,
              background: pin.length > i ? (error ? '#ef4444' : '#6366f1') : 'transparent',
              transition: 'all 0.15s ease',
            }} />
          ))}
        </div>

        {/* Error message */}
        <div style={{
          height: '20px',
          marginBottom: '16px',
          fontSize: '13px',
          color: '#ef4444',
          opacity: error ? 1 : 0,
          transition: 'opacity 0.2s',
        }}>
          Incorrect PIN
        </div>

        {/* Keypad */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '10px',
          maxWidth: '240px',
          margin: '0 auto',
        }}>
          {digits.map((d, i) => (
            d === '' ? <div key={i} /> :
            <button
              key={i}
              className="pin-btn"
              onClick={() => d === '⌫' ? handleDelete() : handleKeyPress(d)}
              style={{
                width: '64px',
                height: '52px',
                borderRadius: '14px',
                border: '1px solid rgba(255,255,255,0.08)',
                background: 'rgba(255,255,255,0.05)',
                color: '#e2e8f0',
                fontSize: d === '⌫' ? '18px' : '20px',
                fontWeight: 500,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                outline: 'none',
              }}
            >
              {d}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <PinGate>
      <App />
    </PinGate>
  </React.StrictMode>,
)
