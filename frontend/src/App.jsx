import { useState, useEffect } from 'react';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE || '';
const HISTORY_KEY = 'phishguard_history';
const MAX_HISTORY = 50;

const FEATURE_LABELS = {
  url_length: 'URL Length', domain_length: 'Domain Length', domain_age_days: 'Domain Age (days)',
  has_https: 'HTTPS', contains_ip: 'IP-Based Domain', num_dots: 'Dot Count', num_hyphens: 'Hyphen Count',
  num_slashes: 'Slash Count', num_at_symbols: '@ Symbols', num_question_marks: 'Question Marks',
  num_equal_signs: 'Equal Signs', num_digits: 'Digit Count', num_special_chars: 'Special Chars',
  suspicious_tld: 'Suspicious TLD', subdomain_depth: 'Subdomain Depth', path_depth: 'Path Depth',
  url_entropy: 'URL Entropy', digit_letter_ratio: 'Digit/Letter Ratio', has_redirect: 'Redirect Params',
  brand_in_domain: 'Brand Impersonation', homograph_similarity: 'Homograph Attack', punycode_detected: 'Punycode (xn--)',
  zero_width_chars: 'Zero-Width Chars', tld_in_path: 'TLD in Path', domain_registration_length: 'Registration Length (days)',
  double_slash_redirect: 'Double-Slash Redirect', shortening_service: 'URL Shortener',
  domain_rank: 'Domain Rank', tranco_rank_log: 'Tranco Rank Log', ssl_valid: 'SSL Valid', ssl_issuer_type: 'SSL Issuer Type',
  cert_age_days: 'Cert Age Days', whois_reg_period: 'WHOIS Reg Period', indexed_in_google: 'Indexed In Google', backlink_count_estimate: 'Backlink Count Estimate'
};

const BAD_WHEN_TRUE = new Set([
  'contains_ip', 'num_at_symbols', 'suspicious_tld', 'has_redirect',
  'brand_in_domain', 'homograph_similarity', 'punycode_detected',
  'zero_width_chars', 'tld_in_path', 'double_slash_redirect', 'shortening_service'
]);

function featureStatus(key, val, isPhishing) {
  if (typeof val === 'boolean') {
    if (key === 'has_https' || key === 'ssl_valid' || key === 'indexed_in_google') {
      return val ? { cls: 'ok', label: '✓ Yes' } : { cls: 'bad', label: '✗ No' };
    }
    if (BAD_WHEN_TRUE.has(key)) return val ? { cls: 'bad', label: '⚠ Yes' } : { cls: 'ok', label: '✓ No' };
    return val ? { cls: 'ok', label: '✓ Yes' } : { cls: 'neutral', label: 'No' };
  }
  if (key === 'domain_age_days') {
    if (val < 0) return { cls: 'neutral', label: 'Unknown' };
    if (val < 30) return { cls: 'bad', label: `${val}d ⚠` };
    if (val < 180) return { cls: 'warn', label: `${val}d` };
    return { cls: 'ok', label: `${val}d ✓` };
  }
  if (key === 'url_entropy') return val > 4.5 ? { cls: 'bad', label: val } : { cls: 'ok', label: val };
  if (key === 'num_hyphens' && val >= 2) return { cls: 'warn', label: val };
  if (key === 'url_length' && val > 75) return { cls: 'warn', label: val };
  return { cls: 'neutral', label: val === -1 || val === null ? 'N/A' : val };
}

export default function App() {
  const [theme, setTheme] = useState('dark');
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);

  useEffect(() => {
    const saved = localStorage.getItem('theme') || 'dark';
    setTheme(saved);
    document.documentElement.setAttribute('data-theme', saved);

    try {
      const savedHistory = JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
      setHistory(savedHistory);
    } catch { setHistory([]); }

    axios.get(`${API_BASE}/api/stats`, {
      headers: { 'Bypass-Tunnel-Reminder': 'true' }
    }).then(res => setStats(res.data)).catch(() => { });
  }, []);

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
  };

  const addToHistory = (resData) => {
    setHistory(prev => {
      const newHist = [{
        id: Date.now(),
        time: new Date().toLocaleTimeString(),
        date: new Date().toLocaleDateString(),
        url: resData.url,
        is_phishing: resData.is_phishing,
        risk_level: resData.risk_level,
        confidence: resData.confidence
      }, ...prev].slice(0, MAX_HISTORY);
      localStorage.setItem(HISTORY_KEY, JSON.stringify(newHist));
      return newHist;
    });
  };

  const analyze = async (targetUrl = url) => {
    if (!targetUrl.trim()) return setError('Please enter a URL.');
    setError('');
    setLoading(true);
    try {
      const res = await axios.post(`${API_BASE}/api/detect`, { url: targetUrl, use_whois: false }, {
        headers: { 'Bypass-Tunnel-Reminder': 'true' }
      });
      setResult(res.data);
      addToHistory(res.data);
      setTimeout(() => {
        document.getElementById('results-section')?.scrollIntoView({ behavior: 'smooth' });
      }, 100);
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  const deleteHistoryItem = (id) => {
    setHistory(prev => {
      const newHist = prev.filter(h => h.id !== id);
      localStorage.setItem(HISTORY_KEY, JSON.stringify(newHist));
      return newHist;
    });
  };

  const clearHistory = () => {
    if (window.confirm('Clear all detection history?')) {
      setHistory([]);
      localStorage.removeItem(HISTORY_KEY);
    }
  };

  const formatPct = (v) => v ? (v * 100).toFixed(1) + '%' : '—';
  const formatNum = (v) => v ? Number(v).toLocaleString() : '—';

  return (
    <>
      <nav id="navbar">
        <div className="nav-inner">
          <a href="#" className="nav-logo">
            <span className="logo-icon"><i className="fa-solid fa-shield-halved"></i></span>
            <span className="logo-text">PhishGuard <span className="accent">AI</span></span>
          </a>
          <ul className="nav-links">
            <li><a href="#hero" className="nav-link">Home</a></li>
            <li><a href="#results-section" className="nav-link">Analyzer</a></li>
            <li><a href="#history-section" className="nav-link">History</a></li>
          </ul>
          <div className="nav-actions" style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <button className="theme-toggle-switch" onClick={toggleTheme} aria-label="Toggle theme">
              <div className="switch-track">
                <div className={`switch-thumb ${theme}`}>
                  {theme === 'dark' ? <i className="fa-solid fa-moon"></i> : <i className="fa-solid fa-sun"></i>}
                </div>
              </div>
            </button>
          </div>
        </div>
      </nav>

      <section id="hero">
        <div className="glow-blob glow-blob-1"></div>
        <div className="glow-blob glow-blob-2"></div>
        <div className="hero-bg-grid"></div>
        <div className="container hero-container-grid">
          <div className="hero-content">
            <div className="hero-badge">
              <i className="fa-solid fa-circle-dot pulse-dot"></i>
              AI-Powered Security Analysis
            </div>
            <h1 className="hero-title">Detect <span className="gradient-text">Phishing</span><br />Websites Instantly</h1>

            <div className="url-card-wrapper">
              <div className={`url-card ${loading ? 'scanning-active' : ''}`}>
                <div className="url-input-wrapper" style={{ display: 'flex', flex: 1, alignItems: 'center' }}>
                  <span className="url-prefix-icon"><i className="fa-solid fa-magnifying-glass"></i></span>
                  <input type="url" className="url-input" placeholder="https://example.com" value={url} onChange={e => setUrl(e.target.value)} onKeyDown={e => e.key === 'Enter' && analyze()} disabled={loading} />
                </div>
                <button className={`analyze-btn ${loading ? 'loading' : ''}`} onClick={() => analyze()}>
                  <span className="btn-text"><i className="fa-solid fa-shield-halved"></i> Analyze</span>
                  <span className="btn-loading"><i className="fa-solid fa-circle-notch fa-spin"></i> Analyzing…</span>
                </button>
              </div>
              {error && <div className="url-error"><i className="fa-solid fa-circle-exclamation"></i> {error}</div>}
            </div>
            <div className="quick-tests">
              <span className="quick-label">Quick test:</span>
              <button className="quick-btn phish-btn" onClick={() => { setUrl('http://paypal-secure.tk'); analyze('http://paypal-secure.tk'); }}>Phishing URL</button>
              <button className="quick-btn safe-btn" onClick={() => { setUrl('https://google.com'); analyze('https://google.com'); }}>Legit URL</button>
            </div>

            <div className="hero-stats">
              <div className="hero-stat"><span className="stat-num">{stats ? formatPct(stats.accuracy) : '—'}</span><span className="stat-lbl">Model Accuracy</span></div>
              <div className="hero-stat"><span className="stat-num">{stats ? stats.features_count : 27}</span><span className="stat-lbl">Features Analyzed</span></div>
              <div className="hero-stat"><span className="stat-num">{stats ? formatNum(stats.dataset_size) : '—'}</span><span className="stat-lbl">URLs Trained On</span></div>
            </div>
          </div>

          <div className="hero-visual">
            <div className="visual-wrapper">
              <div className="tech-circles">
                <div className="circle circle-outer"></div>
                <div className="circle circle-mid"></div>
                <div className="circle circle-inner"></div>
              </div>
              <img src="/cyber_shield_hud.png" alt="Cyber Security Neural HUD" className="hero-hud-img" />
            </div>
          </div>
        </div>
      </section>

      {result && (
        <section id="results-section" className="results-section results-reveal">
          <div className="container">
            <h2 className="section-title"><i className="fa-solid fa-chart-bar"></i> Analysis Results</h2>
            <div className={`verdict-banner ${result.is_phishing ? 'phishing' : 'safe'}`}>
              <div className="verdict-icon">
                {result.is_phishing ? <i className="fa-solid fa-skull-crossbones" style={{ color: 'var(--danger)' }}></i> : <i className="fa-solid fa-shield-check" style={{ color: 'var(--safe)' }}></i>}
              </div>
              <div className="verdict-text">
                <div className="verdict-label" style={{ color: result.is_phishing ? 'var(--danger)' : 'var(--safe)' }}>
                  {result.is_phishing ? '⚠ PHISHING DETECTED' : '✓ URL APPEARS SAFE'}
                </div>
                <div className="verdict-url">{result.url}</div>
              </div>
              <div className={`verdict-badge ${result.risk_level}`}>{result.risk_level.toUpperCase()} RISK</div>
            </div>

            <div className="results-grid">
              <div className="card gauge-card">
                <div className="card-header"><i className="fa-solid fa-gauge-high"></i> Confidence Score</div>
                <div className="gauge-wrapper" style={{ height: '150px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <div className={result.is_phishing ? 'gauge-value-danger' : 'gauge-value-safe'} style={{ fontSize: '3.5rem', fontWeight: '800', fontFamily: 'var(--font-mono)', color: result.is_phishing ? 'var(--danger)' : 'var(--safe)' }}>{result.confidence}%</div>
                </div>

              </div>

              <div className="card features-card">
                <div className="card-header"><i className="fa-solid fa-list-check"></i> Feature Breakdown</div>
                <div className="features-table-wrapper">
                  <table className="features-table">
                    <thead><tr><th>Feature</th><th>Value</th><th>Status</th></tr></thead>
                    <tbody>
                      {Object.entries(result.features_analyzed || {}).map(([k, v]) => {
                        const { cls, label } = featureStatus(k, v, result.is_phishing);
                        return (
                          <tr key={k}>
                            <td>{FEATURE_LABELS[k] || k}</td>
                            <td className="feat-val">{typeof v === 'boolean' ? (v ? 'Yes' : 'No') : v === -1 || v === null ? 'N/A' : v}</td>
                            <td className={`feat-status ${cls}`}>{label}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="card explain-card">
                <div className="card-header"><i className="fa-solid fa-brain"></i> AI Explanation</div>
                <div className="explanation-text">{result.explanation}</div>
              </div>
            </div>
          </div>
        </section>
      )}

      <section id="history-section" className="history-section">
        <div className="container">
          <div className="section-header-row">
            <h2 className="section-title"><i className="fa-solid fa-clock-rotate-left"></i> Detection History</h2>
            {history.length > 0 && (
              <button className="clear-btn" onClick={clearHistory}>
                <i className="fa-solid fa-trash"></i> Clear All
              </button>
            )}
          </div>
          <div className="history-table-wrapper">
            <table className="history-table">
              <thead><tr><th>#</th><th>Time</th><th>URL</th><th>Risk</th><th>Confidence</th><th>Actions</th></tr></thead>
              <tbody>
                {history.length === 0 ? (
                  <tr><td colSpan="6" className="history-empty"><i className="fa-solid fa-database"></i><br />No detections yet. Analyze a URL to get started.</td></tr>
                ) : history.map((item, idx) => (
                  <tr key={item.id}>
                    <td>{idx + 1}</td>
                    <td style={{ whiteSpace: 'nowrap', fontSize: '0.78rem', color: 'var(--text-muted)' }}>{item.date} {item.time}</td>
                    <td><span className="hist-url" title={item.url}>{item.url.length > 50 ? item.url.substring(0, 47) + '…' : item.url}</span></td>
                    <td><span className={`risk-badge ${item.risk_level || (item.is_phishing ? 'high' : 'low')}`}>{item.risk_level || (item.is_phishing ? 'high' : 'low')}</span></td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: item.risk_level === 'high' ? 'var(--danger)' : item.risk_level === 'medium' ? 'var(--warn)' : 'var(--safe)' }}>{item.confidence}%</td>
                    <td className="hist-actions">
                      <button className="hist-btn recheck" onClick={() => { setUrl(item.url); analyze(item.url); window.scrollTo({ top: 0, behavior: 'smooth' }); }} title="Re-analyze">
                        <i className="fa-solid fa-rotate-right"></i>
                      </button>
                      <button className="hist-btn del" onClick={() => deleteHistoryItem(item.id)} title="Delete">
                        <i className="fa-solid fa-trash"></i>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <footer id="footer">
        <div className="footer-inner">
          <div className="footer-logo"><i className="fa-solid fa-shield-halved"></i> PhishGuard <span className="accent">AI</span></div>
          <p className="footer-desc">ML-powered phishing detection system. Built with ♥ for cybersecurity research.</p>
          <div className="footer-meta">
            <span><i className="fa-solid fa-graduation-cap"></i> NAVTTC Cyber Security</span>
            <span className="divider">•</span>
            <span><i className="fa-solid fa-code"></i> Python + React Vite</span>
            <span className="divider">•</span>
            <span><i className="fa-solid fa-copyright"></i> 2026</span>
          </div>
        </div>
      </footer>
    </>
  );
}
