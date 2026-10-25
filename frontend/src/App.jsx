import { useEffect, useState } from "react";
import "./App.css";

const API_BASE = (import.meta.env.VITE_API_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");

const LEGAL_PAGES = {
  about: {
    eyebrow: "ABOUT THE PROJECT",
    title: "A second look at suspicious messages.",
    paragraphs: [
      "PhishGuard is a learning and demonstration project that checks URLs and messages for patterns commonly associated with phishing and scams.",
      "It combines URL inspection, rule-based message checks, and a machine-learning text classifier. Results include the signals found and suggestions for safer next steps.",
      "PhishGuard is a decision-support tool, not a security guarantee. A low score does not prove that a link or message is safe."
    ]
  },
  privacy: {
    eyebrow: "PRIVACY",
    title: "Use the scanner thoughtfully.",
    paragraphs: [
      "Scans may be saved in the application's backend history and in your browser's local storage so you can review recent results. The application may send the text you submit to its configured PhishGuard API for analysis.",
      "Do not paste passwords, payment details, authentication codes, private conversations, or other sensitive personal information. Remove identifying details before scanning a message.",
      "This page describes the current demo behavior. Before public production use, the operator should publish a policy that names the hosting providers, retention period, deletion process, and any third-party services actually used."
    ]
  },
  terms: {
    eyebrow: "TERMS OF USE",
    title: "Treat every result as guidance, not certainty.",
    paragraphs: [
      "PhishGuard is provided for educational and informational purposes. It does not guarantee detection of phishing, fraud, malware, or other harmful content.",
      "Do not use the scanner as your only security control or as a substitute for verifying a request through an independently obtained official channel. Do not submit information you are not permitted to share.",
      "You are responsible for decisions made using the results. The project is provided without a guarantee that it will be available, accurate, or suitable for a particular purpose."
    ]
  }
};

function App() {
  const [mode, setMode] = useState("url");
  const [input, setInput] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [page, setPage] = useState("scanner");
  const [history, setHistory] = useState(() => {
    try {
      const saved = localStorage.getItem("phishguard_scan_history");
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  useEffect(() => {
    let cancelled = false;
    async function loadHistory() {
      try {
        const response = await fetch(`${API_BASE}/api/v1/history`);
        if (!response.ok) return;
        const data = await response.json();
        if (!cancelled && Array.isArray(data.scans)) {
          setHistory(data.scans.map((item) => ({
            id: item.id,
            type: item.type,
            input: item.input,
            score: item.score,
            level: item.level,
            date: item.date ? new Date(item.date).toLocaleString() : "",
            data: item.data
          })));
        }
      } catch {
        // Browser history remains available if the API is offline.
      }
    }
    loadHistory();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem("phishguard_scan_history", JSON.stringify(history));
    } catch {
      // Storage may be unavailable in private browsing.
    }
  }, [history]);

  async function handleScan(event) {
    event.preventDefault();
    const value = input.trim();
    if (!value) {
      setError(mode === "url" ? "Enter a URL to analyze." : "Paste a message to analyze.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);
    const endpoint = mode === "url"
      ? "/api/v1/analyze/url"
      : mode === "message_ml"
        ? "/api/v1/analyze/message/ml"
        : "/api/v1/analyze/message";
    const body = mode === "url" ? { url: value } : { message: value };

    try {
      const response = await fetch(`${API_BASE}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      let data;
      try {
        data = await response.json();
      } catch {
        throw new Error("The server returned an unreadable response.");
      }
      if (!response.ok) {
        throw new Error(typeof data.detail === "string" ? data.detail : "The server rejected the input. Check it and try again.");
      }
      const scan = {
        id: data.id ?? `${Date.now()}-${Math.random()}`,
        type: mode,
        input: value,
        score: data.risk_score,
        level: data.risk_level,
        date: new Date().toLocaleString(),
        data
      };
      setResult(data);
      setHistory((old) => [scan, ...old.filter((item) => item.id !== scan.id)].slice(0, 50));
    } catch (err) {
      setError(err.message === "Failed to fetch"
        ? "Cannot connect to the PhishGuard API. Check that the backend is running."
        : err.message || "Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  function changeMode(nextMode) {
    setMode(nextMode);
    setInput("");
    setResult(null);
    setError("");
  }

  function downloadCSV() {
    if (!history.length) return;
    const rows = [
      ["Type", "Input", "Risk Score", "Risk Level", "Date"],
      ...history.map((item) => [item.type, item.input, item.score, item.level, item.date])
    ];
    const csv = rows.map((row) => row.map((value) => {
      let safe = String(value ?? "");
      if (/^[=+\-@\t\r]/.test(safe)) safe = "'" + safe;
      return `"${safe.replace(/"/g, '""')}"`;
    }).join(",")).join("\r\n");
    const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "phishguard-scan-history.csv";
    link.click();
    URL.revokeObjectURL(url);
  }

  const score = Math.min(100, Math.max(0, Number(result?.risk_score ?? 0)));
  const level = result?.risk_level ?? "low";

  function signalName(signal) {
    return typeof signal === "string" ? signal : signal?.name ?? "Warning signal";
  }
  function signalExplanation(signal) {
    return typeof signal === "string"
      ? "This pattern was identified by the message classifier."
      : signal?.explanation ?? signal?.description ?? "";
  }

  return (
    <div className="app-shell">
      <header className="site-header">
        <button className="wordmark" type="button" onClick={() => setPage("scanner")} aria-label="PhishGuard home">
          <span className="wordmark-mark">P</span><span>phishguard</span>
        </button>
        <nav className="main-nav" aria-label="Main navigation">
          <button className={page === "scanner" ? "nav-link current" : "nav-link"} onClick={() => setPage("scanner")} type="button">Scanner</button>
          <button className="nav-link" onClick={() => { setPage("scanner"); document.getElementById("history")?.scrollIntoView({ behavior: "smooth" }); }} type="button">History <span className="nav-number">{history.length}</span></button>
          <span className="nav-divider" />
          <button className={page === "about" ? "nav-link current" : "nav-link"} onClick={() => setPage("about")} type="button">About</button>
          <button className={page === "privacy" ? "nav-link current" : "nav-link"} onClick={() => setPage("privacy")} type="button">Privacy</button>
          <button className={page === "terms" ? "nav-link current" : "nav-link"} onClick={() => setPage("terms")} type="button">Terms</button>
        </nav>
        <div className="header-status"><span className="status-dot" /> Local analysis workspace</div>
      </header>

      {page !== "scanner" ? (
        <main className="legal-page">
          <div className="eyebrow">{LEGAL_PAGES[page].eyebrow}</div>
          <h1>{LEGAL_PAGES[page].title}</h1>
          <div className="legal-copy">
            {LEGAL_PAGES[page].paragraphs.map((paragraph) => <p key={paragraph}>{paragraph}</p>)}
          </div>
          <button className="button button-dark" type="button" onClick={() => setPage("scanner")}>Return to scanner <span aria-hidden="true">→</span></button>
        </main>
      ) : (
        <main className="page-content" id="home">
          <section className="intro">
            <div className="eyebrow">LINK & MESSAGE INSPECTION</div>
            <h1>Pause before you <span>trust.</span></h1>
            <p className="intro-copy">Inspect a suspicious link or message. PhishGuard shows the warning patterns it finds so you can make a more informed decision.</p>
            <p className="intro-note">The scanner does not open submitted links.</p>
          </section>

          <section className="workspace" aria-label="Security scanner">
            <div className="workspace-heading">
              <div><div className="section-label">NEW SCAN</div><h2>What would you like to inspect?</h2></div>
              <span className="workspace-index">01 / ANALYZE</span>
            </div>

            <div className="mode-switch" role="tablist" aria-label="Scan type">
              <button className={mode === "url" ? "mode-tab selected" : "mode-tab"} type="button" role="tab" aria-selected={mode === "url"} onClick={() => changeMode("url")}>Website URL</button>
              <button className={mode === "message" ? "mode-tab selected" : "mode-tab"} type="button" role="tab" aria-selected={mode === "message"} onClick={() => changeMode("message")}>Email or message</button>
              <button className={mode === "message_ml" ? "mode-tab selected" : "mode-tab"} type="button" role="tab" aria-selected={mode === "message_ml"} onClick={() => changeMode("message_ml")}>AI message analysis</button>
            </div>

            <form onSubmit={handleScan}>
              <label htmlFor="scan-input">{mode === "url" ? "URL TO INSPECT" : mode === "message_ml" ? "MESSAGE CONTENT · MACHINE LEARNING" : "MESSAGE CONTENT · RULE-BASED CHECK"}</label>
              <textarea id="scan-input" value={input} onChange={(event) => setInput(event.target.value)} placeholder={mode === "url" ? "https://example.com/account/verify" : "Paste the email, SMS, or chat message you want to check…"} rows={mode === "url" ? 3 : 6} maxLength={mode === "url" ? 2048 : 10000} aria-describedby="input-help" />
              <div className="input-meta" id="input-help">
                <span>{mode === "url" ? "Paste the full link. Do not open it first." : "Remove personal or confidential details before pasting."}</span>
                <span>{input.length}/{mode === "url" ? 2048 : 10000}</span>
              </div>
              {error && <div className="error-message" role="alert">{error}</div>}
              <div className="form-actions">
                <span className="form-disclaimer">Analysis is an estimate, not a safety guarantee.</span>
                <button className="button button-dark scan-button" type="submit" disabled={loading}>
                  {loading ? <><span className="spinner" /> Analyzing…</> : <>Analyze input <span aria-hidden="true">→</span></>}
                </button>
              </div>
            </form>
          </section>

          {result && (
            <section className="results-section" aria-live="polite">
              <div className="section-topline"><div><div className="section-label">ANALYSIS COMPLETE</div><h2>Scan findings</h2></div><span className={`risk-tag ${level}`}>{level} risk</span></div>
              <div className="result-overview">
                <div className={`score-panel ${level}`}><span className="score-label">RISK SCORE</span><strong>{score}<small>/100</small></strong><div className="score-track"><span style={{ width: `${score}%` }} /></div></div>
                <div className="result-copy">
                  <h3>{result.model ? (result.prediction === "phishing_or_spam" ? "Model flagged this as phishing or spam" : "Model predicts this may be legitimate") : level === "high" ? "High-risk patterns detected" : level === "medium" ? "Some warning signs detected" : "Few warning signs detected"}</h3>
                  <p>{result.model ? "The classifier's score is an estimate, not a calibrated probability." : "This rule-based score is an estimate, not a probability."}</p>
                  {result.recommendation && <div className="recommendation"><span className="section-label">SUGGESTED NEXT STEP</span><p>{result.recommendation}</p></div>}
                </div>
              </div>

              {result.model && <div className="model-details">
                <div className="section-label">MACHINE-LEARNING DETAILS</div>
                <h3>{result.prediction === "phishing_or_spam" ? "Phishing or spam detected" : "Likely legitimate"}</h3>
                <p>{result.model}{result.model_version ? ` · Version ${result.model_version}` : ""}</p>
                {result.model_evaluation && <div className="metric-line"><span>Test accuracy <strong>{result.model_evaluation.test_accuracy}%</strong></span><span>Test F1 score <strong>{result.model_evaluation.test_f1_score}%</strong></span></div>}
                <p className="muted-note">Evaluation metrics describe the test dataset. Real-world performance can differ.</p>
              </div>}

              <div className="signals-heading"><h3>Detected signals</h3><span>{result.signals?.length ?? 0} found</span></div>
              {result.signals?.length ? <div className="signals-list">{result.signals.map((signal, index) => (
                <article className="signal-row" key={`${signalName(signal)}-${index}`}>
                  <span className="signal-marker" aria-hidden="true">!</span><div className="signal-content"><h4>{signalName(signal)}</h4>{signalExplanation(signal) && <p>{signalExplanation(signal)}</p>}
                    {typeof signal === "object" && signal?.matched_phrases?.length > 0 && <div className="matched-phrases">{signal.matched_phrases.map((phrase) => <span key={phrase}>{phrase}</span>)}</div>}
                  </div>
                  {typeof signal === "object" && typeof signal?.points === "number" && <span className="signal-points">+{signal.points}</span>}
                </article>
              ))}</div> : <p className="no-signals">No warning patterns were detected by this analyzer. That does not prove the input is safe.</p>}
              {result.disclaimer && <p className="disclaimer">{result.disclaimer}</p>}
            </section>
          )}

          <section className="history-section" id="history">
            <div className="section-topline history-topline"><div><div className="section-label">LOCAL RECORD</div><h2>Scan history</h2><p>Recent scans saved by the API or this browser.</p></div><button className="button button-outline" type="button" onClick={downloadCSV} disabled={!history.length}>Export CSV ↓</button></div>
            {!history.length ? <div className="empty-history"><p>No scans recorded yet.</p><span>Your completed scans will appear here.</span></div> : <div className="history-table-wrap"><table><thead><tr><th>TYPE / INPUT</th><th>SCORE</th><th>RISK</th><th>DATE</th></tr></thead><tbody>{history.map((item) => <tr key={item.id}><td><span className="history-type">{item.type === "url" ? "URL" : item.type === "message_ml" ? "AI MESSAGE" : "MESSAGE"}</span><span className="history-input">{item.input}</span></td><td>{item.score ?? "—"}/100</td><td><span className={`risk-tag ${item.level}`}>{item.level}</span></td><td>{item.date}</td></tr>)}</tbody></table></div>}
          </section>
        </main>
      )}

      <footer className="site-footer"><span>PHISHGUARD · SECURITY AWARENESS</span><span>Inspect carefully. Verify independently.</span><button type="button" onClick={() => setPage("privacy")}>Privacy & data use</button></footer>
    </div>
  );
}

export default App;
