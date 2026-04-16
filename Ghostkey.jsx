import { useState, useCallback, useRef } from "react";

// ─── Detection Engine ──────────────────────────────────────────────────────────

const PATTERNS = [
  { name: "AWS Access Key",       regex: /\b(AKIA|ASIA)[A-Z0-9]{16}\b/g,                      severity: "high",   env: "AWS_ACCESS_KEY_ID",        fix: "Revoke in AWS IAM → Security Credentials. Rotate all associated permissions immediately." },
  { name: "Stripe Secret Key",    regex: /\bsk_live_[0-9a-zA-Z]{24,}\b/g,                     severity: "high",   env: "STRIPE_SECRET_KEY",        fix: "Revoke at dashboard.stripe.com/apikeys. Anyone with this key can charge cards on your account." },
  { name: "Stripe Publishable",   regex: /\bpk_live_[0-9a-zA-Z]{24,}\b/g,                     severity: "medium", env: "NEXT_PUBLIC_STRIPE_KEY",   fix: "Rotate in Stripe Dashboard → Developers → API keys. Move to env variable." },
  { name: "GitHub Token",         regex: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g,      severity: "high",   env: "GITHUB_TOKEN",             fix: "Revoke at github.com/settings/tokens immediately. Audit API call history." },
  { name: "JWT Token",            regex: /\beyJ[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_=]{10,}\.?[A-Za-z0-9-_.+/=]{10,}/g, severity: "medium", env: "JWT_SECRET", fix: "Rotate the JWT signing secret. Invalidate all active sessions tied to this key." },
  { name: "Google API Key",       regex: /\bAIza[0-9A-Za-z-_]{35}\b/g,                        severity: "high",   env: "GOOGLE_API_KEY",           fix: "Restrict key in Google Cloud Console → APIs & Services → Credentials." },
  { name: "Private Key Block",    regex: /-----BEGIN\s+(RSA|OPENSSH|EC|PGP|DSA)\s+PRIVATE KEY-----/g, severity: "high", env: null,              fix: "Remove from codebase immediately. Store in AWS Secrets Manager or HashiCorp Vault." },
  { name: "Slack Token",          regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,                  severity: "high",   env: "SLACK_TOKEN",              fix: "Revoke at api.slack.com/apps. Check Slack audit logs for unauthorized messages." },
  { name: "Database URL",         regex: /(mysql|postgres|postgresql|mongodb|redis):\/\/[^@\s:]+:[^@\s]+@[^\s'"]+/gi, severity: "high", env: "DATABASE_URL", fix: "Rotate database credentials immediately. Never commit connection strings." },
  { name: "Hardcoded Password",   regex: /\b(password|passwd|pwd)\s*[:=]\s*["'][^"']{6,}["']/gi, severity: "high",  env: "DB_PASSWORD",             fix: "Move to environment variable. Use a secrets manager in production." },
  { name: "SendGrid Key",         regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{40,}\b/g,   severity: "high",   env: "SENDGRID_API_KEY",         fix: "Revoke at app.sendgrid.com/settings/api_keys. Review email activity logs." },
  { name: "API Key Assignment",   regex: /\b(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["'`][A-Za-z0-9_\-]{20,}["'`]/gi, severity: "medium", env: "API_KEY", fix: "Move value to process.env.API_KEY and add to .env (ensure .env is in .gitignore)." },
  { name: "Secret Variable",      regex: /\b(secret|auth[_-]?token)\s*=\s*["'`][A-Za-z0-9_\-./+]{16,}["'`]/gi, severity: "medium", env: "SECRET_TOKEN", fix: "Move to environment variable. Use process.env.SECRET_TOKEN." },
  { name: "Twilio SID",           regex: /\bSK[0-9a-fA-F]{32}\b/g,                             severity: "high",   env: "TWILIO_API_KEY",           fix: "Revoke in Twilio Console → Account → API Keys & Tokens." },
];

function shannonEntropy(s) {
  const f = {};
  for (const c of s) f[c] = (f[c] || 0) + 1;
  let e = 0;
  for (const v of Object.values(f)) { const p = v / s.length; e -= p * Math.log2(p); }
  return e;
}

function scanContent(filename, content) {
  const lines = content.split("\n");
  const findings = [];
  const seen = new Set();

  for (const p of PATTERNS) {
    const re = new RegExp(p.regex.source, p.regex.flags);
    let m;
    while ((m = re.exec(content)) !== null) {
      const ln = content.substring(0, m.index).split("\n").length;
      const key = `${filename}:${ln}:${p.name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const v = m[0];
      const red = v.length > 10 ? v.slice(0, 4) + "●●●●" + v.slice(-4) : "●●●●";
      findings.push({
        id: `${filename}-${ln}-${p.name}`.replace(/\W/g, "-"),
        file: filename, line: ln, type: p.name,
        severity: p.severity, env: p.env, fix: p.fix,
        snippet: (lines[ln - 1] || "").trim(),
        redacted: red, rawLength: v.length, detectionMethod: "pattern",
      });
    }
  }

  const strRe = /["'`]([A-Za-z0-9+/=_\-]{25,})["'`]/g;
  let m2;
  while ((m2 = strRe.exec(content)) !== null) {
    const ent = shannonEntropy(m2[1]);
    if (ent < 4.5) continue;
    const ln = content.substring(0, m2.index).split("\n").length;
    const key = `${filename}:${ln}:entropy`;
    if (seen.has(key)) continue;
    if (findings.some(f => f.file === filename && f.line === ln)) continue;
    seen.add(key);
    findings.push({
      id: `${filename}-${ln}-entropy`.replace(/\W/g, "-"),
      file: filename, line: ln, type: "High Entropy String",
      severity: "medium", env: "SECRET_VALUE",
      fix: "High randomness suggests a secret. Review and move to an environment variable.",
      snippet: (lines[ln - 1] || "").trim(),
      redacted: m2[0].slice(0, 6) + "●●●",
      rawLength: m2[1].length, detectionMethod: "entropy", entropyScore: ent.toFixed(2),
    });
  }

  return findings;
}

function calcRisk(findings) {
  const h = findings.filter(f => f.severity === "high").length;
  const m = findings.filter(f => f.severity === "medium").length;
  const score = Math.min(100, h * 18 + m * 7);
  if (h >= 3 || score >= 54) return { score, level: "critical", label: "CRITICAL", color: "#f85149" };
  if (h >= 1 || score >= 14) return { score, level: "risky",    label: "RISKY",    color: "#f0883e" };
  return { score: 0, level: "safe", label: "SAFE", color: "#3fb950" };
}

const DEMO = [
  { id: "d1", file: "src/payments.js",      line: 14, type: "Stripe Secret Key",   severity: "high",   env: "STRIPE_SECRET_KEY",   fix: "Revoke at dashboard.stripe.com/apikeys. Anyone with this key can charge cards on your account.",         snippet: 'const stripe = require("stripe")("sk_live_4eC39HqLyjWDarjtT1zdp7dc");',         redacted: "sk_l●●●●7dc", rawLength: 32, detectionMethod: "pattern" },
  { id: "d2", file: "auth/token.ts",         line: 22, type: "JWT Token",            severity: "medium", env: "JWT_SECRET",           fix: "Rotate JWT signing secret. Invalidate all active sessions tied to this key.",                             snippet: 'const token = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.s3cr3t";',           redacted: "eyJh●●●●c3t", rawLength: 64, detectionMethod: "pattern" },
  { id: "d3", file: ".env.local",            line:  3, type: "GitHub Token",         severity: "high",   env: "GITHUB_TOKEN",         fix: "Revoke at github.com/settings/tokens immediately. Audit API call history.",                               snippet: "GITHUB_TOKEN=ghp_xA3mK9vL2nQ8wR5tY7uI0oP1eB4hF6cZ",                            redacted: "ghp_●●●●hF6", rawLength: 40, detectionMethod: "pattern" },
  { id: "d4", file: "config/database.js",   line:  8, type: "Database URL",          severity: "high",   env: "DATABASE_URL",         fix: "Rotate database credentials immediately. Never commit connection strings.",                                snippet: "const db = new Pool({ connectionString: 'postgres://admin:p@ssw0rd@prod.db.io/app' });", redacted: "post●●●●app", rawLength: 55, detectionMethod: "pattern" },
  { id: "d5", file: "utils/email.js",       line:  5, type: "SendGrid Key",          severity: "high",   env: "SENDGRID_API_KEY",     fix: "Revoke at app.sendgrid.com/settings/api_keys. Review email activity logs.",                               snippet: 'sgMail.setApiKey("SG.xxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy");',    redacted: "SG.x●●●●yyy", rawLength: 69, detectionMethod: "pattern" },
  { id: "d6", file: "lib/analytics.ts",     line: 31, type: "High Entropy String",   severity: "medium", env: "SECRET_VALUE",         fix: "High randomness suggests a secret. Review and move to an environment variable.",                           snippet: 'const trackKey = "xK9mN2vL8pQ3wR7tY0uI5oP4eB1hF6aD";',                         redacted: '"xK9mN●●●', rawLength: 32, detectionMethod: "entropy", entropyScore: "4.87" },
];

// ─── Component ────────────────────────────────────────────────────────────────

const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Syne:wght@600;700;800&family=JetBrains+Mono:wght@400;500;600&family=DM+Sans:opsz,wght@9..40,300;9..40,400;9..40,500;9..40,600&display=swap');
  *{box-sizing:border-box;margin:0;padding:0}
  @keyframes scanBeam{0%{top:-4px}100%{top:100%}}
  @keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
  @keyframes spin{to{transform:rotate(360deg)}}
  @keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
  @keyframes glow{0%,100%{opacity:.6}50%{opacity:1}}
  @keyframes slideDown{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
  .fade-up{animation:fadeUp .3s ease both}
  .slide-down{animation:slideDown .25s ease both}
  button{cursor:pointer;transition:all .15s ease}
  button:active{transform:scale(.97)}
  textarea:focus{outline:none}
  textarea{resize:vertical}
  .card{transition:border-color .2s,transform .15s}
  .card:hover{transform:translateY(-1px)}
  .spinner{width:15px;height:15px;border:2px solid rgba(0,212,255,.2);border-top:2px solid #00d4ff;border-radius:50%;animation:spin .7s linear infinite;display:inline-block;flex-shrink:0}
  .cursor{animation:blink 1s step-end infinite}
  .dot-pulse{animation:glow 1.5s ease-in-out infinite}
  ::-webkit-scrollbar{width:4px;height:4px}
  ::-webkit-scrollbar-thumb{background:#21262d;border-radius:2px}
`;

export default function Ghostkey() {
  const [view,       setView]       = useState("home");
  const [dark,       setDark]       = useState(true);
  const [files,      setFiles]      = useState([]);
  const [pasted,     setPasted]     = useState("");
  const [findings,   setFindings]   = useState([]);
  const [expanded,   setExpanded]   = useState(null);
  const [aiData,     setAiData]     = useState({});
  const [aiLoading,  setAiLoading]  = useState({});
  const [dragOver,   setDragOver]   = useState(false);
  const [scanStep,   setScanStep]   = useState(0);
  const [filter,     setFilter]     = useState("all");
  const fileRef = useRef();

  const STEPS = [
    "Initializing ghost scanner…",
    "Loading 14 detection patterns…",
    "Running entropy analysis…",
    "Scanning for API keys & tokens…",
    "Checking hardcoded credentials…",
    "JWT & cryptographic analysis…",
    "Detecting database URLs…",
    "Compiling security report…",
  ];

  // colour palette
  const C = {
    bg:      dark ? "#07080a" : "#f6f8fa",
    surface: dark ? "#0d1117" : "#ffffff",
    surf2:   dark ? "#161b22" : "#f0f2f5",
    border:  dark ? "#21262d" : "#d0d7de",
    text:    dark ? "#e6edf3" : "#1f2328",
    muted:   dark ? "#7d8590" : "#636c76",
    accent:  "#00d4ff",
    high:    "#f85149",
    medium:  "#f0883e",
    low:     "#3fb950",
  };

  const sevColor = s => s === "high" ? C.high : s === "medium" ? C.medium : C.low;
  const sevBg    = s => s === "high" ? "rgba(248,81,73,.12)" : s === "medium" ? "rgba(240,136,62,.12)" : "rgba(63,185,80,.12)";

  const risk    = calcRisk(findings);
  const hCount  = findings.filter(f => f.severity === "high").length;
  const mCount  = findings.filter(f => f.severity === "medium").length;
  const visible = filter === "all" ? findings : findings.filter(f => f.severity === filter);

  // ── File Handling ────────────────────────────────────────────────────────
  const readFile = f => new Promise(res => {
    const r = new FileReader();
    r.onload = e => res({ name: f.name, content: e.target.result });
    r.readAsText(f);
  });

  const handleFiles = useCallback(async list => {
    const exts = [".js",".ts",".jsx",".tsx",".env",".json",".py",".rb",".go",".yaml",".yml",".txt",".sh",".config",".toml",".ini",".md",".cs",".java",".php",".swift",".kt"];
    const valid = Array.from(list).filter(f => exts.some(e => f.name.toLowerCase().endsWith(e)));
    if (!valid.length) return;
    setFiles(await Promise.all(valid.map(readFile)));
  }, []);

  // ── Scan ─────────────────────────────────────────────────────────────────
  const runScan = useCallback(async (demo = false) => {
    setView("scanning");
    setScanStep(0);
    setExpanded(null);
    setAiData({});
    setFilter("all");

    for (let i = 0; i < STEPS.length; i++) {
      await new Promise(r => setTimeout(r, 220 + Math.random() * 180));
      setScanStep(i + 1);
    }
    await new Promise(r => setTimeout(r, 250));

    let found;
    if (demo) {
      found = DEMO;
    } else {
      found = [];
      for (const f of files) found.push(...scanContent(f.name, f.content));
      if (pasted.trim()) found.push(...scanContent("pasted-snippet.js", pasted));
      found = found.filter((x, i, a) => a.findIndex(y => y.id === x.id) === i);
    }

    setFindings(found);
    setView("results");
  }, [files, pasted]);

  // ── AI Explanation ───────────────────────────────────────────────────────
  const fetchAI = useCallback(async finding => {
    if (aiData[finding.id] || aiLoading[finding.id]) return;
    setAiLoading(p => ({ ...p, [finding.id]: true }));
    try {
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          system: "You are a senior security engineer. Given a leaked secret finding, write exactly 2–3 sentences of plain prose: (1) the concrete risk of this specific exposure, (2) how an attacker could exploit it right now. End with one bolded immediate action sentence starting with '→ '. No headers, no bullets, no markdown except the bold arrow line.",
          messages: [{ role: "user", content: `Type: ${finding.type}\nFile: ${finding.file}:${finding.line}\nCode: ${finding.snippet}\nSeverity: ${finding.severity}` }],
        }),
      });
      const d = await res.json();
      setAiData(p => ({ ...p, [finding.id]: d.content?.[0]?.text || "Explanation unavailable." }));
    } catch {
      setAiData(p => ({ ...p, [finding.id]: "AI explanation unavailable — check your connection." }));
    } finally {
      setAiLoading(p => ({ ...p, [finding.id]: false }));
    }
  }, [aiData, aiLoading]);

  const toggleExpand = (id, finding) => {
    if (expanded === id) { setExpanded(null); return; }
    setExpanded(id);
    fetchAI(finding);
  };

  // ── Export ───────────────────────────────────────────────────────────────
  const exportJSON = () => {
    const blob = new Blob([JSON.stringify({ findings, risk, scanned: new Date().toISOString() }, null, 2)], { type: "application/json" });
    Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: "ghostkey-report.json" }).click();
  };

  // ── Shared UI ────────────────────────────────────────────────────────────
  const Navbar = () => (
    <nav style={{ background: C.bg, borderBottom: `1px solid ${C.border}`, height: 54, display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 24px", position: "sticky", top: 0, zIndex: 100, backdropFilter: "blur(8px)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 9, cursor: "pointer" }} onClick={() => setView("home")}>
        <div style={{ width: 30, height: 30, borderRadius: 7, background: `${C.accent}12`, border: `1px solid ${C.accent}35`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 15 }}>👻</div>
        <span style={{ fontFamily: "'Syne', sans-serif", fontWeight: 800, fontSize: 17, letterSpacing: "-.03em", color: C.text }}>Ghostkey</span>
        <span style={{ fontSize: 9, fontFamily: "'JetBrains Mono', monospace", color: C.accent, background: `${C.accent}18`, border: `1px solid ${C.accent}30`, padding: "1px 7px", borderRadius: 4, letterSpacing: ".04em" }}>BETA</span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        {view === "results" && (
          <button onClick={() => { setView("home"); setFiles([]); setPasted(""); setFindings([]); }}
            style={{ background: "none", border: `1px solid ${C.border}`, color: C.muted, borderRadius: 7, padding: "4px 12px", fontSize: 12, fontFamily: "'DM Sans', sans-serif" }}>
            ← New Scan
          </button>
        )}
        <button onClick={() => setDark(d => !d)}
          style={{ background: C.surf2, border: `1px solid ${C.border}`, borderRadius: 7, padding: "5px 9px", fontSize: 13, color: C.muted, lineHeight: 1 }}>
          {dark ? "☀️" : "🌙"}
        </button>
      </div>
    </nav>
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // HOME
  // ═══════════════════════════════════════════════════════════════════════════
  if (view === "home") return (
    <div style={{ fontFamily: "'DM Sans', sans-serif", background: C.bg, color: C.text, minHeight: "100vh" }}>
      <style>{CSS}</style>
      <Navbar />

      <div style={{ maxWidth: 680, margin: "0 auto", padding: "52px 20px 60px" }}>

        {/* Hero */}
        <div style={{ textAlign: "center", marginBottom: 44 }} className="fade-up">
          <div style={{ display: "inline-flex", alignItems: "center", gap: 7, background: `${C.accent}0e`, border: `1px solid ${C.accent}28`, borderRadius: 20, padding: "4px 14px", marginBottom: 22, fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: C.accent }}>
            <span className="dot-pulse" style={{ width: 6, height: 6, borderRadius: "50%", background: C.accent, display: "inline-block", boxShadow: `0 0 7px ${C.accent}` }} />
            Privacy-first · In-browser · Zero storage
          </div>

          <h1 style={{ fontFamily: "'Syne', sans-serif", fontSize: "clamp(30px,5vw,50px)", fontWeight: 800, letterSpacing: "-.04em", lineHeight: 1.1, marginBottom: 14 }}>
            Find leaked secrets<br />
            <span style={{ color: C.accent }}>before they find you.</span>
          </h1>
          <p style={{ color: C.muted, fontSize: 15, lineHeight: 1.7, maxWidth: 450, margin: "0 auto" }}>
            Ghostkey scans your code for exposed API keys, tokens & credentials — with AI-powered risk analysis and instant fix suggestions.
          </p>
        </div>

        {/* Upload Zone */}
        <div className="fade-up" style={{ animationDelay: ".08s" }}
          onDragOver={e => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={e => { e.preventDefault(); setDragOver(false); handleFiles(e.dataTransfer.files); }}
          onClick={() => !files.length && fileRef.current?.click()}
          style={{
            border: `2px dashed ${dragOver ? C.accent : files.length ? C.accent + "55" : C.border}`,
            borderRadius: 14, padding: "30px 24px", textAlign: "center",
            cursor: files.length ? "default" : "pointer",
            background: dragOver ? `${C.accent}07` : files.length ? `${C.accent}04` : C.surface,
            transition: "all .2s ease", marginBottom: 14,
            boxShadow: dragOver ? `0 0 0 4px ${C.accent}18` : "none",
          }}>
          <input ref={fileRef} type="file" multiple accept=".js,.ts,.jsx,.tsx,.env,.json,.py,.rb,.go,.yaml,.yml,.txt,.sh,.config,.toml,.ini,.md" style={{ display: "none" }} onChange={e => handleFiles(e.target.files)} />

          {!files.length ? (
            <>
              <div style={{ fontSize: 34, marginBottom: 10 }}>📁</div>
              <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 5 }}>Drop files here, or click to upload</div>
              <div style={{ fontSize: 12, color: C.muted }}>.js · .ts · .env · .json · .py · .go · .yaml · and more</div>
            </>
          ) : (
            <>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 7, justifyContent: "center", marginBottom: 12 }}>
                {files.map(f => (
                  <div key={f.name} style={{ background: C.surf2, border: `1px solid ${C.border}`, borderRadius: 6, padding: "3px 10px", fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: C.muted, display: "flex", alignItems: "center", gap: 5 }}>
                    📄 {f.name}
                    <span onClick={e => { e.stopPropagation(); setFiles(files.filter(x => x.name !== f.name)); }}
                      style={{ color: C.high, cursor: "pointer", fontSize: 15, lineHeight: 1, fontFamily: "sans-serif" }}>×</span>
                  </div>
                ))}
              </div>
              <div onClick={() => fileRef.current?.click()} style={{ fontSize: 12, color: C.accent, cursor: "pointer" }}>+ Add more files</div>
            </>
          )}
        </div>

        {/* OR divider */}
        <div className="fade-up" style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 14, animationDelay: ".12s" }}>
          <div style={{ flex: 1, height: 1, background: C.border }} />
          <span style={{ fontSize: 10, color: C.muted, fontFamily: "'JetBrains Mono', monospace", letterSpacing: ".07em" }}>OR PASTE CODE</span>
          <div style={{ flex: 1, height: 1, background: C.border }} />
        </div>

        {/* Paste Area */}
        <div className="fade-up" style={{ position: "relative", marginBottom: 18, animationDelay: ".15s" }}>
          <textarea value={pasted} onChange={e => setPasted(e.target.value)}
            placeholder={"// Paste code snippet here…\nconst stripe = require('stripe')('sk_live_4eC39HqLyjWD…');\nconst jwtSecret = \"eyJhbGciOiJIUzI1NiJ9…\";\nprocess.env.DATABASE_URL = 'postgres://user:pass@host/db';"}
            style={{ width: "100%", minHeight: 130, background: C.surface, border: `1px solid ${pasted ? C.accent + "55" : C.border}`, borderRadius: 10, padding: "13px 15px", fontSize: 12, fontFamily: "'JetBrains Mono', monospace", color: C.text, lineHeight: 1.65, transition: "border-color .2s" }} />
          {pasted && <span onClick={() => setPasted("")} style={{ position: "absolute", top: 9, right: 10, color: C.muted, cursor: "pointer", fontSize: 17, lineHeight: 1, fontFamily: "sans-serif" }}>×</span>}
        </div>

        {/* Action Buttons */}
        <div className="fade-up" style={{ display: "flex", gap: 10, marginBottom: 36, animationDelay: ".18s" }}>
          <button onClick={() => runScan(false)} disabled={!files.length && !pasted.trim()}
            style={{
              flex: 1, padding: "12px 20px", borderRadius: 9, border: "none",
              background: (files.length || pasted.trim()) ? `linear-gradient(135deg,${C.accent},#008eb0)` : C.surf2,
              color: (files.length || pasted.trim()) ? "#000" : C.muted,
              fontSize: 14, fontWeight: 700, fontFamily: "'Syne', sans-serif",
              boxShadow: (files.length || pasted.trim()) ? `0 4px 22px ${C.accent}35` : "none",
            }}>
            🔍 Scan for Secrets
          </button>
          <button onClick={() => runScan(true)}
            style={{ padding: "12px 18px", borderRadius: 9, border: `1px solid ${C.border}`, background: C.surface, color: C.muted, fontSize: 13, fontFamily: "'DM Sans', sans-serif", whiteSpace: "nowrap" }}>
            Try Demo
          </button>
        </div>

        {/* Feature Cards */}
        <div className="fade-up" style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 10, animationDelay: ".22s" }}>
          {[
            { icon: "🔍", title: "14 Patterns",    desc: "AWS, Stripe, GitHub, JWT, DB URLs & more" },
            { icon: "🧮", title: "Entropy Check",   desc: "Flags random strings above entropy 4.5" },
            { icon: "🤖", title: "AI Analysis",      desc: "Claude explains risk & impact per secret" },
          ].map(x => (
            <div key={x.title} style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 11, padding: "18px 14px", textAlign: "center" }}>
              <div style={{ fontSize: 24, marginBottom: 7 }}>{x.icon}</div>
              <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 3 }}>{x.title}</div>
              <div style={{ fontSize: 11, color: C.muted, lineHeight: 1.5 }}>{x.desc}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // SCANNING
  // ═══════════════════════════════════════════════════════════════════════════
  if (view === "scanning") return (
    <div style={{ fontFamily: "'DM Sans', sans-serif", background: C.bg, color: C.text, minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      <style>{CSS}</style>
      <Navbar />
      <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: 24 }}>

        {/* Scanner Visualiser */}
        <div style={{ width: 190, height: 190, position: "relative", border: `1px solid ${C.border}`, borderRadius: 14, overflow: "hidden", background: C.surface, marginBottom: 38, boxShadow: `0 0 40px ${C.accent}15` }}>
          {/* Grid overlay */}
          <div style={{ position: "absolute", inset: 0, display: "grid", gridTemplateColumns: "repeat(9,1fr)", gridTemplateRows: "repeat(9,1fr)", opacity: .12 }}>
            {Array(81).fill(0).map((_, i) => <div key={i} style={{ border: `0.5px solid ${C.accent}` }} />)}
          </div>
          {/* Scan beam */}
          <div style={{ position: "absolute", left: 0, right: 0, height: 3, background: `linear-gradient(90deg,transparent,${C.accent},transparent)`, boxShadow: `0 0 14px ${C.accent}`, animation: "scanBeam 1.6s linear infinite" }} />
          {/* Ghost icon */}
          <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 5 }}>
            <div style={{ fontSize: 40 }}>👻</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: C.accent, letterSpacing: ".12em" }} className="dot-pulse">SCANNING</div>
          </div>
        </div>

        {/* Progress bar */}
        <div style={{ width: "100%", maxWidth: 380, marginBottom: 22 }}>
          <div style={{ background: C.border, borderRadius: 4, height: 3, marginBottom: 14, overflow: "hidden" }}>
            <div style={{ height: "100%", background: `linear-gradient(90deg,${C.accent},#008eb0)`, width: `${(scanStep / STEPS.length) * 100}%`, transition: "width .35s ease", borderRadius: 4, boxShadow: `0 0 8px ${C.accent}` }} />
          </div>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: C.accent, textAlign: "center" }}>
            {STEPS[Math.min(scanStep, STEPS.length - 1)]}
            <span className="cursor">▌</span>
          </div>
        </div>

        {/* Completed steps */}
        <div style={{ display: "flex", flexDirection: "column", gap: 5, width: "100%", maxWidth: 380 }}>
          {STEPS.slice(0, scanStep).map((s, i) => (
            <div key={i} className="fade-up" style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, color: C.muted, fontFamily: "'JetBrains Mono', monospace" }}>
              <span style={{ color: "#3fb950" }}>✓</span>{s}
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // RESULTS
  // ═══════════════════════════════════════════════════════════════════════════
  return (
    <div style={{ fontFamily: "'DM Sans', sans-serif", background: C.bg, color: C.text, minHeight: "100vh" }}>
      <style>{CSS}</style>
      <Navbar />

      <div style={{ maxWidth: 860, margin: "0 auto", padding: "28px 20px 60px" }}>

        {/* ── Summary Card ──────────────────────────────────────────────── */}
        <div className="fade-up" style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 16, padding: "22px 24px", marginBottom: 20, display: "grid", gridTemplateColumns: "1fr auto", gap: 20, alignItems: "center" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8, flexWrap: "wrap" }}>
              <h2 style={{ fontFamily: "'Syne', sans-serif", fontWeight: 800, fontSize: 20, letterSpacing: "-.03em" }}>
                {findings.length === 0 ? "✅ No secrets found" : `🚨 ${findings.length} Secret${findings.length > 1 ? "s" : ""} Detected`}
              </h2>
              <span style={{ background: risk.color + "18", color: risk.color, border: `1px solid ${risk.color}35`, borderRadius: 6, padding: "2px 10px", fontSize: 10, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", letterSpacing: ".07em" }}>
                {risk.label}
              </span>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 14, fontSize: 13, color: C.muted }}>
              {hCount > 0 && <span style={{ color: C.high, fontWeight: 500 }}>🔴 {hCount} High severity</span>}
              {mCount > 0 && <span style={{ color: C.medium, fontWeight: 500 }}>🟠 {mCount} Medium severity</span>}
              {findings.length === 0 && <span style={{ color: C.low }}>🟢 Your code looks clean!</span>}
              <span>Scanned {files.length || 1} file{(files.length || 1) > 1 ? "s" : ""}</span>
            </div>
          </div>

          {/* Risk ring */}
          <div style={{ textAlign: "center", flexShrink: 0 }}>
            <svg width={68} height={68} viewBox="0 0 68 68">
              <circle cx="34" cy="34" r="26" fill="none" stroke={C.border} strokeWidth="5" />
              <circle cx="34" cy="34" r="26" fill="none" stroke={risk.color} strokeWidth="5"
                strokeDasharray={`${(risk.score / 100) * 163.4} 163.4`} strokeLinecap="round"
                transform="rotate(-90 34 34)"
                style={{ transition: "stroke-dasharray 1.2s ease", filter: `drop-shadow(0 0 5px ${risk.color})` }} />
              <text x="34" y="38" textAnchor="middle" fill={risk.color} fontSize="13" fontWeight="700" fontFamily="JetBrains Mono,monospace">{risk.score}</text>
            </svg>
            <div style={{ fontSize: 9, color: C.muted, marginTop: 1, fontFamily: "'JetBrains Mono', monospace", letterSpacing: ".08em" }}>RISK SCORE</div>
          </div>
        </div>

        {findings.length > 0 && (
          <>
            {/* Filter + Export */}
            <div className="fade-up" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14, flexWrap: "wrap", gap: 8, animationDelay: ".06s" }}>
              <div style={{ display: "flex", gap: 6 }}>
                {[["all", `All (${findings.length})`], ["high", `High (${hCount})`], ["medium", `Medium (${mCount})`]].map(([k, label]) => (
                  <button key={k} onClick={() => setFilter(k)} style={{ padding: "4px 13px", borderRadius: 6, border: `1px solid ${filter === k ? C.accent : C.border}`, background: filter === k ? `${C.accent}16` : C.surface, color: filter === k ? C.accent : C.muted, fontSize: 11, fontFamily: "'JetBrains Mono', monospace", letterSpacing: ".04em", textTransform: "uppercase" }}>
                    {label}
                  </button>
                ))}
              </div>
              <button onClick={exportJSON} style={{ padding: "4px 13px", borderRadius: 6, border: `1px solid ${C.border}`, background: C.surface, color: C.muted, fontSize: 12, display: "flex", alignItems: "center", gap: 5 }}>
                📥 Export JSON
              </button>
            </div>

            {/* ── Finding Cards ──────────────────────────────────────────── */}
            <div style={{ display: "flex", flexDirection: "column", gap: 9 }}>
              {visible.map((f, idx) => (
                <div key={f.id} className="card fade-up" style={{ background: C.surface, border: `1px solid ${expanded === f.id ? sevColor(f.severity) + "45" : C.border}`, borderRadius: 13, overflow: "hidden", animationDelay: `${idx * .04}s` }}>

                  {/* Header row */}
                  <div onClick={() => toggleExpand(f.id, f)} style={{ padding: "13px 16px", cursor: "pointer", display: "grid", gridTemplateColumns: "auto 1fr auto", gap: 12, alignItems: "center" }}>
                    <div style={{ background: sevBg(f.severity), color: sevColor(f.severity), border: `1px solid ${sevColor(f.severity)}30`, borderRadius: 6, padding: "3px 9px", fontSize: 9, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", letterSpacing: ".08em", whiteSpace: "nowrap" }}>
                      {f.severity === "high" ? "● HIGH" : f.severity === "medium" ? "● MED" : "● LOW"}
                    </div>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 2 }}>{f.type}</div>
                      <div style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: C.muted }}>
                        {f.file}<span style={{ color: C.accent }}>:{f.line}</span>
                        {f.detectionMethod === "entropy" && <span style={{ marginLeft: 9, color: C.medium }}>entropy {f.entropyScore}</span>}
                      </div>
                    </div>
                    <div style={{ color: C.muted, fontSize: 13, transition: "transform .2s", transform: expanded === f.id ? "rotate(180deg)" : "none" }}>▾</div>
                  </div>

                  {/* Expanded panel */}
                  {expanded === f.id && (
                    <div className="slide-down" style={{ borderTop: `1px solid ${C.border}`, padding: "18px 18px", display: "flex", flexDirection: "column", gap: 15 }}>

                      {/* Snippet */}
                      <div>
                        <div style={{ fontSize: 10, color: C.muted, fontFamily: "'JetBrains Mono', monospace", marginBottom: 6, letterSpacing: ".07em", textTransform: "uppercase" }}>Code Snippet · Line {f.line}</div>
                        <div style={{ background: C.surf2, borderRadius: 9, padding: "11px 13px", fontFamily: "'JetBrains Mono', monospace", fontSize: 11, lineHeight: 1.65, overflowX: "auto" }}>
                          <span style={{ color: C.muted, marginRight: 12, userSelect: "none" }}>{f.line}</span>
                          <span style={{ color: C.text }}>{f.snippet}</span>
                        </div>
                        <div style={{ marginTop: 7, display: "flex", alignItems: "center", gap: 7, fontSize: 11 }}>
                          <span style={{ color: C.muted }}>Detected value:</span>
                          <code style={{ fontFamily: "'JetBrains Mono', monospace", background: sevBg(f.severity), color: sevColor(f.severity), border: `1px solid ${sevColor(f.severity)}25`, borderRadius: 4, padding: "1px 7px", fontSize: 11 }}>{f.redacted}</code>
                          <span style={{ color: C.muted, fontSize: 10 }}>({f.rawLength} chars)</span>
                        </div>
                      </div>

                      {/* AI Analysis */}
                      <div>
                        <div style={{ fontSize: 10, color: C.muted, fontFamily: "'JetBrains Mono', monospace", marginBottom: 6, letterSpacing: ".07em", textTransform: "uppercase", display: "flex", alignItems: "center", gap: 6 }}>🤖 AI Risk Analysis</div>
                        <div style={{ background: `${C.accent}09`, border: `1px solid ${C.accent}22`, borderRadius: 9, padding: "12px 14px", fontSize: 13, lineHeight: 1.65 }}>
                          {aiLoading[f.id] ? (
                            <div style={{ display: "flex", alignItems: "center", gap: 8, color: C.muted }}>
                              <span className="spinner" /> Analyzing with Claude…
                            </div>
                          ) : aiData[f.id] ? (
                            <span style={{ color: C.text }}>{aiData[f.id]}</span>
                          ) : (
                            <span style={{ color: C.muted }}>Fetching AI analysis…</span>
                          )}
                        </div>
                      </div>

                      {/* Fix Panel */}
                      <div>
                        <div style={{ fontSize: 10, color: C.muted, fontFamily: "'JetBrains Mono', monospace", marginBottom: 8, letterSpacing: ".07em", textTransform: "uppercase" }}>🛠️ Fix Suggestions</div>
                        <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
                          {f.env && (
                            <div style={{ background: C.surf2, borderRadius: 8, padding: "10px 13px" }}>
                              <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 4, color: "#3fb950" }}>✅ Add to .env file</div>
                              <code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: C.muted }}>{f.env}=your_actual_value</code>
                            </div>
                          )}
                          {f.env && (
                            <div style={{ background: C.surf2, borderRadius: 8, padding: "10px 13px" }}>
                              <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 4, color: C.accent }}>🔄 Replace with process.env</div>
                              <code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: C.muted }}>process.env.{f.env}</code>
                            </div>
                          )}
                          <div style={{ background: `${C.high}0a`, border: `1px solid ${C.high}22`, borderRadius: 8, padding: "10px 13px" }}>
                            <div style={{ fontWeight: 600, fontSize: 12, marginBottom: 4, color: C.high }}>🚨 Immediate Action Required</div>
                            <div style={{ fontSize: 12, color: C.muted, lineHeight: 1.55 }}>{f.fix}</div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </>
        )}

        {/* Empty state */}
        {findings.length === 0 && (
          <div className="fade-up" style={{ textAlign: "center", padding: "52px 24px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: 14 }}>
            <div style={{ fontSize: 50, marginBottom: 12 }}>🎉</div>
            <h3 style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700, fontSize: 20, marginBottom: 8 }}>All Clear!</h3>
            <p style={{ color: C.muted, fontSize: 14, lineHeight: 1.65, maxWidth: 380, margin: "0 auto" }}>No secrets or credentials were detected. Keep it that way — always use environment variables and add <code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>.env</code> to your <code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>.gitignore</code>.</p>
          </div>
        )}

        {/* Privacy Banner */}
        <div style={{ marginTop: 22, background: `${C.accent}07`, border: `1px solid ${C.accent}20`, borderRadius: 10, padding: "11px 15px", display: "flex", alignItems: "center", gap: 9, fontSize: 12, color: C.muted }}>
          <span style={{ color: C.accent, flexShrink: 0 }}>🔒</span>
          <span>Your code never leaves this session. All scanning happens in-memory. Nothing is stored or transmitted to any server.</span>
        </div>
      </div>
    </div>
  );
}
