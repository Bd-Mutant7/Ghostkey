# 👻 Ghostkey — Secrets Leak Detector

> Find exposed API keys, tokens & credentials in your codebase — before attackers do.

![Next.js](https://img.shields.io/badge/Next.js-14-black?logo=next.js)
![Vercel](https://img.shields.io/badge/Deploy-Vercel-black?logo=vercel)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## ✨ Features

- 🔍 **14 detection patterns** — AWS, Stripe, GitHub, Google, JWT, Slack, SendGrid, Twilio, DB URLs, hardcoded passwords
- 🧮 **Shannon entropy analysis** — catches random-looking secrets no regex can name
- 🤖 **AI risk analysis** — Claude explains the real-world impact of each finding
- 🛠️ **Fix suggestions** — exact `.env` variable names and `process.env` replacements
- 📥 **Export JSON report** — one-click download of all findings
- 🔒 **Privacy-first** — files processed in-memory, never stored or uploaded
- 🌙 **Dark / light mode**

---

## 🗂️ Project Structure

```
ghostkey/
├── app/
│   ├── layout.jsx          ← Root HTML shell (Next.js App Router)
│   ├── page.jsx            ← Main Ghostkey UI (scanner + results)
│   └── api/
│       └── explain/
│           └── route.js    ← Server-side API route → calls Anthropic
├── .env.example            ← Copy this to .env.local
├── .gitignore
├── next.config.mjs
├── package.json
└── README.md
```

---

## 🚀 Local Setup (5 minutes)

### 1. Prerequisites
- [Node.js 18+](https://nodejs.org/) installed
- An [Anthropic API key](https://console.anthropic.com/settings/keys) (free tier works)

### 2. Clone or create the project

```bash
# If you're starting fresh:
mkdir ghostkey && cd ghostkey

# Copy all project files into this folder (see structure above)
```

### 3. Install dependencies

```bash
npm install
```

### 4. Set up your environment variable

```bash
# Copy the example file
cp .env.example .env.local

# Open .env.local and add your real key:
# ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

> ⚠️ **Never commit `.env.local`** — it's already in `.gitignore`

### 5. Run the dev server

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) — you should see Ghostkey's home page.

---

## ☁️ Deploy to Vercel (the right way)

Getting a **404** after deploying usually means the project was deployed as a raw file
instead of a proper Next.js app. Follow these steps exactly:

### Step 1 — Push to GitHub

```bash
git init
git add .
git commit -m "feat: initial Ghostkey setup"

# Create a new repo on github.com, then:
git remote add origin https://github.com/YOUR_USERNAME/ghostkey.git
git push -u origin main
```

### Step 2 — Import into Vercel

1. Go to [vercel.com/new](https://vercel.com/new)
2. Click **"Import Git Repository"**
3. Select your `ghostkey` repo
4. Vercel will auto-detect **Next.js** — leave all framework settings as-is
5. **Do NOT click Deploy yet** — add the env var first (Step 3)

### Step 3 — Add your API key in Vercel

Before deploying, scroll to **"Environment Variables"** on the import screen:

| Name | Value |
|------|-------|
| `ANTHROPIC_API_KEY` | `sk-ant-xxxxxxxxxxxxxxxx` |

Then click **Deploy**.

### Step 4 — Verify

Your app will be live at `https://ghostkey-xxx.vercel.app`. The home page should load immediately. Hit **Try Demo** to confirm everything works end-to-end.

---

## 🔧 Why Was There a 404?

A 404 on Vercel happens when:

| Cause | Fix |
|-------|-----|
| Deployed a raw `.jsx` file directly (not a Next.js project) | Use this full project structure |
| Missing `app/page.jsx` as the entry point | ✅ Already included here |
| Missing `package.json` with `next` as a dependency | ✅ Already included here |
| Wrong framework detected in Vercel settings | Re-import and confirm "Next.js" is selected |

The key rule: **Vercel needs a Next.js project folder**, not a single component file.

---

## 🔑 Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes (for AI analysis) | Your key from console.anthropic.com. The app works without it — AI explanations will show an error message instead |

---

## 🧠 How the AI Analysis Works

When you expand a finding, Ghostkey calls `/api/explain` — a **server-side Next.js route** that:

1. Receives the finding details (type, file, line, snippet)
2. Calls the Anthropic API using your `ANTHROPIC_API_KEY` env var
3. Returns a 2–3 sentence plain-English risk explanation

The API key **never touches the browser** — it stays on the server. This is the secure pattern for any AI-powered Next.js app.

---

## 🛡️ Detection Patterns

| Pattern | Severity | Example |
|---------|----------|---------|
| AWS Access Key | 🔴 High | `AKIAXXXXXXXXXXXXXXXX` |
| Stripe Secret | 🔴 High | `sk_live_...` |
| GitHub Token | 🔴 High | `ghp_...` |
| Google API Key | 🔴 High | `AIzaXXXXX...` |
| Private Key Block | 🔴 High | `-----BEGIN RSA PRIVATE KEY-----` |
| Slack Token | 🔴 High | `xoxb-...` |
| Database URL | 🔴 High | `postgres://user:pass@host/db` |
| Hardcoded Password | 🔴 High | `password = "hunter2"` |
| SendGrid Key | 🔴 High | `SG.xxxxx.yyyyy` |
| Twilio SID | 🔴 High | `SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| JWT Token | 🟠 Medium | `eyJhbGci...` |
| Stripe Publishable | 🟠 Medium | `pk_live_...` |
| API Key Assignment | 🟠 Medium | `api_key = "abc123..."` |
| High Entropy String | 🟠 Medium | Any 25+ char string with entropy > 4.5 |

---

## 📄 License

MIT — use it, fork it, ship it.

---

## 🙋 Troubleshooting

**"AI explanation unavailable"** → Add `ANTHROPIC_API_KEY` to Vercel → Settings → Environment Variables, then redeploy.

**Files not uploading** → Supported extensions: `.js .ts .jsx .tsx .env .json .py .rb .go .yaml .yml .txt .sh .config .toml .ini .md .cs .java .php .swift .kt`

**Build fails on Vercel** → Make sure `package.json` is at the root of the repo, not inside a subfolder.

**Still getting 404** → In Vercel project settings, go to **General → Framework Preset** and confirm it says **Next.js**.
