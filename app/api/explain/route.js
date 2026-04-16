// app/api/explain/route.js
// Server-side only — ANTHROPIC_API_KEY is never sent to the browser

export async function POST(req) {
  const { type, file, line, snippet, severity } = await req.json();

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return Response.json(
      { error: "ANTHROPIC_API_KEY not configured. Add it in Vercel → Settings → Environment Variables." },
      { status: 500 }
    );
  }

  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 300,
      system:
        "You are a senior security engineer. Given a leaked secret finding, write exactly 2–3 sentences of plain prose: (1) the concrete risk of this specific exposure, (2) how an attacker could exploit it right now. End with one bolded immediate action sentence starting with '→ '. No headers, no bullets, no markdown except the bold arrow line.",
      messages: [
        {
          role: "user",
          content: `Type: ${type}\nFile: ${file}:${line}\nCode: ${snippet}\nSeverity: ${severity}`,
        },
      ],
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    return Response.json({ error: `Anthropic API error: ${err}` }, { status: res.status });
  }

  const data = await res.json();
  const text = data.content?.[0]?.text ?? "Explanation unavailable.";
  return Response.json({ text });
}
