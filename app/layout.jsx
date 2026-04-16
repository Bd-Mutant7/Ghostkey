export const metadata = {
  title: "Ghostkey – Secrets Leak Detector",
  description:
    "Find leaked API keys, tokens and credentials in your codebase — privacy-first, in-browser scanning with AI-powered risk analysis.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, padding: 0 }}>{children}</body>
    </html>
  );
}
