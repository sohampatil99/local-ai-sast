import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Local AI SAST",
  description: "Offline AI-assisted static application security testing",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="font-sans antialiased">{children}</body>
    </html>
  );
}
