// Production: a static export that FastAPI serves from backend/static, so the dashboard needs no Node at runtime.
// Development (`npm run dev`): API calls are proxied to the FastAPI server on port 8000.
const dev = process.env.NODE_ENV === "development";

/** @type {import('next').NextConfig} */
const config = dev
  ? { async rewrites() { return [{ source: "/api/:path*", destination: "http://127.0.0.1:8000/api/:path*" }]; } }
  : { output: "export", images: { unoptimized: true } };

export default config;
