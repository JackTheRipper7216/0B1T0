import type { NextConfig } from "next";
import { resolve } from "node:path";

const apiOrigin = process.env.API_ORIGIN ?? "http://127.0.0.1:8000";

const nextConfig: NextConfig = {
  allowedDevOrigins: ["127.0.0.1", "localhost"],
  distDir: process.env.NEXT_DIST_DIR ?? ".next",
  experimental: {
    // Matrix campaigns can run for five minutes plus a final provider retry window.
    proxyTimeout: 15 * 60 * 1000,
  },
  turbopack: {
    root: resolve(__dirname, "../.."),
  },
  async rewrites() {
    return [
      {
        source: "/api/v1/:path*",
        destination: `${apiOrigin}/api/v1/:path*`,
      },
    ];
  },
};

export default nextConfig;
