import type { Config } from "tailwindcss";

// Every color is a CSS variable (app/globals.css) so light and dark themes switch in one place.
const v = (name: string) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: v("bg"), surface: v("surface"), raised: v("raised"), line: v("line"),
        ink: v("ink"), muted: v("muted"),
        citrine: v("citrine"), lilac: v("lilac"), lilacInk: v("lilac-ink"), void: v("void"), accent: v("accent"),
        crit: v("crit"), high: v("high"), med: v("med"), low: v("low"), ok: v("ok"),
      },
      fontFamily: {
        sans: ["Segoe UI Variable", "Segoe UI", "system-ui", "-apple-system", "sans-serif"],
        mono: ["Cascadia Mono", "Consolas", "ui-monospace", "monospace"],
      },
      borderRadius: { card: "14px" },
    },
  },
  plugins: [],
} satisfies Config;
