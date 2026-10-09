import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#0a0c10",
        surface: "#11141c",
        "surface-border": "#1b2230",
        cyber: {
          cyan: "#00f0ff",
          emerald: "#00ff9d",
          rose: "#ff0055",
          amber: "#ffb800",
        },
      },
    },
  },
  plugins: [],
};
export default config;
