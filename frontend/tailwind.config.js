/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        base: "#EDEFF2",
        panel: "#FFFFFF",
        line: "#D8DCE3",
        ink: "#14181F",
        inkfaint: "#5C6270",
        signal: "#2A5CA6",
        signalDark: "#1D4278",
        malicious: "#B23A2F",
        maliciousBg: "#F7E7E4",
        safe: "#2F7A4D",
        safeBg: "#E6F0E9",
        unknown: "#8A8F98",
        unknownBg: "#EDEDEF",
      },
      fontFamily: {
        display: ["'Space Grotesk'", "sans-serif"],
        body: ["'IBM Plex Sans'", "sans-serif"],
        mono: ["'IBM Plex Mono'", "monospace"],
      },
    },
  },
  plugins: [],
};
