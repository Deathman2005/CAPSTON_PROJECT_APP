/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        shield: {
          dark: '#0b0f19',
          card: '#111827',
          border: '#1f2937',
          accent: '#06b6d4',
          safe: '#10b981',
          warning: '#f59e0b',
          danger: '#ef4444',
          unknown: '#6b7280',
        }
      }
    },
  },
  plugins: [],
}
