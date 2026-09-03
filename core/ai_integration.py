import os, json, sqlite3
from openai import OpenAI

class AIIntegration:
    def __init__(self, db_conn):
        self.db = db_conn
        self.keys = self.load_keys()

    # ---------------- LOAD KEYS ----------------
    def load_keys(self):
        """Load API keys (env vars -> user config -> local gitignored file)."""
        from config import load_api_keys
        return load_api_keys()

    def get_key(self, provider):
        """Return key for a given provider (e.g., 'openai')"""
        return self.keys.get(provider)

    def available_providers(self):
        """Return list of providers with keys configured"""
        return [p for p, k in self.keys.items() if k]

    # ---------------- THREAT SUMMARIZATION ----------------
    def summarize_threats(self, provider="openai"):
        """Fetch threats from DB and summarize with AI"""
        cursor = self.db.cursor()
        cursor.execute("SELECT timestamp, type, name FROM threats ORDER BY id DESC LIMIT 20")
        rows = cursor.fetchall()
        text = "\n".join(f"{r[0]} [{r[1]}] {r[2]}" for r in rows)

        if not text:
            return "No recent threats found."

        key = self.get_key(provider)
        if not key:
            return f"No API key for {provider}"

        if provider == "openai":
            try:
                client = OpenAI(api_key=key)
                prompt = f"Summarize these security threats in plain English:\n{text}"
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.choices[0].message.content
            except Exception as e:
                return f"[AI Error] {e}"

        # For now, simulate other providers
        return f"[Simulated {provider}] Summary of threats:\n{text}"

    # ---------------- CHAT ----------------
    def chat(self, provider, message):
        """Send a chat message to the AI provider"""
        key = self.get_key(provider)
        if not key:
            return f"No API key for {provider}"

        if provider == "openai":
            try:
                client = OpenAI(api_key=key)
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": message}]
                )
                return response.choices[0].message.content
            except Exception as e:
                return f"[AI Error] {e}"

        # For other providers (Anthropic, Groq) we can add later
        return f"[Simulated {provider}] Response to: {message}"