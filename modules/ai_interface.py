# modules/ai_interface.py
import os, json

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


class AIInterface:
    def __init__(self, keys_path="config/api_keys.json"):
        self.keys_path = keys_path
        self.keys = self.load_keys()

    def load_keys(self):
        """Load API keys from config file"""
        if os.path.exists(self.keys_path):
            try:
                with open(self.keys_path) as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def available_providers(self):
        """Return a list of enabled AI providers"""
        return list(self.keys.keys())

    # ---------------- CHAT ----------------
    def chat(self, provider, prompt):
        if provider == "openai" and OpenAI and "openai" in self.keys:
            try:
                client = OpenAI(api_key=self.keys["openai"])
                resp = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "You are a helpful cybersecurity assistant."},
                        {"role": "user", "content": prompt}
                    ]
                )
                return resp.choices[0].message.content.strip()
            except Exception as e:
                return f"[OpenAI error: {e}]"
        return f"[No provider available for {provider}]"

    # ---------------- SUMMARIZE THREATS ----------------
    def summarize_threats(self, provider):
        """Ask AI to summarize recent threats (simplified demo)."""
        if provider == "openai" and OpenAI and "openai" in self.keys:
            try:
                client = OpenAI(api_key=self.keys["openai"])
                prompt = "Summarize the last 5 security threats in one short paragraph for a non-technical user."
                resp = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": prompt}]
                )
                return resp.choices[0].message.content.strip()
            except Exception as e:
                return f"[OpenAI error: {e}]"
        return "[Threat summary unavailable]"# modules/ai_interface.py
import os, json

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


class AIInterface:
    def __init__(self, keys_path="config/api_keys.json"):
        self.keys_path = keys_path
        self.keys = self.load_keys()

    def load_keys(self):
        """Load API keys from config file"""
        if os.path.exists(self.keys_path):
            try:
                with open(self.keys_path) as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def available_providers(self):
        """Return a list of enabled AI providers"""
        return list(self.keys.keys())

    # ---------------- CHAT ----------------
    def chat(self, provider, prompt):
        if provider == "openai" and OpenAI and "openai" in self.keys:
            try:
                client = OpenAI(api_key=self.keys["openai"])
                resp = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "You are a helpful cybersecurity assistant."},
                        {"role": "user", "content": prompt}
                    ]
                )
                return resp.choices[0].message.content.strip()
            except Exception as e:
                return f"[OpenAI error: {e}]"
        return f"[No provider available for {provider}]"

    # ---------------- SUMMARIZE THREATS ----------------
    def summarize_threats(self, provider):
        """Ask AI to summarize recent threats (simplified demo)."""
        if provider == "openai" and OpenAI and "openai" in self.keys:
            try:
                client = OpenAI(api_key=self.keys["openai"])
                prompt = "Summarize the last 5 security threats in one short paragraph for a non-technical user."
                resp = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": prompt}]
                )
                return resp.choices[0].message.content.strip()
            except Exception as e:
                return f"[OpenAI error: {e}]"
        return "[Threat summary unavailable]"