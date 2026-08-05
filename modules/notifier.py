# modules/notifier.py
import json, requests, smtplib
from email.mime.text import MIMEText

class Notifier:
    def __init__(self, config="config/notifications.json"):
        self.conf = {}
        try:
            with open(config) as f:
                self.conf = json.load(f)
        except Exception:
            pass

    def send_discord(self, msg):
        url = self.conf.get("discord_webhook")
        if not url:
            return
        try:
            requests.post(url, json={"content": msg}, timeout=5)
        except Exception:
            pass

    def send_email(self, msg):
        cfg = self.conf.get("email")
        if not cfg:
            return
        try:
            smtp = smtplib.SMTP(cfg["server"], cfg.get("port", 587))
            smtp.starttls()
            smtp.login(cfg["user"], cfg["password"])
            smtp.sendmail(cfg["from"], cfg["to"], MIMEText(msg).as_string())
            smtp.quit()
        except Exception:
            pass

    def notify(self, msg):
        self.send_discord(msg)
        self.send_email(msg)