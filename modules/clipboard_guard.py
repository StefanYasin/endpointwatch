# modules/clipboard_guard.py
import tkinter as tk, re, datetime

class ClipboardGuard:
    def __init__(self, db_conn):
        self.db = db_conn
        self.last_clip = None

    def classify(self, text):
        # Regex for Bitcoin (basic), Ethereum, email, credit card
        if re.match(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$", text):
            return "Bitcoin address"
        if re.match(r"^0x[a-fA-F0-9]{40}$", text):
            return "Ethereum address"
        if re.match(r"[^@]+@[^@]+\.[^@]+", text):
            return "Email"
        if re.match(r"^\d{13,19}$", text) and self.luhn_check(text):
            return "Credit card number"
        return "text"

    def luhn_check(self, num):
        digits = [int(x) for x in num]
        checksum = 0
        odd = True
        for d in reversed(digits):
            if odd:
                checksum += d
            else:
                checksum += sum(divmod(2 * d, 10))
            odd = not odd
        return checksum % 10 == 0

    def check_clipboard(self):
        threats = []
        root = tk.Tk()
        root.withdraw()
        try:
            data = root.clipboard_get()
        except Exception:
            data = None
        root.destroy()

        if data and self.last_clip and data != self.last_clip:
            ctype = self.classify(data.strip())
            msg = f"Clipboard changed: {ctype}"
            cursor = self.db.cursor()
            cursor.execute(
                "INSERT INTO threats (timestamp, type, name, pid) VALUES (?, ?, ?, ?)",
                (datetime.datetime.now().isoformat(), "clipboard", msg, -1)
            )
            self.db.commit()
            threats.append(msg)

        if data:
            self.last_clip = data
        return threats