import tkinter as tk
import sqlite3, os
from gui.matrix_ui import MatrixUI
from notifications.audio_alerts import AudioAlerts
from modules.ai_interface import AIInterface

def main():
    # Ensure database folder
    os.makedirs("database", exist_ok=True)

    # Thread-safe connection
    db = sqlite3.connect("database/security.db", check_same_thread=False)
    cur = db.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        type TEXT,
        name TEXT
    )""")
    db.commit()

    # Audio + AI
    audio = AudioAlerts()
    ai = AIInterface()

    # Tk root
    root = tk.Tk()
    root.geometry("1400x850")
    root.configure(bg="black")

    # Launch GUI
    gui = MatrixUI(root, audio=audio, ai=ai, db=db)
    gui.log("Dashboard", "🚀 Quantum Security Monitor started")

    root.mainloop()

if __name__ == "__main__":
    main()