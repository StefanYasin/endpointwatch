# modules/report_generator.py
import datetime

class ReportGenerator:
    def __init__(self, db_conn, ai=None):
        self.db = db_conn
        self.ai = ai

    def generate_report(self, path="reports/security_report.md"):
        cursor = self.db.cursor()
        cursor.execute("SELECT timestamp, type, name FROM threats ORDER BY id DESC LIMIT 100")
        rows = cursor.fetchall()

        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# Security Report ({datetime.date.today()})\n\n")
            f.write("## Recent Threats\n\n")
            for r in rows:
                f.write(f"- {r[0]} [{r[1]}] {r[2]}\n")

            if self.ai:
                summary = self.ai.summarize_threats("openai")
                f.write("\n## AI Summary\n\n")
                f.write(summary)

        return path