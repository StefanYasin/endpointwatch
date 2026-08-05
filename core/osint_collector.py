import feedparser, datetime

class OSINTCollector:
    def __init__(self, db_conn):
        self.db = db_conn
        self.feeds = [
            "https://feeds.feedburner.com/TheHackersNews",
            "https://www.us-cert.gov/ncas/alerts.xml"
        ]

    def fetch_feeds(self):
        cursor = self.db.cursor()
        for url in self.feeds:
            feed = feedparser.parse(url)
            for entry in feed.entries[:3]:
                cursor.execute("INSERT INTO intel (timestamp, source, title, link) VALUES (?, ?, ?, ?)",
                               (datetime.datetime.now().isoformat(), url, entry.title, entry.link))
        self.db.commit()