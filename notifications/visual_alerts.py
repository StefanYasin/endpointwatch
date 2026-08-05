from plyer import notification

class VisualAlerts:
    def notify(self, title, message):
        notification.notify(title=title, message=message, timeout=5)