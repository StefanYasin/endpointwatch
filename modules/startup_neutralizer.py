import subprocess

class StartupNeutralizer:
    def remove_registry_run(self, name):
        try:
            cmd = f'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "{name}" /f'
            subprocess.run(["powershell", "-Command", cmd], capture_output=True)
            return f"Registry Run entry '{name}' removed."
        except Exception as e:
            return f"Error removing registry entry: {e}"

    def remove_startup_file(self, path):
        try:
            cmd = f'Remove-Item -Path "{path}" -Force'
            subprocess.run(["powershell", "-Command", cmd], capture_output=True)
            return f"Startup file '{path}' removed."
        except Exception as e:
            return f"Error removing startup file: {e}"

    def remove_scheduled_task(self, task_name):
        try:
            cmd = f'Schtasks /Delete /TN "{task_name}" /F'
            subprocess.run(cmd, shell=True, capture_output=True)
            return f"Scheduled task '{task_name}' removed."
        except Exception as e:
            return f"Error removing scheduled task: {e}"

    def run_winutil_cleanup(self):
        try:
            cmd = 'irm "https://christitus.com/win" | iex'
            subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
            return "Winutil cleanup executed."
        except Exception as e:
            return f"Error running Winutil: {e}"