import json
import os
from datetime import datetime

class AlertEngine:
    def __init__(self, output_file="alerts/alerts.json"):
        self.output_file = output_file
        # Ensure the directory exists
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)

    def process_alerts(self, alerts):
        """
        Takes a list of alerts, saves them to a file, and prints them.
        """
        if not alerts:
            return

        for alert in alerts:
            # 1. Add a timestamp to the alert itself (Detection Time)
            alert["detection_time"] = datetime.now().isoformat()
            
            # 2. Save to JSON file (Append mode)
            self._save_to_file(alert)

            # 3. Print to Console (The "Dashboard" view)
            self._print_alert(alert)

    def _save_to_file(self, alert):
        """
        Appends the alert as a JSON line to the output file.
        """
        with open(self.output_file, "a") as f:
            f.write(json.dumps(alert) + "\n")

    def _print_alert(self, alert):
        """
        Pretty prints the alert to the terminal with colors (if supported).
        """
        severity = alert["severity"]
        color = "\033[0m" # Reset
        if severity == "HIGH":
            color = "\033[91m" # Red
        elif severity == "MEDIUM":
            color = "\033[93m" # Yellow
        elif severity == "LOW":
            color = "\033[92m" # Green

        print(f"{color}[!] ALERT GENERATED: {alert['rule']} ({severity}){'\033[0m'}")
        print(f"    Time: {alert['detection_time']}")
        print(f"    Desc: {alert['description']}")
        print(f"    Evidence: {alert['evidence']}")
        print("-" * 50)
