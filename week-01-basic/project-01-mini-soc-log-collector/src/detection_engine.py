from datetime import datetime

class DetectionEngine:
    def __init__(self):
        # "Memory" to count failed logins
        self.failed_login_tracker = {}
        self.THRESHOLD = 3  # Alert if failures >= 3

    def detect(self, normalized_event):
        alerts = []
        event_type = normalized_event.get("event_type")
        src_ip = normalized_event.get("source_ip")
        user = normalized_event.get("user")

        # --- RULE 1: SUDO USAGE ---
        if event_type == "SUDO_COMMAND":
            alert = {
                "rule": "Suspicious Privilege Escalation",
                "severity": "MEDIUM",
                "source_ip": src_ip,  # <--- CRITICAL FIX
                "user": user,
                "description": f"User '{user}' executed a sudo command.",
                "evidence": normalized_event.get("command", "N/A")
            }
            alerts.append(alert)

        # --- RULE 2: SSH BRUTE FORCE ---
        if event_type == "SSH_FAILED_LOGIN":
            # Increment count
            if src_ip in self.failed_login_tracker:
                self.failed_login_tracker[src_ip] += 1
            else:
                self.failed_login_tracker[src_ip] = 1

            current_count = self.failed_login_tracker[src_ip]
            
            # TRIGGER ALERT if threshold is met
            if current_count >= self.THRESHOLD:
                alert = {
                    "rule": "SSH Brute Force Detected",
                    "severity": "HIGH",
                    "source_ip": src_ip,  # <--- CRITICAL FIX
                    "user": user,
                    "count": current_count,
                    "description": f"IP {src_ip} failed to login {current_count} times.",
                    "evidence": f"User attempted: {user}"
                }
                alerts.append(alert)

        # --- RULE 3: SSH SUCCESSFUL LOGIN ---
        if event_type == "SSH_SUCCESS_LOGIN":
            alert = {
                "rule": "SSH Successful Login",
                "severity": "LOW",
                "source_ip": src_ip,  # <--- CRITICAL FIX
                "user": user,
                "description": f"User '{user}' logged in successfully from {src_ip}.",
                "evidence": "Access granted"
            }
            alerts.append(alert)

        return alerts