from datetime import datetime

class DetectionEngine:
    def __init__(self):
        # "Memory" to count failed logins
        # Structure: { "192.168.1.104": count }
        self.failed_login_tracker = {}
        self.THRESHOLD = 3  # Alert if failures >= 3

    def detect(self, normalized_event):
        """
        Checks the event against security rules.
        Returns an Alert Object if a rule is broken, otherwise None.
        """
        alerts = []
        event_type = normalized_event.get("event_type")
        src_ip = normalized_event.get("source_ip")
        user = normalized_event.get("user")

        # --- RULE 1: SUDO USAGE (Monitoring) ---
        # In a real SOC, we might only alert if a non-admin uses sudo.
        # For this lab, we alert on ANY sudo usage to prove it works.
        if event_type == "SUDO_COMMAND":
            alert = {
                "rule": "Suspicious Privilege Escalation",
                "severity": "MEDIUM",
                "description": f"User '{user}' executed a sudo command.",
                "evidence": normalized_event["command"]
            }
            alerts.append(alert)

        # --- RULE 2: SSH BRUTE FORCE (Counting) ---
        if event_type == "SSH_FAILED_LOGIN":
            # Increment count for this IP
            if src_ip in self.failed_login_tracker:
                self.failed_login_tracker[src_ip] += 1
            else:
                self.failed_login_tracker[src_ip] = 1

            # Check Threshold
            current_count = self.failed_login_tracker[src_ip]
            
            if current_count >= self.THRESHOLD:
                alert = {
                    "rule": "SSH Brute Force Detected",
                    "severity": "HIGH",
                    "description": f"IP {src_ip} failed to login {current_count} times.",
                    "evidence": f"User attempted: {user}"
                }
                alerts.append(alert)

        # --- RULE 3: SSH SUCCESSFUL LOGIN (Info) ---
        # Good to know, usually LOW severity
        if event_type == "SSH_SUCCESS_LOGIN":
            alert = {
                "rule": "SSH Successful Login",
                "severity": "LOW",
                "description": f"User '{user}' logged in successfully from {src_ip}.",
                "evidence": "Access granted"
            }
            alerts.append(alert)

        return alerts

# --- TEST BLOCK ---
if __name__ == "__main__":
    engine = DetectionEngine()
    
    # Simulate a Brute Force Attack (3 failures from same IP)
    test_event = {
        "event_type": "SSH_FAILED_LOGIN", 
        "source_ip": "1.2.3.4", 
        "user": "root"
    }

    print("--- TESTING DETECTION ENGINE ---")
    print(f"Attempt 1: {engine.detect(test_event)}")
    print(f"Attempt 2: {engine.detect(test_event)}")
    print(f"Attempt 3: {engine.detect(test_event)}") # Should trigger HIGH alert here
