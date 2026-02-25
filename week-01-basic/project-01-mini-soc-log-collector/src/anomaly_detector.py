import json
import os

class AnomalyDetector:
    def __init__(self, baseline_file="baselines/baseline_model.json"):
        self.baseline_file = baseline_file
        self.baselines = self._load_baselines()

    def _load_baselines(self):
        try:
            with open(self.baseline_file, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Could not load baseline model: {e}")
            return {}

    def detect(self, session_activity):
        """
        Evaluates a current session dictionary against the user's baseline.
        """
        user = session_activity.get("user")
        if not user or user not in self.baselines:
            print(f"[-] No baseline exists for user '{user}'. Skipping UEBA.")
            return None

        baseline = self.baselines[user]
        anomalies = []
        risk_score = 0

        # --- ANOMALY 1: Abnormal Login Time ---
        login_hour = session_activity.get("login_hour")
        if login_hour is not None:
            avg_hour = baseline["avg_login_hour"]
            # We enforce a minimum std_dev of 1 to prevent the system from being overly sensitive
            std_dev = max(baseline["std_dev_hour"], 1.0) 
            
            # Is the login outside the 95% confidence interval? (2 standard deviations)
            if abs(login_hour - avg_hour) > (2 * std_dev):
                anomalies.append(f"Login at abnormal hour ({login_hour}:00 vs avg {avg_hour})")
                risk_score += 25

        # --- ANOMALY 2: New Source IP ---
        source_ip = session_activity.get("source_ip")
        if source_ip and source_ip not in baseline["common_source_ips"]:
            anomalies.append(f"New, unknown source IP detected ({source_ip})")
            risk_score += 30

        # --- ANOMALY 3: Failed Attempt Spike ---
        # We ensure avg_fails is at least 0.5 to prevent dividing by zero errors
        failed_attempts = session_activity.get("failed_attempts", 0)
        avg_fails = max(baseline["avg_failed_attempts_per_day"], 0.5)
        
        if failed_attempts > (5 * avg_fails):
            anomalies.append(f"Spike in failed logins ({failed_attempts} vs daily avg {avg_fails})")
            risk_score += 30

        # --- ANOMALY 4: Sudo Spike ---
        sudo_count = session_activity.get("sudo_count", 0)
        avg_sudo = max(baseline["avg_sudo_per_day"], 0.5)
        
        if sudo_count > (3 * avg_sudo):
            anomalies.append(f"Spike in sudo usage ({sudo_count} vs daily avg {avg_sudo})")
            risk_score += 20

        # Cap the risk score at 100
        risk_score = min(risk_score, 100)

        # Severity mapping based on the behavior risk score
        severity = "LOW"
        if risk_score >= 70:
            severity = "HIGH"
        elif risk_score >= 40:
            severity = "MEDIUM"

        # If any anomalies were found, generate the UEBA incident
        if anomalies:
            return {
                "incident_id": "INC-UEBA-001",
                "user": user,
                "anomalies": anomalies,
                "risk_score": risk_score,
                "severity": severity,
                "confidence": "MEDIUM",  # UEBA is usually medium confidence until verified
                "reason": "Behavior deviates significantly from baseline model."
            }
            
        return None

# --- TEST BLOCK ---
if __name__ == "__main__":
    detector = AnomalyDetector()
    
    # We simulate a hacker (or malware) compromising Manoj's account at 3:00 AM
    # from an external IP, failing a few times, and immediately trying sudo.
    malicious_session = {
        "user": "manoj",
        "login_hour": 3,
        "source_ip": "82.146.45.10", # Completely unknown IP
        "failed_attempts": 3,
        "sudo_count": 2
    }
    
    print("--- STARTING BEHAVIORAL ANOMALY DETECTION ---")
    print(f"[*] Analyzing new session for user '{malicious_session['user']}'...")
    
    alert = detector.detect(malicious_session)
    
    if alert:
        print("\n[!] ANOMALY DETECTED!")
        print(json.dumps(alert, indent=4))
        
        # Save the UEBA Alert to the investigations folder
        os.makedirs("investigations", exist_ok=True)
        filepath = "investigations/behavior_alert.json"
        with open(filepath, "w") as f:
            json.dump(alert, f, indent=4)
        print(f"\n[+] Saved UEBA incident report to {filepath}")
    else:
        print("\n[+] Session appears normal. No anomalies detected.")
