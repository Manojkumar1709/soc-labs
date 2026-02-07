import json
from datetime import datetime

class AttackAnalyzer:
    def __init__(self, alerts_file="alerts/alerts.json"):
        self.alerts_file = alerts_file

    def analyze_attacks(self):
        """
        Reads raw alerts and groups them into 'Attacks' based on Source IP.
        """
        try:
            with open(self.alerts_file, "r") as f:
                # Read line-by-line JSON
                raw_alerts = [json.loads(line) for line in f]
        except FileNotFoundError:
            print(f"[!] Error: {self.alerts_file} not found. Run Project-1 first!")
            return []

        attacks = {}

        for alert in raw_alerts:
            # We group by Source IP (The "Attacker")
            source_ip = alert.get("source_ip", "unknown")
            if source_ip == "unknown":
                continue
            
            # Use 'detection_time' because that is what AlertEngine saves
            event_time = alert.get("detection_time", datetime.now().isoformat())

            # Initialize the attack record if new
            if source_ip not in attacks:
                attacks[source_ip] = {
                    "attack_type": "SSH_BRUTE_FORCE", 
                    "source_ip": source_ip,
                    "target_users": set(),
                    "start_time": event_time,
                    "end_time": event_time,
                    "attempt_count": 0,
                    "related_alerts": []
                }

            # Update the record
            attack = attacks[source_ip]
            
            # 1. Collect Target Users
            # Evidence string usually looks like: "User attempted: root"
            evidence = alert.get("evidence", "")
            user = alert.get("user", "unknown")
            if user != "unknown":
                attack["target_users"].add(user)
            elif "User attempted: " in evidence:
                user = evidence.split(": ")[1]
                attack["target_users"].add(user)
            
            # 2. Update Time Window (Start/End)
            if event_time < attack["start_time"]:
                attack["start_time"] = event_time
            if event_time > attack["end_time"]:
                attack["end_time"] = event_time
            
            # 3. Count
            # If the alert has a count (e.g. "failed 3 times"), use it. Otherwise count as 1.
            count = alert.get("count", 1) 
            attack["attempt_count"] += count
            
            # 4. Link the Alert ID
            attack["related_alerts"].append(alert)

        # Convert sets to lists for JSON compatibility
        results = []
        for ip, data in attacks.items():
            data["target_users"] = list(data["target_users"])
            results.append(data)
            
        return results

# --- TEST BLOCK ---
if __name__ == "__main__":
    analyzer = AttackAnalyzer()
    attacks = analyzer.analyze_attacks()
    
    print(f"--- ATTACK ANALYSIS REPORT ---")
    print(json.dumps(attacks, indent=4))