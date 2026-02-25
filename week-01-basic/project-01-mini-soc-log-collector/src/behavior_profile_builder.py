import json
import math
import os
from collections import defaultdict
from datetime import datetime

class BehaviorProfileBuilder:
    def __init__(self, history_file="data/historical_events.json", output_file="baselines/baseline_model.json"):
        self.history_file = history_file
        self.output_file = output_file

    def build_profiles(self):
        print("--- STARTING BEHAVIORAL PROFILING (UEBA) ---")
        
        # This will hold the raw counts before we do the math
        users_data = defaultdict(lambda: {
            "login_hours": [],
            "failed_count": 0,
            "sudo_count": 0,
            "source_ips": defaultdict(int),
            "unique_days": set()
        })

        # 1. Read historical data
        try:
            with open(self.history_file, "r") as f:
                for line in f:
                    if not line.strip(): continue
                    event = json.loads(line)
                    user = event.get("user")
                    if not user: continue
                    
                    # Parse the time
                    dt = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                    day_str = dt.strftime("%Y-%m-%d")
                    
                    # Store the raw data
                    udata = users_data[user]
                    udata["unique_days"].add(day_str)
                    udata["source_ips"][event["source_ip"]] += 1
                    
                    if event["event_type"] == "SSH_SUCCESS_LOGIN":
                        udata["login_hours"].append(dt.hour)
                    elif event["event_type"] == "SSH_FAILED_LOGIN":
                        udata["failed_count"] += 1
                    elif event["event_type"] == "SUDO_COMMAND":
                        udata["sudo_count"] += 1
        except FileNotFoundError:
            print(f"[!] Error: {self.history_file} not found.")
            return

        # 2. Compute baselines (The Math)
        baselines = {}
        for user, data in users_data.items():
            days = len(data["unique_days"]) or 1 # Avoid dividing by zero
            
            # Hour stats (Mean and Standard Deviation)
            hours = data["login_hours"]
            if hours:
                avg_hour = sum(hours) / len(hours)
                # Standard Deviation: How much does the time normally bounce around?
                variance = sum((h - avg_hour) ** 2 for h in hours) / len(hours)
                std_dev = math.sqrt(variance)
            else:
                avg_hour, std_dev = 0, 0

            # 3. Create the final Baseline Profile
            baselines[user] = {
                "avg_login_hour": round(avg_hour, 2),
                "std_dev_hour": round(std_dev, 2),
                "avg_failed_attempts_per_day": round(data["failed_count"] / days, 2),
                "avg_sudo_per_day": round(data["sudo_count"] / days, 2),
                # If an IP was used, we consider it "known" or "common"
                "common_source_ips": [ip for ip in data["source_ips"].keys()] 
            }
            
            print(f"[*] Profile built for user: '{user}'")
            print(f"    -> Avg Login Time: {round(avg_hour, 2)}:00 (±{round(std_dev, 2)} hours)")
            print(f"    -> Avg Fails/Day:  {round(data['failed_count'] / days, 2)}")
            print(f"    -> Known IPs:      {baselines[user]['common_source_ips']}")

        # 4. Save the Model
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
        with open(self.output_file, "w") as f:
            json.dump(baselines, f, indent=4)
            
        print(f"\n[+] Baseline model saved to {self.output_file}")

if __name__ == "__main__":
    builder = BehaviorProfileBuilder()
    builder.build_profiles()
