import json
import os
from attack_chain_builder import AttackChainBuilder

class CorrelationEngine:
    def __init__(self, events_file="data/normalized_events.json"):
        self.events_file = events_file
        self.builder = AttackChainBuilder()
        self.output_dir = "investigations"
        os.makedirs(self.output_dir, exist_ok=True)

    def load_events(self):
        events = []
        try:
            with open(self.events_file, "r") as f:
                for line in f:
                    if line.strip():
                        events.append(json.loads(line))
        except FileNotFoundError:
            print(f"[!] File {self.events_file} not found.")
        return events

    def run_correlation(self):
        print("--- STARTING AXIORA CORRELATION ENGINE ---")
        events = self.load_events()
        
        if not events:
            return

        # 1. Group by Entity (Source IP)
        ip_groups = {}
        for event in events:
            ip = event.get("source_ip")
            if ip not in ip_groups:
                ip_groups[ip] = []
            ip_groups[ip].append(event)

        # 2. Analyze each IP's timeline for Attack Chains
        for ip, group in ip_groups.items():
            # Ensure events are sorted chronologically
            group.sort(key=lambda x: x["timestamp"])
            
            # State trackers for the sequence
            failed_logins = []
            successful_login = None
            privilege_escalation = None
            
            for event in group:
                etype = event["event_type"]
                
                if etype == "SSH_FAILED_LOGIN":
                    failed_logins.append(event)
                elif etype == "SSH_SUCCESS_LOGIN" and len(failed_logins) > 0:
                    successful_login = event
                elif etype == "SUDO_COMMAND" and successful_login:
                    # We only care about sudo IF they successfully logged in first
                    privilege_escalation = event

            # 3. Chain Detection Logic
            # Did they hit all 3 stages? (Credential Compromise -> Persistence/Escalation)
            if failed_logins and successful_login and privilege_escalation:
                # Build the chain using the first fail, the success, and the sudo
                chain_events = [failed_logins[0], successful_login, privilege_escalation]
                target_user = successful_login["user"]
                
                print(f"[*] ATTACK CHAIN DETECTED from {ip} targeting '{target_user}'!")
                
                incident = self.builder.build_incident(
                    source_ip=ip,
                    target_user=target_user,
                    chain_events=chain_events,
                    chain_name="Credential Compromise & Privilege Escalation"
                )
                
                # Save the correlated incident
                filepath = f"{self.output_dir}/correlated_incident_{incident['incident_id']}.json"
                with open(filepath, "w") as f:
                    json.dump(incident, f, indent=4)
                    
                print(f"[+] Correlated Incident Generated: {filepath}")
                print(f"    -> Severity: {incident['severity']} | Stages: {len(chain_events)}\n")

if __name__ == "__main__":
    engine = CorrelationEngine()
    engine.run_correlation()
