import json
import os
from datetime import datetime
from attack_analyzer import AttackAnalyzer
from timeline_builder import TimelineBuilder
from risk_scoring import RiskScorer

class InvestigationReporter:
    def __init__(self):
        self.analyzer = AttackAnalyzer()
        self.timeline_builder = TimelineBuilder()
        self.risk_scorer = RiskScorer()
        self.output_dir = "investigations"
        
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_reports(self):
        print("--- STARTING AUTOMATED INVESTIGATION ---")
        
        # 1. Analyze Attacks
        attacks = self.analyzer.analyze_attacks()
        print(f"[*] Detected {len(attacks)} potential attack chains.")
        
        for attack in attacks:
            source_ip = attack["source_ip"]
            print(f"\n[*] Investigating IP: {source_ip}...")
            
            # 2. Build Timeline
            timeline = self.timeline_builder.build_timeline(attack)
            
            # 3. Calculate Risk
            risk_assessment = self.risk_scorer.calculate_risk(attack)
            
            # 4. Generate Attacker Profile (Static Logic for now)
            attacker_profile = {
                "ip": source_ip,
                "pattern": "Brute Force -> Successful Login",
                "tools_suspected": "Hydra / Medusa / Custom Script",
                "intent": "Credential Theft & Persistence"
            }
            
            # 5. Construct Full Incident Report
            incident_report = {
                "incident_id": f"INC-{source_ip.replace('.', '-')}-{int(datetime.now().timestamp())}",
                "generated_at": datetime.now().isoformat(),
                "status": "OPEN",
                "summary": f"CRITICAL Brute Force attack detected from {source_ip} targeting {len(attack['target_users'])} users.",
                "attacker": attacker_profile,
                "risk_assessment": risk_assessment,
                "timeline": timeline,
                "recommended_actions": [
                    f"Block IP {source_ip} on Firewall immediately.",
                    "Reset passwords for affected users: " + ", ".join(attack['target_users']),
                    "Check /var/log/auth.log for lateral movement."
                ]
            }
            
            # 6. Save Report
            filename = f"{self.output_dir}/investigation_{source_ip}.json"
            with open(filename, "w") as f:
                json.dump(incident_report, f, indent=4)
                
            print(f"[+] Report generated: {filename}")
            print(f"[!] SEVERITY: {risk_assessment['severity_label']} (Score: {risk_assessment['risk_score']})")

if __name__ == "__main__":
    reporter = InvestigationReporter()
    reporter.generate_reports()