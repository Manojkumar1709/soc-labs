import json
import glob
from ip_reputation_lookup import IPReputationLookup
from risk_adjustment import RiskAdjuster

class ThreatIntelEngine:
    def __init__(self, investigations_dir="investigations"):
        self.investigations_dir = investigations_dir
        # Bring in our two new tools
        self.ti_lookup = IPReputationLookup()
        self.adjuster = RiskAdjuster()

    def enrich_incidents(self):
        print("--- STARTING THREAT INTELLIGENCE ENRICHMENT ---")
        
        # Find all MITRE reports that haven't been TI-enriched yet
        files = glob.glob(f"{self.investigations_dir}/*_mitre.json")
        
        if not files:
            print("[-] No MITRE reports found. Run Week 2 Project 1 first.")
            return

        for filepath in files:
            print(f"\n[*] Processing Incident: {filepath}")
            
            with open(filepath, 'r') as f:
                report = json.load(f)

            # Extract IP and Base Risk from the report
            attacker_ip = report.get("attacker", {}).get("ip")
            if not attacker_ip:
                print("[-] No attacker IP found in report. Skipping.")
                continue
                
            base_score = report.get("risk_assessment", {}).get("risk_score", 0)

            # 1. Query Threat Intel
            ti_data = self.ti_lookup.lookup(attacker_ip)

            # 2. Adjust Risk
            risk_result = self.adjuster.adjust_risk(base_score, ti_data)

            # 3. Add the Threat Intel section to the report
            report["threat_intelligence"] = {
                "ip_reputation": ti_data,
                "risk_modifier": f"+{risk_result['ti_modifier']}" if risk_result['ti_modifier'] > 0 else str(risk_result['ti_modifier'])
            }
            
            # 4. Update the risk assessment block
            report["risk_assessment"]["base_score"] = base_score
            report["risk_assessment"]["final_risk_score"] = risk_result["final_score"]
            report["risk_assessment"]["severity_label"] = risk_result["final_severity"]
            
            # 5. Add an urgent action if it's a known bad IP
            if risk_result["final_score"] >= 90:
                urgent_msg = f"[TI MATCH] URGENT: Block known malicious IP {attacker_ip} at edge firewall."
                if urgent_msg not in report.get("recommended_actions", []):
                    # Insert at the very top of the list
                    report["recommended_actions"].insert(0, urgent_msg)

            # 6. Save Final Report
            new_filepath = filepath.replace("_mitre.json", "_final_enriched.json")
            with open(new_filepath, 'w') as f:
                json.dump(report, f, indent=4)
            
            print(f"[+] Enrichment Complete!")
            print(f"    -> TI Abuse Score: {ti_data['abuse_confidence_score']} | Country: {ti_data['country_code']}")
            print(f"    -> Risk Adjusted: {base_score} -> {risk_result['final_score']} ({risk_result['final_severity']})")
            print(f"[+] Saved to: {new_filepath}")

# --- EXECUTION BLOCK ---
if __name__ == "__main__":
    engine = ThreatIntelEngine()
    engine.enrich_incidents()
